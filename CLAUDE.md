# SSSD - MCP BOT Ephemeral Principals (branch: s4u)

## What this branch does

This branch adds support for MCP BOT ephemeral principals in SSSD. A BOT principal (e.g. `BOT-1000-abc@REALM`) is a short-lived Kerberos principal that maps to a real local user (identified by the UID embedded in the principal name). When a BOT principal authenticates via GSSAPI (e.g. SSH), SSSD:

1. Recognizes the BOT principal pattern in `cache_req` and creates an ephemeral NSS entry mapping it to the original user (by UID)
2. Translates the BOT principal to the local username in the `localauth` krb5 plugin (`sss_an2ln`)
3. Exports environment variables in the PAM session so `sss-confined-shell` can enforce policy

## Architecture

### BOT principal format
- Pattern: `BOT-<UID>-<random>@REALM` (e.g. `BOT-1000-abc@REALM`)
- Short name (without realm): `BOT-1000-abc` - used as hash table key
- The UID identifies the original local user the BOT maps to

### MCP BOT metadata via auth indicators
MCP BOT metadata (agent, model, tool, request_id) is carried in Kerberos auth indicators (ad-type 97) rather than encoded in the principal name. Indicators use the format:
- `mcp-bot-agent:<value>`
- `mcp-bot-model:<value>`
- `mcp-bot-tool:<value>`
- `mcp-bot-request-id:<value>`

### Data flow for auth indicators
```
KDC embeds indicators in ticket
    |
    v
sshd (GSSAPI auth) loads sssd_pac_plugin.so
    |
    v
sssd_pac.c: import_authdata receives ad-type 97, stores indicators
sssd_pac.c: verify() calls sssdpac_send_indicators()
    |  (SSS_PAM_REGISTER_BOT command via sss_pam_make_request over PAM socket)
    v
PAM responder: pam_cmd_register_bot() parses body, stores in hash table
    |  (keyed by BOT short name, 5-min TTL)
    v
PAM responder: pam_reply_bot_export_env() looks up indicators during session
    |  (deletes entry after consumption)
    v
Environment variables: SSS_BOT_NAME, SSS_BOT_AGENT, SSS_BOT_MODEL,
                       SSS_BOT_TOOL, SSS_BOT_REQUEST_ID
```

## Key files

| File | Purpose |
|------|---------|
| `src/sss_client/sssd_pac.c` | Kerberos authdata plugin (loaded into sshd). Handles PAC (ad-type 128) and auth indicators (ad-type 97). Forwards indicators to PAM responder via `sss_pam_make_request(SSS_PAM_REGISTER_BOT)`. |
| `src/responder/pam/pamsrv_bot_iface.{c,h}` | `pam_cmd_register_bot()` handler for `SSS_PAM_REGISTER_BOT`. Parses `mcp-bot-*` indicators, stores in hash table with timer cleanup. |
| `src/responder/pam/pamsrv_cmd.c` | `pam_reply_bot_export_env()` - exports BOT env vars from hash table lookup. PAM command dispatch table. |
| `src/responder/pam/pamsrv.h` | `struct pam_ctx` - contains `bot_indicators_table` hash table. |
| `src/responder/pam/pamsrv.c` | PAM responder init - creates hash table. |
| `src/krb5_plugin/sssd_krb5_localauth_plugin.c` | Localauth plugin - `sss_an2ln` translates BOT principals to local usernames, `sss_bot_parse_princ()` parses BOT principal format. |
| `src/responder/common/cache_req/plugins/cache_req_user_by_name.c` | Cache request plugin - handles BOT principal lookup by UID. |

## Build notes

- **PAC plugin dependencies**: `sssd_pac_plugin.so` is dlopen'd into sshd. It uses `sss_pam_make_request()` (from `CLIENT_LIBS`) to communicate with the PAM responder. No D-Bus or SBUS dependency — only libc, krb5, and SSS client libs.
- **Test targets**: `pam_srv_tests` and `test_pamsrv_json` both compile `pamsrv_cmd.c` directly, so they also need `pamsrv_bot_iface.c` in their SOURCES.
- **`test_sssd_krb5_localauth_plugin`**: Compiles the localauth plugin source directly and needs mocks for any NSS functions used (both `_nss_sss_getpwnam_r` and `_nss_sss_getpwuid_r`).

## Development guidelines

- The PAC plugin runs inside sshd, not inside SSSD. It must not depend on SSSD-internal libraries (they fail dlopen symbol resolution). Use only standard libc, krb5, and SSS client APIs. Errors in the plugin are non-fatal - they should not prevent authentication.
- Auth indicator hash table entries have a 5-minute TTL and are deleted after consumption by `pam_reply_bot_export_env()`.
