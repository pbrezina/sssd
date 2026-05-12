/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2026 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <string.h>

#include "util/util.h"
#include "sss_iface/sss_iface_async.h"
#include "responder/pam/pamsrv.h"
#include "responder/pam/pamsrv_bot_iface.h"

#define PAM_BOT_INDICATOR_TIMEOUT 300 /* 5 minutes */

#define MCP_BOT_AGENT      "mcp-bot-agent:"
#define MCP_BOT_MODEL      "mcp-bot-model:"
#define MCP_BOT_TOOL        "mcp-bot-tool:"
#define MCP_BOT_REQUEST_ID  "mcp-bot-request-id:"

struct pam_bot_table_ctx {
    hash_table_t *table;
    char *bot_name;
};

static void pam_bot_cache_remove(struct tevent_context *ev,
                                 struct tevent_timer *te,
                                 struct timeval tv,
                                 void *pvt)
{
    hash_key_t key;
    int hret;
    struct pam_bot_table_ctx *table_ctx;

    table_ctx = talloc_get_type(pvt, struct pam_bot_table_ctx);

    key.type = HASH_KEY_STRING;
    key.str = table_ctx->bot_name;

    hret = hash_delete(table_ctx->table, &key);
    if (hret != HASH_SUCCESS && hret != HASH_ERROR_KEY_NOT_FOUND) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Could not remove [%s] from BOT indicators cache: [%s]\n",
              table_ctx->bot_name, hash_error_string(hret));
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "[%s] removed from BOT indicators cache\n",
              table_ctx->bot_name);
    }

    talloc_free(table_ctx);
}

static errno_t
pam_bot_register(TALLOC_CTX *mem_ctx,
                 struct sbus_request *sbus_req,
                 struct pam_ctx *pctx,
                 const char *bot_name,
                 const char **indicators)
{
    struct pam_bot_indicators *ind;
    struct pam_bot_table_ctx *table_ctx;
    struct tevent_timer *te;
    struct timeval tv;
    hash_key_t key;
    hash_value_t val;
    int hret;

    if (bot_name == NULL || bot_name[0] == '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "BOT register: empty bot_name\n");
        return EINVAL;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "BOT register: [%s] with indicators\n", bot_name);

    table_ctx = talloc_zero(pctx->bot_indicators_table,
                            struct pam_bot_table_ctx);
    if (table_ctx == NULL) {
        return ENOMEM;
    }

    table_ctx->table = pctx->bot_indicators_table;
    table_ctx->bot_name = talloc_strdup(table_ctx, bot_name);
    if (table_ctx->bot_name == NULL) {
        talloc_free(table_ctx);
        return ENOMEM;
    }

    ind = talloc_zero(table_ctx, struct pam_bot_indicators);
    if (ind == NULL) {
        talloc_free(table_ctx);
        return ENOMEM;
    }

    /* Parse indicators into fields. */
    if (indicators != NULL) {
        for (int i = 0; indicators[i] != NULL; i++) {
            DEBUG(SSSDBG_TRACE_ALL,
                  "BOT register: indicator [%s]\n", indicators[i]);

            if (strncmp(indicators[i], MCP_BOT_AGENT,
                        strlen(MCP_BOT_AGENT)) == 0) {
                ind->agent = talloc_strdup(ind,
                    indicators[i] + strlen(MCP_BOT_AGENT));
            } else if (strncmp(indicators[i], MCP_BOT_MODEL,
                               strlen(MCP_BOT_MODEL)) == 0) {
                ind->model = talloc_strdup(ind,
                    indicators[i] + strlen(MCP_BOT_MODEL));
            } else if (strncmp(indicators[i], MCP_BOT_TOOL,
                               strlen(MCP_BOT_TOOL)) == 0) {
                ind->tool = talloc_strdup(ind,
                    indicators[i] + strlen(MCP_BOT_TOOL));
            } else if (strncmp(indicators[i], MCP_BOT_REQUEST_ID,
                               strlen(MCP_BOT_REQUEST_ID)) == 0) {
                ind->request_id = talloc_strdup(ind,
                    indicators[i] + strlen(MCP_BOT_REQUEST_ID));
            }
        }
    }

    key.type = HASH_KEY_STRING;
    key.str = table_ctx->bot_name;

    /* If an entry already exists (e.g. re-authentication), delete it
     * and free the old table_ctx (which cancels the old timer via talloc
     * destructor) to prevent it from deleting the new entry. */
    hret = hash_lookup(pctx->bot_indicators_table, &key, &val);
    if (hret == HASH_SUCCESS) {
        struct pam_bot_indicators *old_ind;
        old_ind = (struct pam_bot_indicators *)val.ptr;
        /* table_ctx is the talloc parent of ind */
        talloc_free(talloc_parent(old_ind));
        hash_delete(pctx->bot_indicators_table, &key);
    }

    val.type = HASH_VALUE_PTR;
    val.ptr = ind;

    hret = hash_enter(pctx->bot_indicators_table, &key, &val);
    if (hret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not store BOT indicators for [%s]: [%s]\n",
              bot_name, hash_error_string(hret));
        talloc_free(table_ctx);
        return EIO;
    }

    /* Set timer to clean up the entry. */
    tv = tevent_timeval_current_ofs(PAM_BOT_INDICATOR_TIMEOUT, 0);
    te = tevent_add_timer(pctx->rctx->ev, table_ctx, tv,
                          pam_bot_cache_remove, table_ctx);
    if (te == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Could not add cleanup timer for [%s]\n", bot_name);
        talloc_free(table_ctx);
        return ENOMEM;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "BOT register: [%s] stored (agent=%s, model=%s, tool=%s, "
          "request_id=%s)\n", bot_name,
          ind->agent != NULL ? ind->agent : "<none>",
          ind->model != NULL ? ind->model : "<none>",
          ind->tool != NULL ? ind->tool : "<none>",
          ind->request_id != NULL ? ind->request_id : "<none>");

    return EOK;
}

struct pam_bot_indicators *
pam_bot_indicators_lookup(struct pam_ctx *pctx, const char *bot_name)
{
    hash_key_t key;
    hash_value_t val;
    int hret;

    key.type = HASH_KEY_STRING;
    key.str = discard_const_p(char, bot_name);

    hret = hash_lookup(pctx->bot_indicators_table, &key, &val);
    if (hret != HASH_SUCCESS) {
        return NULL;
    }

    return (struct pam_bot_indicators *)val.ptr;
}

void pam_bot_indicators_delete(struct pam_ctx *pctx, const char *bot_name)
{
    hash_key_t key;

    key.type = HASH_KEY_STRING;
    key.str = discard_const_p(char, bot_name);

    hash_delete(pctx->bot_indicators_table, &key);
}

errno_t pam_register_bot_iface(struct sbus_connection *conn,
                               struct pam_ctx *pctx)
{
    errno_t ret;

    SBUS_INTERFACE(iface_bot,
        sssd_pam_BotAccount,
        SBUS_METHODS(
            SBUS_SYNC(METHOD, sssd_pam_BotAccount, Register,
                      pam_bot_register, pctx)
        ),
        SBUS_SIGNALS(SBUS_NO_SIGNALS),
        SBUS_PROPERTIES(SBUS_NO_PROPERTIES)
    );

    ret = sbus_connection_add_path(conn, SSS_BUS_PATH, &iface_bot);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Unable to register BOT account interface [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    return ret;
}
