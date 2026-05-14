/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2026 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/*
 * Kerberos authdata plugin for forwarding MCP BOT auth indicators
 * from the ticket to the SSSD PAM responder.
 *
 * Auth indicators are embedded in AD-CAMMAC (ad-type 96) by the KDC.
 * This plugin registers for KRB5_AUTHDATA_AUTH_INDICATOR with the
 * AD_CAMMAC_PROTECTED flag so the krb5 framework extracts and verifies
 * the CAMMAC before passing indicators to import_authdata.
 *
 * This is a separate plugin from sssd_pac_plugin.so because the krb5
 * authdata framework creates a separate module instance for each ad-type
 * a plugin registers for. When a plugin registers for multiple ad-types
 * (e.g. both PAC and AUTH_INDICATOR), the copy path in
 * k5_copy_ad_module_data passes NULL request_context to size() but the
 * valid shared context to externalize(), causing a size mismatch and
 * ENOMEM failure during GSSAPI security context establishment.
 */

#include "config.h"

#include <krb5/krb5.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include "krb5_authdata_int.h"
#include "sss_cli.h"

/*
 * k5_authind_decode is exported from libkrb5 but declared in the
 * internal header k5-int.h which we cannot include. Declare it here.
 *
 * It decodes a single KRB5_AUTHDATA_AUTH_INDICATOR element (which
 * contains a DER-encoded SEQUENCE OF UTF8String) and appends the
 * decoded strings to the *indicators array, reallocating as needed.
 */
extern krb5_error_code
k5_authind_decode(const krb5_authdata *ad, krb5_data ***indicators);

#define BOT_PREFIX "BOT-"
#define BOT_PREFIX_LEN (sizeof(BOT_PREFIX) - 1)

struct bot_context {
    krb5_data **indicators;
};

static krb5_error_code
bot_init(krb5_context kcontext, void **plugin_context)
{
    *plugin_context = NULL;
    return 0;
}

static void
bot_flags(krb5_context kcontext,
          void *plugin_context,
          krb5_authdatatype ad_type,
          krb5_flags *flags)
{
    *flags = AD_CAMMAC_PROTECTED | AD_INFORMATIONAL;
}

static krb5_error_code
bot_request_init(krb5_context kcontext,
                 krb5_authdata_context context,
                 void *plugin_context,
                 void **request_context)
{
    struct bot_context *bctx;

    bctx = (struct bot_context *)calloc(1, sizeof(*bctx));
    if (bctx == NULL) {
        return ENOMEM;
    }

    *request_context = bctx;

    return 0;
}

static void
bot_free_indicators(krb5_context kcontext, struct bot_context *bctx)
{
    size_t i;

    if (bctx->indicators == NULL) {
        return;
    }

    for (i = 0; bctx->indicators[i] != NULL; i++) {
        krb5_free_data(kcontext, bctx->indicators[i]);
    }
    free(bctx->indicators);
    bctx->indicators = NULL;
}

static void
bot_request_fini(krb5_context kcontext,
                 krb5_authdata_context context,
                 void *plugin_context,
                 void *request_context)
{
    struct bot_context *bctx = (struct bot_context *)request_context;

    if (bctx != NULL) {
        bot_free_indicators(kcontext, bctx);
        free(bctx);
    }
}

static krb5_error_code
bot_import_authdata(krb5_context kcontext,
                    krb5_authdata_context context,
                    void *plugin_context,
                    void *request_context,
                    krb5_authdata **authdata,
                    krb5_boolean kdc_issued,
                    krb5_const_principal kdc_issuer)
{
    struct bot_context *bctx = (struct bot_context *)request_context;
    krb5_error_code ret;
    size_t i;

    bot_free_indicators(kcontext, bctx);

    for (i = 0; authdata != NULL && authdata[i] != NULL; i++) {
        ret = k5_authind_decode(authdata[i], &bctx->indicators);
        if (ret != 0) {
            return ret;
        }
    }

    return 0;
}

static void
bot_send_indicators(krb5_context kcontext,
                    const krb5_ap_req *req,
                    struct bot_context *bctx)
{
    struct sss_cli_req_data req_data;
    krb5_error_code kerr;
    char *princ_str = NULL;
    char *at;
    char *short_name = NULL;
    uint8_t *buf = NULL;
    size_t buf_len;
    size_t name_len;
    size_t offset;
    size_t i;
    size_t count;
    int errnop;

    if (bctx->indicators == NULL) {
        return;
    }

    /* Count indicators. */
    for (count = 0; bctx->indicators[count] != NULL; count++) {
        /* just counting */
    }

    if (count == 0) {
        return;
    }

    /* Extract principal name and strip @REALM. */
    kerr = krb5_unparse_name(kcontext, req->ticket->enc_part2->client,
                             &princ_str);
    if (kerr != 0) {
        return;
    }

    at = strrchr(princ_str, '@');
    if (at != NULL) {
        short_name = strndup(princ_str, at - princ_str);
    } else {
        short_name = strdup(princ_str);
    }
    if (short_name == NULL) {
        goto done;
    }

    /* Only forward indicators for BOT principals. */
    if (strncasecmp(short_name, BOT_PREFIX, BOT_PREFIX_LEN) != 0) {
        goto done;
    }

    /* Build request body: [bot_name\0][ind1\0][ind2\0]... */
    name_len = strlen(short_name) + 1;
    buf_len = name_len;
    for (i = 0; i < count; i++) {
        buf_len += bctx->indicators[i]->length + 1;
    }

    buf = malloc(buf_len);
    if (buf == NULL) {
        goto done;
    }

    memcpy(buf, short_name, name_len);
    offset = name_len;
    for (i = 0; i < count; i++) {
        memcpy(buf + offset, bctx->indicators[i]->data,
               bctx->indicators[i]->length);
        buf[offset + bctx->indicators[i]->length] = '\0';
        offset += bctx->indicators[i]->length + 1;
    }

    req_data.len = buf_len;
    req_data.data = buf;

    /* Send to PAM responder. Non-fatal on error. */
    sss_pam_make_request(SSS_PAM_REGISTER_BOT, &req_data,
                         NULL, NULL, &errnop);

done:
    free(buf);
    free(short_name);
    krb5_free_unparsed_name(kcontext, princ_str);
}

static krb5_error_code
bot_verify(krb5_context kcontext,
           krb5_authdata_context context,
           void *plugin_context,
           void *request_context,
           const krb5_auth_context *auth_context,
           const krb5_keyblock *key,
           const krb5_ap_req *req)
{
    struct bot_context *bctx = (struct bot_context *)request_context;

    if (bctx == NULL) {
        return 0;
    }

    bot_send_indicators(kcontext, req, bctx);

    return 0;
}

/*
 * Indicators are transient: they are forwarded to the PAM responder
 * during verify() and not needed afterwards. Serialize an empty state
 * (just an indicator count of 0) so that size/externalize/internalize
 * are consistent and the context can be copied without issues.
 */

static krb5_error_code
bot_size(krb5_context kcontext,
         krb5_authdata_context context,
         void *plugin_context,
         void *request_context,
         size_t *sizep)
{
    *sizep += sizeof(krb5_int32);

    return 0;
}

static krb5_error_code
bot_externalize(krb5_context kcontext,
                krb5_authdata_context context,
                void *plugin_context,
                void *request_context,
                krb5_octet **buffer,
                size_t *lenremain)
{
    return krb5_ser_pack_int32(0, buffer, lenremain);
}

static krb5_error_code
bot_internalize(krb5_context kcontext,
                krb5_authdata_context context,
                void *plugin_context,
                void *request_context,
                krb5_octet **buffer,
                size_t *lenremain)
{
    krb5_int32 count;
    krb5_error_code code;

    code = krb5_ser_unpack_int32(&count, buffer, lenremain);
    if (code != 0) {
        return code;
    }

    if (count != 0) {
        return EINVAL;
    }

    return 0;
}

static krb5_authdatatype bot_ad_types[] = {
    KRB5_AUTHDATA_AUTH_INDICATOR,
    0
};

krb5plugin_authdata_client_ftable_v0 authdata_client_0 = {
    "sssd_authdata_bot",
    bot_ad_types,
    bot_init,
    NULL,
    bot_flags,
    bot_request_init,
    bot_request_fini,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    bot_import_authdata,
    NULL,
    NULL,
    bot_verify,
    bot_size,
    bot_externalize,
    bot_internalize,
    NULL
};
