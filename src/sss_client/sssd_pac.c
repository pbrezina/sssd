/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2011, 2012, 2013 Red Hat

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

/* A short documentation about authdata plugins can be found in
 * http://http://k5wiki.kerberos.org/wiki/Projects/VerifyAuthData */

#include "config.h"

#include <krb5/krb5.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include "krb5_authdata_int.h"
#include "sss_cli.h"

#define BOT_PREFIX "BOT-"
#define BOT_PREFIX_LEN (sizeof(BOT_PREFIX) - 1)


struct sssd_context {
    krb5_data data;
    char **indicators;
    size_t num_indicators;
};

static krb5_error_code
sssdpac_init(krb5_context kcontext, void **plugin_context)
{
    *plugin_context = NULL;
    return 0;
}

static void
sssdpac_flags(krb5_context kcontext,
              void *plugin_context,
              krb5_authdatatype ad_type,
              krb5_flags *flags)
{
    *flags = AD_USAGE_KDC_ISSUED | AD_USAGE_TGS_REQ;
}

static void
sssdpac_fini(krb5_context kcontext, void *plugin_context)
{
    return;
}

static krb5_error_code
sssdpac_request_init(krb5_context kcontext,
                     krb5_authdata_context context,
                     void *plugin_context,
                     void **request_context)
{
    struct sssd_context *sssdctx;

    sssdctx = (struct sssd_context *)calloc(1, sizeof(*sssdctx));
    if (sssdctx == NULL) {
        return ENOMEM;
    }

    *request_context = sssdctx;

    return 0;
}

static void
sssdpac_free_indicators(struct sssd_context *sssdctx)
{
    size_t i;

    if (sssdctx->indicators == NULL) {
        return;
    }

    for (i = 0; i < sssdctx->num_indicators; i++) {
        free(sssdctx->indicators[i]);
    }
    free(sssdctx->indicators);
    sssdctx->indicators = NULL;
    sssdctx->num_indicators = 0;
}

static krb5_error_code
sssdpac_import_pac(struct sssd_context *sssdctx,
                   krb5_context kcontext,
                   krb5_authdata **authdata)
{
    char *data = NULL;

    if (authdata[0]->length > 0) {
        data = malloc(sizeof(char) * authdata[0]->length);
        if (data == NULL) {
            return ENOMEM;
        }
        memcpy(data, authdata[0]->contents, authdata[0]->length);
    }

    if (sssdctx->data.data != NULL) {
        krb5_free_data_contents(kcontext, &sssdctx->data);
    }

    sssdctx->data.length = authdata[0]->length;
    sssdctx->data.data = data;

    return 0;
}

static krb5_error_code
sssdpac_import_indicators(struct sssd_context *sssdctx,
                          krb5_authdata **authdata)
{
    size_t count;
    size_t i;

    /* Count entries. */
    for (count = 0; authdata[count] != NULL; count++) {
        /* just counting */
    }

    sssdpac_free_indicators(sssdctx);

    sssdctx->indicators = calloc(count, sizeof(char *));
    if (sssdctx->indicators == NULL) {
        return ENOMEM;
    }

    for (i = 0; i < count; i++) {
        sssdctx->indicators[i] = strndup((char *)authdata[i]->contents,
                                         authdata[i]->length);
        if (sssdctx->indicators[i] == NULL) {
            sssdpac_free_indicators(sssdctx);
            return ENOMEM;
        }
    }

    sssdctx->num_indicators = count;

    return 0;
}

static krb5_error_code
sssdpac_import_authdata(krb5_context kcontext,
                        krb5_authdata_context context,
                        void *plugin_context,
                        void *request_context,
                        krb5_authdata **authdata,
                        krb5_boolean kdc_issued,
                        krb5_const_principal kdc_issuer)
{
    struct sssd_context *sssdctx = (struct sssd_context *)request_context;

    if (authdata[0] == NULL) {
        return EINVAL;
    }

    switch (authdata[0]->ad_type) {
    case KRB5_AUTHDATA_WIN2K_PAC:
        return sssdpac_import_pac(sssdctx, kcontext, authdata);
    case KRB5_AUTHDATA_AUTH_INDICATOR:
        return sssdpac_import_indicators(sssdctx, authdata);
    default:
        return EINVAL;
    }
}

static void
sssdpac_request_fini(krb5_context kcontext,
                     krb5_authdata_context context,
                     void *plugin_context,
                     void *request_context)
{
    struct sssd_context *sssdctx = (struct sssd_context *)request_context;

    if (sssdctx != NULL) {
        if (sssdctx->data.data != NULL) {
            krb5_free_data_contents(kcontext, &sssdctx->data);
        }

        sssdpac_free_indicators(sssdctx);
        free(sssdctx);
    }
}

static void
sssdpac_send_indicators(krb5_context kcontext,
                        const krb5_ap_req *req,
                        struct sssd_context *sssdctx)
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
    int errnop;

    if (sssdctx->indicators == NULL || sssdctx->num_indicators == 0) {
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
    for (i = 0; i < sssdctx->num_indicators; i++) {
        buf_len += strlen(sssdctx->indicators[i]) + 1;
    }

    buf = malloc(buf_len);
    if (buf == NULL) {
        goto done;
    }

    memcpy(buf, short_name, name_len);
    offset = name_len;
    for (i = 0; i < sssdctx->num_indicators; i++) {
        size_t ind_len = strlen(sssdctx->indicators[i]) + 1;
        memcpy(buf + offset, sssdctx->indicators[i], ind_len);
        offset += ind_len;
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

static krb5_error_code sssdpac_verify(krb5_context kcontext,
                                      krb5_authdata_context context,
                                      void *plugin_context,
                                      void *request_context,
                                      const krb5_auth_context *auth_context,
                                      const krb5_keyblock *key,
                                      const krb5_ap_req *req)
{
    krb5_error_code kerr;
    int ret;
    krb5_pac pac;
    struct sssd_context *sssdctx = (struct sssd_context *)request_context;
    struct sss_cli_req_data sss_data;
    int errnop;

    if (sssdctx == NULL) {
        return EINVAL;
    }

    /* Forward auth indicators to PAM responder if available.
     * Do this before the PAC check so indicators are sent even
     * for tickets that carry only auth indicators and no PAC. */
    sssdpac_send_indicators(kcontext, req, sssdctx);

    if (sssdctx->data.data == NULL) {
        /* No PAC data, nothing to verify. */
        return 0;
    }

    kerr = krb5_pac_parse(kcontext, sssdctx->data.data,
                          sssdctx->data.length, &pac);
    if (kerr != 0) {
        return EINVAL;
    }

    kerr = krb5_pac_verify(kcontext, pac,
                           req->ticket->enc_part2->times.authtime,
                           req->ticket->enc_part2->client, key, NULL);
    /* deallocate pac */
    krb5_pac_free(kcontext, pac);
    pac = NULL;
    if (kerr != 0) {
        /* The krb5 documentation says:
         * A checksum mismatch can occur if the PAC was copied from a
         * cross-realm TGT by an ignorant KDC; also Apple Mac OS X Server
         * Open Directory (as of 10.6) generates PACs with no server checksum
         * at all. One should consider not failing the whole authentication
         * because of this reason, but, instead, treating the ticket as
         * if it did not contain a PAC or marking the PAC information as
         * non-verified.
         */
        return 0;
    }

    sss_data.len = sssdctx->data.length;
    sss_data.data = sssdctx->data.data;

    ret = sss_pac_make_request_with_lock(SSS_PAC_ADD_PAC_USER, &sss_data,
                                         NULL, NULL, &errnop);
    if (ret != 0) {
        /* Ignore the error */
    }

    return 0;
}

static krb5_error_code
sssdpac_size(krb5_context kcontext,
             krb5_authdata_context context,
             void *plugin_context,
             void *request_context,
             size_t *sizep)
{
    struct sssd_context *sssdctx = (struct sssd_context *)request_context;

    if (sssdctx == NULL || sssdctx->data.data == NULL) {
        *sizep += 2 * sizeof(krb5_int32);
        return 0;
    }

    *sizep += sizeof(krb5_int32);

    *sizep += sssdctx->data.length;

    *sizep += sizeof(krb5_int32);

    return 0;
}

static krb5_error_code
sssdpac_externalize(krb5_context kcontext,
                    krb5_authdata_context context,
                    void *plugin_context,
                    void *request_context,
                    krb5_octet **buffer,
                    size_t *lenremain)
{
    krb5_error_code code = 0;
    struct sssd_context *sssdctx = (struct sssd_context *)request_context;
    size_t required = 0;
    krb5_octet *bp;
    size_t remain;

    bp = *buffer;
    remain = *lenremain;

    if (sssdctx == NULL) {
        krb5_ser_pack_int32(0, &bp, &remain); /* length */
        krb5_ser_pack_int32(0, &bp, &remain); /* verified */
        *buffer = bp;
        *lenremain = remain;
        return 0;
    }

    if (sssdctx->data.data != NULL) {
        sssdpac_size(kcontext, context, plugin_context,
                   request_context, &required);

        if (required <= remain) {
            krb5_ser_pack_int32((krb5_int32)sssdctx->data.length,
                                &bp, &remain);
            krb5_ser_pack_bytes((krb5_octet *)sssdctx->data.data,
                                (size_t)sssdctx->data.length,
                                &bp, &remain);
            krb5_ser_pack_int32(0,
                                &bp, &remain);
        } else {
            code = ENOMEM;
        }
    } else {
        krb5_ser_pack_int32(0, &bp, &remain); /* length */
        krb5_ser_pack_int32(0, &bp, &remain); /* verified */
    }

    *buffer = bp;
    *lenremain = remain;

    return code;
}

static krb5_error_code
sssdpac_internalize(krb5_context kcontext,
                    krb5_authdata_context context,
                    void *plugin_context,
                    void *request_context,
                    krb5_octet **buffer,
                    size_t *lenremain)
{
    struct sssd_context *sssdctx = (struct sssd_context *)request_context;
    krb5_error_code code;
    krb5_int32 ibuf;
    krb5_octet *bp;
    size_t remain;
    krb5_data data;

    if (sssdctx == NULL) {
        return EINVAL;
    }

    bp = *buffer;
    remain = *lenremain;

    /* length */
    code = krb5_ser_unpack_int32(&ibuf, &bp, &remain);
    if (code != 0) {
        return code;
    }

    if (ibuf != 0) {

        data.length = ibuf;
        data.data = malloc(sizeof(char) * ibuf);
        if (data.data == NULL) {
            return ENOMEM;
        }
        memcpy(data.data, bp, ibuf);

        bp += ibuf;
        remain -= ibuf;
    } else {
        data.length = 0;
        data.data = NULL;
    }

    /* verified */
    code = krb5_ser_unpack_int32(&ibuf, &bp, &remain);
    if (code != 0) {
        free(data.data);
        return code;
    }

    if (sssdctx->data.data != NULL) {
        krb5_free_data_contents(kcontext, &sssdctx->data);
    }

    sssdctx->data.length = data.length;
    sssdctx->data.data = data.data;

    *buffer = bp;
    *lenremain = remain;

    return 0;
}

static krb5_authdatatype sssdpac_ad_types[] = {
    KRB5_AUTHDATA_WIN2K_PAC,
    KRB5_AUTHDATA_AUTH_INDICATOR,
    0
};

krb5plugin_authdata_client_ftable_v0 authdata_client_0 = {
    "sssd_sssdpac",
    sssdpac_ad_types,
    sssdpac_init,
    sssdpac_fini,
    sssdpac_flags,
    sssdpac_request_init,
    sssdpac_request_fini,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    sssdpac_import_authdata,
    NULL,
    NULL,
    sssdpac_verify,
    sssdpac_size,
    sssdpac_externalize,
    sssdpac_internalize,
    NULL
};
