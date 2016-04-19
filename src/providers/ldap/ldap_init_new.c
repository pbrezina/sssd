/*
    SSSD

    LDAP Provider Initialization functions

    Authors:
        Simo Sorce <ssorce@redhat.com>

    Copyright (C) 2009 Red Hat

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

#include "util/child_common.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async_private.h"
#include "providers/ldap/sdap_access.h"
#include "providers/ldap/sdap_sudo.h"
#include "providers/ldap/sdap_autofs.h"
#include "providers/ldap/sdap_idmap.h"
#include "providers/fail_over_srv.h"
#include "providers/be_refresh.h"

/* Please use this only for short lists */
errno_t check_order_list_for_duplicates(char **list,
                                        bool case_sensitive)
{
    size_t c;
    size_t d;
    int cmp;

    for (c = 0; list[c] != NULL; c++) {
        for (d = c + 1; list[d] != NULL; d++) {
            if (case_sensitive) {
                cmp = strcmp(list[c], list[d]);
            } else {
                cmp = strcasecmp(list[c], list[d]);
            }
            if (cmp == 0) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Duplicate string [%s] found.\n", list[c]);
                return EINVAL;
            }
        }
    }

    return EOK;
}

static errno_t ldap_init_auth_ctx(TALLOC_CTX *mem_ctx,
                                  struct be_ctx *be_ctx,
                                  struct sdap_id_ctx *id_ctx,
                                  struct sdap_options *options)
{
    struct sdap_auth_ctx *auth_ctx;

    auth_ctx = talloc(mem_ctx, struct sdap_auth_ctx);
    if (auth_ctx == NULL) {
        return ENOMEM;
    }

    auth_ctx->be = be_ctx;
    auth_ctx->opts = options;
    auth_ctx->service = id_ctx->conn->service;
    auth_ctx->chpass_service = NULL;

    options->auth_ctx = auth_ctx;

    return EOK;
}

static errno_t init_chpass_service(TALLOC_CTX *mem_ctx,
                                   struct be_ctx *be_ctx,
                                   struct sdap_options *opts,
                                   struct sdap_service **_chpass_service)
{
    errno_t ret;
    const char *urls;
    const char *backup_urls;
    const char *dns_service_name;
    struct sdap_service *chpass_service;

    dns_service_name = dp_opt_get_string(opts->basic,
                                         SDAP_CHPASS_DNS_SERVICE_NAME);
    if (dns_service_name != NULL) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Service name for chpass discovery set to %s\n",
              dns_service_name);
    }

    urls = dp_opt_get_string(opts->basic, SDAP_CHPASS_URI);
    backup_urls = dp_opt_get_string(opts->basic, SDAP_CHPASS_BACKUP_URI);

    if (urls != NULL || backup_urls != NULL || dns_service_name != NULL) {
        ret = sdap_service_init(mem_ctx,
                                be_ctx,
                                "LDAP_CHPASS",
                                dns_service_name,
                                urls,
                                backup_urls,
                                &chpass_service);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to initialize failover service!\n");
            return ret;
        }
    } else {
        DEBUG(SSSDBG_TRACE_ALL,
              "ldap_chpass_uri and ldap_chpass_dns_service_name not set, "
              "using ldap_uri.\n");
        chpass_service = NULL;
    }

    *_chpass_service = chpass_service;
    return EOK;
}

static errno_t get_access_order_list(TALLOC_CTX *mem_ctx,
                                     const char *order,
                                     char ***_order_list)
{
    errno_t ret;
    char **order_list;
    int order_list_len;

    ret = split_on_separator(mem_ctx, order, ',', true, true,
                             &order_list, &order_list_len);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "split_on_separator failed.\n");
        goto done;
    }

    ret = check_order_list_for_duplicates(order_list, false);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "check_order_list_for_duplicates failed.\n");
        goto done;
    }

    if (order_list_len > LDAP_ACCESS_LAST) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Currently only [%d] different access rules are supported.\n",
              LDAP_ACCESS_LAST);
        ret = EINVAL;
        goto done;
    }

    *_order_list = order_list;

done:
    if (ret != EOK) {
        talloc_free(order_list);
    }

    return ret;
}

static errno_t check_expire_policy(struct sdap_options *opts)
{
    const char *expire_policy;
    bool matched_policy = false;
    const char *policies[] = {LDAP_ACCOUNT_EXPIRE_SHADOW,
                              LDAP_ACCOUNT_EXPIRE_AD,
                              LDAP_ACCOUNT_EXPIRE_NDS,
                              LDAP_ACCOUNT_EXPIRE_RHDS,
                              LDAP_ACCOUNT_EXPIRE_IPA,
                              LDAP_ACCOUNT_EXPIRE_389DS,
                              NULL};

    expire_policy = dp_opt_get_cstring(opts->basic,
                                       SDAP_ACCOUNT_EXPIRE_POLICY);
    if (expire_policy == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Warning: LDAP access rule 'expire' is set, "
              "but no ldap_account_expire_policy configured. "
              "All domain users will be denied access.\n");
        return EOK;
    }

    for (unsigned i = 0; policies[i] != NULL; i++) {
        if (strcasecmp(expire_policy, policies[i]) == 0) {
            matched_policy = true;
            break;
        }
    }

    if (matched_policy == false) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unsupported LDAP account expire policy [%s].\n",
              expire_policy);
        return EINVAL;
    }

    return EOK;
}

static errno_t get_access_filter(TALLOC_CTX *mem_ctx,
                                 struct sdap_options *opts,
                                 const char **_filter)
{
    const char *filter;

    filter = dp_opt_get_cstring(opts->basic, SDAP_ACCESS_FILTER);
    if (filter == NULL) {
        /* It's okay if this is NULL. In that case we will simply act
         * like the 'deny' provider.
         */
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Warning: LDAP access rule 'filter' is set, "
              "but no ldap_access_filter configured. "
              "All domain users will be denied access.\n");
        return EOK;
    }

    filter = sdap_get_access_filter(mem_ctx, filter);
    if (filter == NULL) {
        return ENOMEM;
    }

    *_filter = filter;

    return EOK;
}

static errno_t set_access_rules(TALLOC_CTX *mem_ctx,
                                struct sdap_access_ctx *access_ctx,
                                struct sdap_options *opts)
{
    errno_t ret;
    char **order_list = NULL;
    const char *order;
    size_t c;

    /* To make sure that in case of failure it's safe to be freed */
    access_ctx->filter = NULL;

    order = dp_opt_get_cstring(access_ctx->id_ctx->opts->basic,
                               SDAP_ACCESS_ORDER);
    if (order == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "ldap_access_order not given, using 'filter'.\n");
        order = "filter";
    }

    ret = get_access_order_list(mem_ctx, order, &order_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "get_access_order_list failed: [%d][%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    for (c = 0; order_list[c] != NULL; c++) {

        if (strcasecmp(order_list[c], LDAP_ACCESS_FILTER_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_FILTER;
            if (get_access_filter(mem_ctx, opts, &access_ctx->filter) != EOK) {
                goto done;
            }

        } else if (strcasecmp(order_list[c], LDAP_ACCESS_EXPIRE_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_EXPIRE;
            if (check_expire_policy(opts) != EOK) {
                goto done;
            }

        } else if (strcasecmp(order_list[c], LDAP_ACCESS_SERVICE_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_SERVICE;
        } else if (strcasecmp(order_list[c], LDAP_ACCESS_HOST_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_HOST;
        } else if (strcasecmp(order_list[c], LDAP_ACCESS_LOCK_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_LOCKOUT;
        } else if (strcasecmp(order_list[c],
                              LDAP_ACCESS_EXPIRE_POLICY_REJECT_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_EXPIRE_POLICY_REJECT;
        } else if (strcasecmp(order_list[c],
                              LDAP_ACCESS_EXPIRE_POLICY_WARN_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_EXPIRE_POLICY_WARN;
        } else if (strcasecmp(order_list[c],
                              LDAP_ACCESS_EXPIRE_POLICY_RENEW_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_EXPIRE_POLICY_RENEW;
        } else if (strcasecmp(order_list[c], LDAP_ACCESS_PPOLICY_NAME) == 0) {
            access_ctx->access_rule[c] = LDAP_ACCESS_PPOLICY;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unexpected access rule name [%s].\n", order_list[c]);
            ret = EINVAL;
            goto done;
        }
    }
    access_ctx->access_rule[c] = LDAP_ACCESS_EMPTY;
    if (c == 0) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Warning: access_provider=ldap set, "
              "but ldap_access_order is empty. "
              "All domain users will be denied access.\n");
    }

done:
    talloc_free(order_list);
    if (ret != EOK) {
        talloc_zfree(access_ctx->filter);
    }
    return ret;
}

static errno_t get_sdap_service(TALLOC_CTX *mem_ctx,
                                struct be_ctx *be_ctx,
                                struct sdap_options *opts,
                                struct sdap_service **_sdap_service)
{
    errno_t ret;
    const char *urls;
    const char *backup_urls;
    const char *dns_service_name;
    struct sdap_service *sdap_service;

    urls = dp_opt_get_string(opts->basic, SDAP_URI);
    backup_urls = dp_opt_get_string(opts->basic, SDAP_BACKUP_URI);
    dns_service_name = dp_opt_get_string(opts->basic, SDAP_DNS_SERVICE_NAME);
    if (dns_service_name != NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Service name for discovery set to %s\n", dns_service_name);
    }

    ret = sdap_service_init(mem_ctx, be_ctx, "LDAP",
                            dns_service_name,
                            urls,
                            backup_urls,
                            &sdap_service);
    if (ret != EOK) {
        return ret;
    }

    *_sdap_service = sdap_service;
    return EOK;
}

static bool should_call_gssapi_init(struct sdap_options *opts)
{
    const char *sasl_mech;

    sasl_mech = dp_opt_get_string(opts->basic, SDAP_SASL_MECH);
    if (sasl_mech == NULL) {
        return false;
    }

    if (strcasecmp(sasl_mech, "GSSAPI") != 0) {
        return false;
    }

    if (dp_opt_get_bool(opts->basic, SDAP_KRB5_KINIT) == false) {
        return false;
    }

    return true;
}

errno_t sssm_ldap_init(TALLOC_CTX *mem_ctx,
                       struct be_ctx *be_ctx,
                       struct data_provider *provider,
                       const char *module_name,
                       void **_module_data)
{
    struct sdap_id_ctx *sdap_id_ctx = NULL;
    struct sdap_service *sdap_service = NULL;
    struct sdap_options *opts = NULL;
    errno_t ret;

    ret = ldap_get_options(mem_ctx, be_ctx->domain, be_ctx->cdb,
                           be_ctx->conf_path, &opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to init LDAP options\n");
        goto done;
    }

    ret = get_sdap_service(mem_ctx, be_ctx, opts, &sdap_service);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to initialize failover service [%d][%s]!\n",
              ret, sss_strerror(ret));
        goto done;
    }

    sdap_id_ctx = sdap_id_ctx_new(mem_ctx, be_ctx, sdap_service);
    if (sdap_id_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to init id context.\n");
        ret = ENOMEM;
        goto done;
    }

    /* Move under id_ctx */
    sdap_id_ctx->opts = talloc_steal(sdap_id_ctx, opts);
    /* sdap_service is stealed in sdap_id_ctx_conn_add */

    if (should_call_gssapi_init(opts)) {
        ret = sdap_gssapi_init(sdap_id_ctx,
                               sdap_id_ctx->opts->basic,
                               sdap_id_ctx->be,
                               sdap_id_ctx->conn->service,
                               &sdap_id_ctx->krb5_service);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "sdap_gssapi_init failed [%d][%s].\n",
                  ret, sss_strerror(ret));
            goto done;
        }
    }

    ret = setup_tls_config(sdap_id_ctx->opts->basic);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to get TLS options [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* Setup the ID mapping object */
    ret = sdap_idmap_init(sdap_id_ctx,
                          sdap_id_ctx,
                          &sdap_id_ctx->opts->idmap_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Could not initialize ID mapping. In case ID mapping properties "
              "changed on the server, please remove the SSSD database\n");
        goto done;
    }

    ret = ldap_id_setup_tasks(sdap_id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "ldap_id_setup_tasks failed [%d][%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    ret = sdap_setup_child();
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "setup_child failed [%d][%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* Setup SRV lookup plugin */
    ret = be_fo_set_dns_srv_lookup_plugin(be_ctx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Unable to set SRV lookup plugin [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    /* Setup periodical refresh of expired records */
    ret = sdap_refresh_init(be_ctx->refresh_ctx, sdap_id_ctx);
    if (ret != EOK && ret != EEXIST) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Periodical refresh will not work [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    if (dp_module_auth_enabled(provider, module_name)) {
        ret = ldap_init_auth_ctx(mem_ctx, be_ctx, sdap_id_ctx, opts);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create auth context "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            return ret;
        }
    }

    *_module_data = sdap_id_ctx;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(opts);
        talloc_free(sdap_id_ctx);
        talloc_free(sdap_service);
    }

    return ret;
}

errno_t sssm_ldap_id_init(TALLOC_CTX *mem_ctx,
                          struct be_ctx *be_ctx,
                          void *module_data,
                          struct dp_method *dp_methods)
{
    struct sdap_id_ctx *id_ctx;

    id_ctx = talloc_get_type(module_data, struct sdap_id_ctx);

    dp_set_method(dp_methods, DPM_ACCOUNT_HANDLER, NULL, NULL, id_ctx,
                  struct sdap_id_ctx, void, struct dp_reply_std);

    return EOK;
}

errno_t sssm_ldap_auth_init(TALLOC_CTX *mem_ctx,
                            struct be_ctx *be_ctx,
                            void *module_data,
                            struct dp_method *dp_methods)
{
    struct sdap_id_ctx *id_ctx;
    struct sdap_auth_ctx *auth_ctx;

    id_ctx = talloc_get_type(module_data, struct sdap_id_ctx);
    auth_ctx = id_ctx->opts->auth_ctx;

    dp_set_method(dp_methods, DPM_AUTH_HANDLER, NULL, NULL, auth_ctx,
                  struct sdap_auth_ctx, void, struct dp_reply_std);

    return EOK;
}

errno_t sssm_ldap_access_init(TALLOC_CTX *mem_ctx,
                              struct be_ctx *be_ctx,
                              void *module_data,
                              struct dp_method *dp_methods)
{
    errno_t ret;

    struct sdap_access_ctx *access_ctx;

    access_ctx = talloc_zero(mem_ctx, struct sdap_access_ctx);
    if(access_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    access_ctx->id_ctx = talloc_get_type(module_data, struct sdap_id_ctx);

    ret = set_access_rules(access_ctx, access_ctx, access_ctx->id_ctx->opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "set_access_rules failed: [%d][%s].\n",
              ret, sss_strerror(ret));
        goto done;
    }

    dp_set_method(dp_methods, DPM_ACCESS_HANDLER, NULL, NULL, access_ctx,
                  struct sdap_access_ctx, void, struct dp_reply_std);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(access_ctx);
    }
    return ret;
}

errno_t sssm_ldap_chpass_init(TALLOC_CTX *mem_ctx,
                              struct be_ctx *be_ctx,
                              void *module_data,
                              struct dp_method *dp_methods)
{
    struct sdap_id_ctx *id_ctx;
    struct sdap_auth_ctx *auth_ctx;
    errno_t ret;

    id_ctx = talloc_get_type(module_data, struct sdap_id_ctx);
    auth_ctx = id_ctx->opts->auth_ctx;

    ret = init_chpass_service(id_ctx->opts->auth_ctx,
                              be_ctx,
                              id_ctx->opts,
                              &id_ctx->opts->auth_ctx->chpass_service);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "init_chpass_service failed with [%d][%s]!\n",
              ret, sss_strerror(ret));
        return ret;
    }

    dp_set_method(dp_methods, DPM_AUTH_HANDLER, NULL, NULL, auth_ctx,
                  struct sdap_auth_ctx, void, struct dp_reply_std);

    return EOK;
}

int sssm_ldap_autofs_init(struct be_ctx *be_ctx,
                          struct bet_ops **ops,
                          void **pvt_data)
{
#ifdef BUILD_AUTOFS
    /* TODO fix when we can compile with this
    struct sdap_id_ctx *id_ctx;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing LDAP autofs handler\n");

    id_ctx = talloc_get_type(module_data, struct sdap_id_ctx);

    return sdap_autofs_init(mem_ctx, be_ctx, id_ctx, dp_methods);
    */
    return ENOTSUP;
#else
    DEBUG(SSSDBG_MINOR_FAILURE, "Autofs init handler called but SSSD is "
                                 "built without autofs support, ignoring\n");
    return EOK;
#endif
}

errno_t sssm_ldap_sudo_init(TALLOC_CTX *mem_ctx,
                            struct be_ctx *be_ctx,
                            void *module_data,
                            struct dp_method *dp_methods)
{
#ifdef BUILD_SUDO
    /* TODO fix when we can compile with this */
    /* struct sdap_id_ctx *id_ctx; */
    /* errno_t ret; */

    /* DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing LDAP sudo handler\n"); */

    /* id_ctx = talloc_get_type(module_data, struct sdap_id_ctx); */

    /* return sdap_sudo_init(mem_ctx, be_ctx, id_ctx, dp_methods); */
    return ENOTSUP;
#else
    DEBUG(SSSDBG_MINOR_FAILURE, "Sudo init handler called but SSSD is "
                                 "built without sudo support, ignoring\n");
    return EOK;
#endif
}
