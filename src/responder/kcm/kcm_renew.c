/*
    SSSD

    KCM Kerberos renewals -- Renew a TGT automatically

    Authors:
        Justin Stephenson <jstephen@redhat.com>

    Copyright (C) 2020 Red Hat

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
#include "util/util.h"
#include "providers/krb5/krb5_common.h"
#include "providers/krb5/krb5_auth.h"
#include "providers/krb5/krb5_utils.h"
#include "providers/krb5/krb5_ccache.h"
#include "responder/kcm/kcmsrv_ccache.h"
#include "responder/kcm/kcmsrv_pvt.h"
#include "responder/kcm/kcm_renew.h"

#define INITIAL_TGT_TABLE_SIZE 10

extern struct dp_option default_krb5_opts[];

struct renew_tgt_ctx {
    hash_table_t *tgt_table;
    struct tevent_context *ev;
    struct krb5_ctx *krb5_ctx;
    struct resp_ctx *rctx;
    struct kcm_ccdb *db;
    time_t timer_interval;
    struct tevent_timer *te;
};

struct renew_data {
    const char *ccname;
    uid_t uid;
    gid_t gid;
    time_t start_time;
    time_t lifetime;
    time_t start_renew_at;
    time_t renew_till;
};

struct auth_data {
    struct krb5_ctx *krb5_ctx;
    struct renew_data *renew_data;
    hash_table_t *table;
    const char *key;
};

static void kcm_renew_tgt_done(struct tevent_req *req);

static int kcm_get_auth_provider_options(struct kcm_ctx *kctx,
                                         struct krb5_ctx *krb5_ctx,
                                         time_t *_renew_intv)
{
    errno_t ret;
    char *lifetime_str;
    char *rtime;
    bool validate;
    bool canonicalize;
    int child_timeout;
    struct dp_option *opts;
    const char *conf_path;
    char *auth_provider;
    struct sss_domain_info *domains;
    struct sss_domain_info *dom;

    ret = confdb_get_domains(kctx->rctx->cdb, &domains);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot get domains\n");
        goto done;
    }

    for (dom = domains; dom != NULL;
            dom = get_next_domain(dom, SSS_GND_DESCEND)) {

        conf_path = talloc_asprintf(kctx->rctx, CONFDB_DOMAIN_PATH_TMPL,
                                    dom->name);
        if (conf_path == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory\n");
            ret = ENOMEM;
            goto done;
        }

        ret = confdb_get_string(kctx->rctx->cdb,
                                kctx->rctx,
                                conf_path,
                                CONFDB_DOMAIN_AUTH_PROVIDER,
                                NULL, &auth_provider);

        if (auth_provider == NULL ||
            strcasecmp(auth_provider, "krb5") != 0) {
            continue;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Checking auth provider options for: "
                                 "[%s]\n", dom->name);
        ret = dp_get_options(kctx->rctx, kctx->rctx->cdb, conf_path,
                             default_krb5_opts, KRB5_OPTS, &opts);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "dp_get_options failed\n");
            goto done;
        }

        /* Lifetime */
        lifetime_str = dp_opt_get_string(opts, KRB5_LIFETIME);
        if (lifetime_str != NULL) {
            ret = krb5_string_to_deltat(lifetime_str,
                                        &krb5_ctx->lifetime);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to convert lifetime string.\n");
                goto done;
            }
            krb5_ctx->lifetime_str = lifetime_str;
        }

        /* Renewable lifetime */
        rtime = dp_opt_get_string(opts, KRB5_RENEWABLE_LIFETIME);
        if (rtime != 0) {
            ret = krb5_string_to_deltat(rtime, &krb5_ctx->rlife);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Failed to convert renewable lifetime string.\n");
                goto done;
            }
            krb5_ctx->rlife_str = rtime;
        }

        /* Validate */
        validate = dp_opt_get_bool(opts, KRB5_VALIDATE);
        ret = dp_opt_set_bool(krb5_ctx->opts, KRB5_VALIDATE, validate);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Cannot set dp opt krb5 validate\n");
            goto done;
        }

        /* Canonicalize */
        canonicalize = dp_opt_get_bool(opts, KRB5_CANONICALIZE);
        ret = dp_opt_set_bool(krb5_ctx->opts, KRB5_CANONICALIZE,
                              canonicalize);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot set dp opt krb5 "
                                     "canonicalize\n");
            goto done;
        }

        /* Child timeout */
        child_timeout = dp_opt_get_int(opts, KRB5_AUTH_TIMEOUT);
        if (child_timeout > 0) {
            ret = dp_opt_set_int(krb5_ctx->opts, KRB5_AUTH_TIMEOUT,
                                 child_timeout);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Cannot set krb5 child "
                                         "timeout\n");
                goto done;
            }
        }

        break;
    }

    ret = EOK;
done:
    return ret;
}

static int kcm_get_krb5_config(struct kcm_ctx *kctx,
                               struct krb5_ctx *krb5_ctx,
                               time_t *_renew_intv)
{
    errno_t ret;
    char *rtime;
    char *lifetime_str;
    bool validate;
    bool canonicalize;
    int child_timeout;
    bool kcm_renew_option_defined;
    char *renew_intv_str;
    time_t renew_intv;
    krb5_deltat renew_interval_delta;
    krb5_error_code kerr;

    /* Renew interval */
    ret = confdb_get_string(kctx->rctx->cdb,
                            kctx->rctx,
                            kctx->rctx->confdb_service_path,
                            CONFDB_KCM_KRB5_RENEW_INTERVAL,
                            0, &renew_intv_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get renew interval\n");
        goto done;
    }

    if (renew_intv_str != NULL) {
        kerr = krb5_string_to_deltat(renew_intv_str, &renew_interval_delta);
        if (kerr != 0) {
            DEBUG(SSSDBG_FATAL_FAILURE, "krb5_string_to_deltat failed\n");
            ret = ENOMEM;
            goto done;
        }

        kcm_renew_option_defined = true;
        renew_intv = renew_interval_delta;
    }

    /* Lifetime */
    ret = confdb_get_string(kctx->rctx->cdb,
                            kctx->rctx,
                            kctx->rctx->confdb_service_path,
                            CONFDB_KCM_KRB5_LIFETIME,
                            NULL, &lifetime_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get confdb lifetime\n");
        goto done;
    }

    if (lifetime_str != NULL) {
        ret = krb5_string_to_deltat(lifetime_str, &krb5_ctx->lifetime);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to convert lifetime string.\n");
            goto done;
        }
        kcm_renew_option_defined = true;
        krb5_ctx->lifetime_str = lifetime_str;
    }

    /* Renewable lifetime */
    ret = confdb_get_string(kctx->rctx->cdb,
                            kctx->rctx,
                            kctx->rctx->confdb_service_path,
                            CONFDB_KCM_KRB5_RENEWABLE_LIFETIME,
                            NULL, &rtime);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get confdb renewable lifetime\n");
        goto done;
    }

    if (rtime != 0) {
        ret = krb5_string_to_deltat(rtime, &krb5_ctx->rlife);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to convert renewable lifetime "
                                     "string.\n");
            goto done;
        }
        kcm_renew_option_defined = true;
        krb5_ctx->rlife_str = rtime;
    }

    /* Validate */
    ret = confdb_get_bool(kctx->rctx->cdb,
                          kctx->rctx->confdb_service_path,
                          CONFDB_KCM_KRB5_VALIDATE,
                          false, &validate);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get confdb krb5 validate\n");
        goto done;
    }

    ret = dp_opt_set_bool(krb5_ctx->opts, KRB5_VALIDATE, validate);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set dp opt krb5 validate\n");
        goto done;
    }

    /* Canonicalize */
    ret = confdb_get_bool(kctx->rctx->cdb,
                          kctx->rctx->confdb_service_path,
                          CONFDB_KCM_KRB5_CANONICALIZE,
                          false, &canonicalize);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get confdb krb5 canonicalize\n");
        goto done;
    }
    ret = dp_opt_set_bool(krb5_ctx->opts, KRB5_CANONICALIZE, canonicalize);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot set dp opt krb5 canonicalize\n");
        goto done;
    }

    /* Child timeout */
    ret = confdb_get_int(kctx->rctx->cdb,
                         kctx->rctx->confdb_service_path,
                         CONFDB_KCM_KRB5_AUTH_TIMEOUT,
                         0, &child_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get krb5 child timeout\n");
        goto done;
    }

    if (child_timeout > 0) {
        ret = dp_opt_set_int(krb5_ctx->opts, KRB5_AUTH_TIMEOUT, child_timeout);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Cannot set krb5 child timeout\n");
            goto done;
        }
        kcm_renew_option_defined = true;
    }

    /* Fallback to first auth_provider=krb5 domain */
    if (kcm_renew_option_defined == false) {
        ret = kcm_get_auth_provider_options(kctx, krb5_ctx, &renew_intv);
        if (ret != EOK) {
            /* Not fatal */
            DEBUG(SSSDBG_OP_FAILURE, "Failed to read auth provider options\n");
        }
    }

    *_renew_intv = renew_intv;
    ret = EOK;
done:
    return ret;
}

int kcm_get_renewal_config(struct kcm_ctx *kctx,
                           struct krb5_ctx **_krb5_ctx,
                           time_t *renew_intv)
{
    int ret;
    struct krb5_ctx *krb5_ctx;
    int i;

    krb5_ctx = talloc_zero(kctx->rctx, struct krb5_ctx);
    if (krb5_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "fatal error allocating krb5_ctx\n");
        ret = ENOMEM;
        goto done;
    }

    /* Set default Kerberos options */
    krb5_ctx->opts = talloc_zero_array(krb5_ctx, struct dp_option, KRB5_OPTS);
    if (!krb5_ctx->opts) goto done;
    for (i = 0; i < KRB5_OPTS; i++) {
        krb5_ctx->opts[i].opt_name = default_krb5_opts[i].opt_name;
        krb5_ctx->opts[i].type = default_krb5_opts[i].type;
        krb5_ctx->opts[i].def_val = default_krb5_opts[i].def_val;
        switch (krb5_ctx->opts[i].type) {
            case DP_OPT_STRING:
                ret = dp_opt_set_string(krb5_ctx->opts, i,
                                        default_krb5_opts[i].def_val.string);
                break;
            case DP_OPT_BLOB:
                ret = dp_opt_set_blob(krb5_ctx->opts, i,
                                      default_krb5_opts[i].def_val.blob);
                break;
            case DP_OPT_NUMBER:
                ret = dp_opt_set_int(krb5_ctx->opts, i,
                                     default_krb5_opts[i].def_val.number);
                break;
            case DP_OPT_BOOL:
                ret = dp_opt_set_bool(krb5_ctx->opts, i,
                                      default_krb5_opts[i].def_val.boolean);
                break;
        }
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed setting default KCM kerberos "
                                     "options\n");
            talloc_free(krb5_ctx->opts);
            goto done;
        }
    }

    /* Override with config options */
    kcm_get_krb5_config(kctx, krb5_ctx, renew_intv);

    *_krb5_ctx = krb5_ctx;
    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(krb5_ctx);
    }
    return ret;
}

static void kcm_renew_tgt(struct tevent_context *ev, struct tevent_timer *te,
                      struct timeval current_time, void *private_data)
{
    struct auth_data *auth_data = talloc_get_type(private_data,
                                                  struct auth_data);
    struct tevent_req *req;
}

static void kcm_renew_tgt_done(struct tevent_req *req)
{
}

errno_t kcm_renew_all_tgts(struct renew_tgt_ctx *renew_tgt_ctx)
{
    hash_key_t *keys;
    unsigned long count;
    int ret;
    size_t i;
    time_t now;
    struct auth_data *auth_data;
    struct renew_data *renew_data;
    struct tevent_timer *te;

    ret = hash_keys(renew_tgt_ctx->tgt_table, &count, &keys);
    if (ret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed retrieving hash keys.\n");
        return EIO;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL, "Found [%lu] renewal entries.\n", count);

    now = time(NULL);

    for (i = 0; i < count; i++) {
        renew_data = sss_ptr_hash_lookup(renew_tgt_ctx->tgt_table, keys[i].c_str,
                                         struct renew_data);
        DEBUG(SSSDBG_TRACE_INTERNAL, "Checking [%s] for renewal at [%.24s].\n",
              renew_data->ccname, ctime(&renew_data->start_renew_at));
        if (renew_data->renew_till < now) {
            DEBUG(SSSDBG_TRACE_INTERNAL, "Renew time exceeded, removing [%s].\n",
                                         renew_data->ccname);
            talloc_free(renew_data);
        } else if (renew_data->start_renew_at <= now) {
            auth_data = talloc_zero(renew_tgt_ctx, struct auth_data);
            if (auth_data == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
            } else {
                auth_data->krb5_ctx = renew_tgt_ctx->krb5_ctx;
                auth_data->table = renew_tgt_ctx->tgt_table;
                auth_data->renew_data = renew_data;
                auth_data->key = talloc_strdup(auth_data, keys[i].c_str);
                if (auth_data->key == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
                } else {
                    te = tevent_add_timer(renew_tgt_ctx->ev,
                                          auth_data, tevent_timeval_current(),
                                          kcm_renew_tgt, auth_data);
                    if (te == NULL) {
                        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_add_timer failed.\n");
                    }
                }
            }

            if (auth_data == NULL || te == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "Failed to renew TGT in [%s].\n", renew_data->ccname);
                talloc_free(renew_data);
            }
        }
    }

    return EOK;
}


static void kcm_renew_tgt_timer_handler(struct tevent_context *ev,
                                        struct tevent_timer *te,
                                        struct timeval current_time,
										void *data)
{
    struct renew_tgt_ctx *renew_tgt_ctx = talloc_get_type(data,
                                                          struct renew_tgt_ctx);
    errno_t ret;
    struct timeval next;

    /* forget the timer event, it will be freed by the tevent timer loop */
    renew_tgt_ctx->te = NULL;

	/* Add any renew-applicable KCM tickets to renew table */
	ret = kcm_ccdb_renew_init(renew_tgt_ctx->rctx, renew_tgt_ctx->krb5_ctx,
                              ev, renew_tgt_ctx->db);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to add KCM tickets to table.\n");
        talloc_zfree(renew_tgt_ctx);
        return;
    }

    ret = kcm_renew_all_tgts(renew_tgt_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to attempt renewal of KCM ticket"
                                   " table.\n");
        talloc_zfree(renew_tgt_ctx);
        return;
    }

    next = tevent_timeval_current_ofs(renew_tgt_ctx->timer_interval, 0);
    renew_tgt_ctx->te = tevent_add_timer(ev, renew_tgt_ctx,
                                         next, kcm_renew_tgt_timer_handler,
                                         renew_tgt_ctx);
    if (renew_tgt_ctx->te == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup timer\n");
        talloc_zfree(renew_tgt_ctx);
        return;
    }
}

errno_t kcm_add_tgt_to_renew_table(struct krb5_ctx *krb5_ctx,
                                   const char *ccname,
                                   uid_t uid,
                                   gid_t gid,
                                   struct tgt_times *tgtt,
                                   const char *upn)
{
    int ret;
    struct renew_data *renew_data;
    struct renew_data *existing_tgt_entry;

    if (krb5_ctx->renew_tgt_ctx == NULL) {
        DEBUG(SSSDBG_TRACE_LIBS, "Renew context not initialized, "
                  "automatic renewal not available.\n");
        return EOK;
    }

    if (upn == NULL || ccname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing user principal name or ccname.\n");
        return EINVAL;
    }

    renew_data = talloc_zero(krb5_ctx->renew_tgt_ctx, struct renew_data);
    if (renew_data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    existing_tgt_entry = talloc_zero(krb5_ctx->renew_tgt_ctx, struct renew_data);
    if (existing_tgt_entry == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    renew_data->ccname = talloc_strdup(renew_data, ccname);
    renew_data->uid = uid;
    renew_data->gid = gid;

    renew_data->start_time = tgtt->starttime;
    renew_data->lifetime = tgtt->endtime;
    renew_data->start_renew_at = (time_t) (tgtt->starttime +
                                        0.5 *(tgtt->endtime - tgtt->starttime));
    renew_data->renew_till = tgtt->renew_till;

    /* Overwrite existing entry with updated times */
    existing_tgt_entry = sss_ptr_hash_lookup(krb5_ctx->renew_tgt_ctx->tgt_table, upn,
                                             struct renew_data);
    if (existing_tgt_entry != NULL) {
        if (strcmp(existing_tgt_entry->ccname, ccname) == 0) {
            talloc_free(existing_tgt_entry);
        }
    }

    ret = sss_ptr_hash_add(krb5_ctx->renew_tgt_ctx->tgt_table,
                     upn, renew_data, struct renew_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_ptr_hash_add failed\n");
        ret = EFAULT;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_LIBS,
          "Added [%s][%s] for renewal at [%s].",
          upn, renew_data->ccname,
          ctime(&renew_data->start_renew_at));

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(renew_data);
    }
    return ret;
}

errno_t kcm_renewal_init(struct resp_ctx *rctx,
                         struct krb5_ctx *krb5_ctx,
                         struct tevent_context *ev,
                         struct kcm_ccdb *db,
                         time_t renew_intv)
{
    int ret;
    struct timeval next;

    krb5_ctx->renew_tgt_ctx = talloc_zero(krb5_ctx, struct renew_tgt_ctx);
    if (krb5_ctx->renew_tgt_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }

    krb5_ctx->renew_tgt_ctx->tgt_table = sss_ptr_hash_create(krb5_ctx->renew_tgt_ctx,
                                                             NULL,
                                                             NULL);
    if (krb5_ctx->renew_tgt_ctx->tgt_table == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_ptr_hash_create failed.\n");
        goto fail;
    }

    krb5_ctx->renew_tgt_ctx->rctx = rctx;
    krb5_ctx->renew_tgt_ctx->krb5_ctx = krb5_ctx;
    krb5_ctx->renew_tgt_ctx->db = db,
    krb5_ctx->renew_tgt_ctx->ev = ev;
    krb5_ctx->renew_tgt_ctx->timer_interval = renew_intv;

    /* Check KCM for tickets to renew */
    next = tevent_timeval_current_ofs(krb5_ctx->renew_tgt_ctx->timer_interval,
                                      0);
    krb5_ctx->renew_tgt_ctx->te = tevent_add_timer(ev, krb5_ctx->renew_tgt_ctx,
                                                   next,
                                                   kcm_renew_tgt_timer_handler,
                                                   krb5_ctx->renew_tgt_ctx);
    if (krb5_ctx->renew_tgt_ctx->te == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_add_timer failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    return EOK;

fail:
    talloc_zfree(krb5_ctx->renew_tgt_ctx);
    return ret;
}
