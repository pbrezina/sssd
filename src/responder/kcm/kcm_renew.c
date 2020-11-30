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
    time_t start_time;
    time_t lifetime;
    time_t start_renew_at;
};

struct auth_data {
    struct krb5_ctx *krb5_ctx;
    struct renew_data *renew_data;
    hash_table_t *table;
    hash_key_t key;
};

static void kcm_renew_tgt_done(struct tevent_req *req);

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

static errno_t kcm_renew_all_tgts(struct renew_tgt_ctx *renew_tgt_ctx)
{
    int ret;
    hash_entry_t *entries;
    unsigned long count;
    size_t c;
    time_t now;
    struct auth_data *auth_data;
    struct renew_data *renew_data;
    struct tevent_timer *te = NULL;

    ret = hash_entries(renew_tgt_ctx->tgt_table, &count, &entries);
    if (ret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "hash_entries failed.\n");
        return ENOMEM;
    }
    DEBUG(SSSDBG_TRACE_ALL,
          "JS-Found [%lu] entries.\n", count);

    now = time(NULL);

    for (c = 0; c < count; c++) {
        renew_data = talloc_get_type(entries[c].value.ptr, struct renew_data);
        DEBUG(SSSDBG_TRACE_ALL,
              "JS-Checking [%s] for renewal at [%.24s].\n", renew_data->ccname,
                  ctime(&renew_data->start_renew_at));
        if (renew_data->start_renew_at < now) {
            auth_data = talloc_zero(renew_tgt_ctx, struct auth_data);
            if (auth_data == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
            } else {
                auth_data->krb5_ctx = renew_tgt_ctx->krb5_ctx;
                auth_data->table = renew_tgt_ctx->tgt_table;
                auth_data->renew_data = renew_data;
                auth_data->key.type = entries[c].key.type;
                auth_data->key.str = talloc_strdup(auth_data,
                                                   entries[c].key.str);
                if (auth_data->key.str == NULL) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
                } else {
                    te = tevent_add_timer(renew_tgt_ctx->ev,
                                          auth_data, tevent_timeval_current(),
                                          kcm_renew_tgt, auth_data);
                    if (te == NULL) {
                        DEBUG(SSSDBG_CRIT_FAILURE,
                              "tevent_add_timer failed.\n");
                    }
                }
            }

            if (auth_data == NULL || te == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "JS-Failed to renew TGT in [%s].\n", renew_data->ccname);
                ret = hash_delete(renew_tgt_ctx->tgt_table, &entries[c].key);
                if (ret != HASH_SUCCESS) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "hash_delete failed.\n");
                }
            }
        }
    }

    talloc_free(entries);

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

    DEBUG(SSSDBG_TRACE_LIBS, "JS-Renew handler called.\n");

	/* Add any renew-applicable KCM tickets to renew table */
	ret = kcm_ccdb_renew_init(renew_tgt_ctx->rctx, renew_tgt_ctx->krb5_ctx,
                              ev, renew_tgt_ctx->db);
    if (ret != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to add KCM tickets to table.\n");
        talloc_zfree(renew_tgt_ctx);
        return;
    }

    ret = kcm_renew_all_tgts(renew_tgt_ctx);

    next = tevent_timeval_current_ofs(renew_tgt_ctx->timer_interval, 0);
    renew_tgt_ctx->te = tevent_add_timer(ev, renew_tgt_ctx,
                                         next, kcm_renew_tgt_timer_handler,
                                         renew_tgt_ctx);
}


static void kcm_renew_del_cb(hash_entry_t *entry, hash_destroy_enum type, void *pvt)
{
    struct renew_data *renew_data;

    if (entry->value.type == HASH_VALUE_PTR) {
        renew_data = talloc_get_type(entry->value.ptr, struct renew_data);
        talloc_zfree(renew_data);
        return;
    }

    DEBUG(SSSDBG_CRIT_FAILURE,
          "Unexpected value type [%d].\n", entry->value.type);
}

errno_t kcm_add_tgt_to_renew_table(struct krb5_ctx *krb5_ctx, const char *ccname,
                                   struct tgt_times *tgtt, const char *upn)
{
    int ret;
    hash_key_t key;
    hash_value_t value;
    struct renew_data *renew_data = NULL;

    if (krb5_ctx->renew_tgt_ctx == NULL) {
        DEBUG(SSSDBG_TRACE_LIBS ,"Renew context not initialized, "
                  "automatic renewal not available.\n");
        return EOK;
    }

    if (upn == NULL || ccname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing user principal name or ccname.\n");
        return EINVAL;
    }

    /* hash_enter copies the content of the hash string, so it is safe to use
     * discard_const_p here. */
    key.type = HASH_KEY_STRING;
    key.str = discard_const_p(char, upn);

    renew_data = talloc_zero(krb5_ctx->renew_tgt_ctx, struct renew_data);
    if (renew_data == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    renew_data->ccname = talloc_strdup(renew_data, ccname);

    renew_data->start_time = tgtt->starttime;
    renew_data->lifetime = tgtt->endtime;
    renew_data->start_renew_at = (time_t) (tgtt->starttime +
                                        0.5 *(tgtt->endtime - tgtt->starttime));

    value.type = HASH_VALUE_PTR;
    value.ptr = renew_data;

    ret = hash_enter(krb5_ctx->renew_tgt_ctx->tgt_table, &key, &value);
    if (ret != HASH_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE, "hash_enter failed.\n");
        ret = EFAULT;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_LIBS,
          "JS-Added [%s][%s] for renewal at [%s].",
          key.str, renew_data->ccname,
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

    ret = sss_hash_create_ex(krb5_ctx->renew_tgt_ctx, INITIAL_TGT_TABLE_SIZE,
                             &krb5_ctx->renew_tgt_ctx->tgt_table, 0, 0, 0, 0,
                             kcm_renew_del_cb, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sss_hash_create failed.\n");
        goto fail;
    }

    krb5_ctx->renew_tgt_ctx->rctx = rctx;
    krb5_ctx->renew_tgt_ctx->krb5_ctx = krb5_ctx;
    krb5_ctx->renew_tgt_ctx->db = db,
    krb5_ctx->renew_tgt_ctx->ev = ev;
    krb5_ctx->renew_tgt_ctx->timer_interval = renew_intv;

    /* Instead of check ccache files,
     * Check KCM entries for tickets to renew */
    next = tevent_timeval_current_ofs(krb5_ctx->renew_tgt_ctx->timer_interval,
                                      0);
    krb5_ctx->renew_tgt_ctx->te = tevent_add_timer(ev, krb5_ctx->renew_tgt_ctx,
                                                   next, kcm_renew_tgt_timer_handler,
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
