/*
   SSSD

   Data Provider Process

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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

#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <string.h>
#include <sys/time.h>
#include <errno.h>
#include <dlfcn.h>
#include <popt.h>
#include <dbus/dbus.h>

#include <security/pam_appl.h>
#include <security/pam_modules.h>

#include "util/util.h"
#include "util/sss_utf8.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"
#include "sbus/sssd_dbus.h"
#include "providers/backend.h"
#include "providers/fail_over.h"
#include "providers/be_refresh.h"
#include "providers/be_ptask.h"
#include "util/child_common.h"
#include "resolv/async_resolv.h"
#include "monitor/monitor_interfaces.h"

#define MSG_TARGET_NO_CONFIGURED "sssd_be: The requested target is not configured"

#define ACCESS_PERMIT "permit"
#define ACCESS_DENY "deny"
#define NO_PROVIDER "none"

static int data_provider_res_init(struct sbus_request *dbus_req, void *data);
static int data_provider_go_offline(struct sbus_request *dbus_req, void *data);
static int data_provider_reset_offline(struct sbus_request *dbus_req, void *data);
static int data_provider_logrotate(struct sbus_request *dbus_req, void *data);

struct mon_cli_iface monitor_be_methods = {
    { &mon_cli_iface_meta, 0 },
    .ping = monitor_common_pong,
    .resInit = data_provider_res_init,
    .shutDown = NULL,
    .goOffline = data_provider_go_offline,
    .resetOffline = data_provider_reset_offline,
    .rotateLogs = data_provider_logrotate,
    .clearMemcache = NULL,
    .clearEnumCache = NULL,
    .sysbusReconnect = NULL,
};

static int client_registration(struct sbus_request *dbus_req, void *data);
static int be_get_account_info(struct sbus_request *dbus_req, void *user_data);
static int be_pam_handler(struct sbus_request *dbus_req, void *user_data);
static int be_sudo_handler(struct sbus_request *dbus_req, void *user_data);
static int be_autofs_handler(struct sbus_request *dbus_req, void *user_data);
static int be_host_handler(struct sbus_request *dbus_req, void *user_data);
static int be_get_subdomains(struct sbus_request *dbus_req, void *user_data);

struct data_provider_iface be_methods = {
    { &data_provider_iface_meta, 0 },
    .RegisterService = client_registration,
    .pamHandler = be_pam_handler,
    .sudoHandler = be_sudo_handler,
    .autofsHandler = be_autofs_handler,
    .hostHandler = be_host_handler,
    .getDomains = be_get_subdomains,
    .getAccountInfo = be_get_account_info,
};

static struct bet_data bet_data[] = {
    {BET_NULL, NULL, NULL},
    {BET_ID, CONFDB_DOMAIN_ID_PROVIDER, "sssm_%s_id_init"},
    {BET_AUTH, CONFDB_DOMAIN_AUTH_PROVIDER, "sssm_%s_auth_init"},
    {BET_ACCESS, CONFDB_DOMAIN_ACCESS_PROVIDER, "sssm_%s_access_init"},
    {BET_CHPASS, CONFDB_DOMAIN_CHPASS_PROVIDER, "sssm_%s_chpass_init"},
    {BET_SUDO, CONFDB_DOMAIN_SUDO_PROVIDER, "sssm_%s_sudo_init"},
    {BET_AUTOFS, CONFDB_DOMAIN_AUTOFS_PROVIDER, "sssm_%s_autofs_init"},
    {BET_SELINUX, CONFDB_DOMAIN_SELINUX_PROVIDER, "sssm_%s_selinux_init"},
    {BET_HOSTID, CONFDB_DOMAIN_HOSTID_PROVIDER, "sssm_%s_hostid_init"},
    {BET_SUBDOMAINS, CONFDB_DOMAIN_SUBDOMAINS_PROVIDER, "sssm_%s_subdomains_init"},
    {BET_MAX, NULL, NULL}
};

struct bet_queue_item {
    struct bet_queue_item *prev;
    struct bet_queue_item *next;

    TALLOC_CTX *mem_ctx;
    struct be_req *be_req;
    be_req_fn_t fn;

};

static const char *dp_err_to_string(int dp_err_type)
{
    switch (dp_err_type) {
    case DP_ERR_OK:
        return "Success";
    case DP_ERR_OFFLINE:
        return "Provider is Offline";
    case DP_ERR_TIMEOUT:
        return "Request timed out";
    case DP_ERR_FATAL:
        return "Internal Error";
    default:
        break;
    }

    return "Unknown Error";
}

static const char *safe_be_req_err_msg(const char *msg_in,
                                       int dp_err_type)
{
    bool ok;

    if (msg_in == NULL) {
        /* No custom error, just use default */
        return dp_err_to_string(dp_err_type);
    }

    ok = sss_utf8_check((const uint8_t *) msg_in,
                        strlen(msg_in));
    if (!ok) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Back end message [%s] contains invalid non-UTF8 character, " \
              "using default\n", msg_in);
        return dp_err_to_string(dp_err_type);
    }

    return msg_in;
}

#define REQ_PHASE_ACCESS 0
#define REQ_PHASE_SELINUX 1

struct be_req {
    struct be_client *becli;
    struct be_ctx *be_ctx;
    struct sss_domain_info *domain;
    void *req_data;

    be_async_callback_t fn;
    void *pvt;

    /* This is utilized in access provider
     * request handling to indicate if access or
     * selinux provider is calling the callback.
     */
    int phase;

    /* Just for nicer debugging */
    const char *req_name;

    struct be_req *prev;
    struct be_req *next;
};

static int be_req_destructor(struct be_req *be_req)
{
    DLIST_REMOVE(be_req->be_ctx->active_requests, be_req);

    return 0;
}

struct be_req *be_req_create(TALLOC_CTX *mem_ctx,
                             struct be_client *becli,
                             struct be_ctx *be_ctx,
                             const char *name,
                             be_async_callback_t fn,
                             void *pvt_fn_data)
{
    struct be_req *be_req;

    be_req = talloc_zero(mem_ctx, struct be_req);
    if (be_req == NULL) return NULL;

    be_req->becli = becli;
    be_req->be_ctx = be_ctx;
    be_req->domain = be_ctx->domain;
    be_req->fn = fn;
    be_req->pvt = pvt_fn_data;
    be_req->req_name = talloc_strdup(be_req, name);
    if (be_req->req_name == NULL) {
        talloc_free(be_req);
        return NULL;
    }

    /* Add this request to active request list and make sure it is
     * removed on termination. */
    DLIST_ADD(be_ctx->active_requests, be_req);
    talloc_set_destructor(be_req, be_req_destructor);

    return be_req;
}

static errno_t be_req_set_domain(struct be_req *be_req, const char *domain)
{
    struct sss_domain_info *dom = NULL;

    dom = find_domain_by_name(be_req->be_ctx->domain, domain, true);
    if (dom == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown domain [%s]!\n", domain);
        return ERR_DOMAIN_NOT_FOUND;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Changing request domain from [%s] to [%s]\n",
                              be_req->domain->name, dom->name);
    be_req->domain = dom;

    return EOK;
}

struct be_ctx *be_req_get_be_ctx(struct be_req *be_req)
{
    return be_req->be_ctx;
}

void *be_req_get_data(struct be_req *be_req)
{
    return be_req->req_data;
}

void be_req_terminate(struct be_req *be_req,
                      int dp_err_type, int errnum, const char *errstr)
{
    if (be_req->fn == NULL) return;
    be_req->fn(be_req, dp_err_type, errnum, errstr);
}

static errno_t be_sbus_reply(struct sbus_request *sbus_req,
                             dbus_uint16_t err_maj,
                             dbus_uint32_t err_min,
                             const char *err_msg)
{
    errno_t ret;
    const char *safe_err_msg;

    /* Only return a reply if one was requested
     * There may not be one if this request began
     * while we were offline
     */
    if (sbus_req == NULL) {
        return EOK;
    }

    safe_err_msg = safe_be_req_err_msg(err_msg, err_maj);

    if (err_maj == DP_ERR_FATAL && err_min == ENODEV) {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Cannot handle request: %s",
              err_msg ? err_msg : "Handler not configured\n");
    } else {
        DEBUG(SSSDBG_TRACE_LIBS,
              "Request processed. Returned [%s]:%d,%d,%s\n",
              dp_err_to_string(err_maj), err_maj, err_min, err_msg);
    }

    ret = sbus_request_return_and_finish(sbus_req,
                                         DBUS_TYPE_UINT16, &err_maj,
                                         DBUS_TYPE_UINT32, &err_min,
                                         DBUS_TYPE_STRING, &safe_err_msg,
                                         DBUS_TYPE_INVALID);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "sbus_request_return_and_finish failed: [%d]: %s\n",
              ret, sss_strerror(ret));
    }

    return ret;
}

static errno_t be_sbus_req_reply(struct sbus_request *sbus_req,
                                 int dp_err_type,
                                 int errnum,
                                 const char *errstr)
{
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;

    err_maj = dp_err_type;
    err_min = errnum;

    return be_sbus_reply(sbus_req, err_maj, err_min, errstr);
}

static void be_req_default_callback(struct be_req *be_req,
                                    int dp_err_type,
                                    int errnum,
                                    const char *errstr)
{
    struct sbus_request *dbus_req;

    DEBUG(SSSDBG_TRACE_FUNC, "Replying to %s request\n", be_req->req_name);

    dbus_req = (struct sbus_request *) be_req->pvt;

    be_sbus_req_reply(dbus_req, dp_err_type, errnum, errstr);
    talloc_free(be_req);
}

/* Send back an immediate reply and set the sbus_request to NULL
 * so that we are sure the request is not reused in the future
 */
static errno_t be_offline_reply(struct sbus_request **sbus_req_ptr)
{
    struct sbus_request *dbus_req;
    errno_t ret;

    if (sbus_req_ptr == NULL) {
        return EINVAL;
    }
    dbus_req = *sbus_req_ptr;

    ret = be_sbus_req_reply(dbus_req, DP_ERR_OFFLINE, EAGAIN,
                            "Fast reply - offline");
    *sbus_req_ptr = NULL;
    return ret;
}

struct be_sbus_reply_data {
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    const char *err_msg;
};

#define BE_SBUS_REPLY_DATA_INIT { .err_maj = DP_ERR_FATAL, \
                                  .err_min = ERR_INTERNAL, \
                                  .err_msg = "Fatal error" \
                                };

static inline void be_sbus_reply_data_set(struct be_sbus_reply_data *rdata,
                                          dbus_uint16_t err_maj,
                                          dbus_uint32_t err_min,
                                          const char *err_msg)
{
    if (rdata == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Bug: Attempt to set NULL be_sbus_reply_data\n");
        return;
    }

    rdata->err_maj = err_maj;
    rdata->err_min = err_min;
    rdata->err_msg = err_msg;
}

static inline errno_t be_sbus_req_reply_data(struct sbus_request *sbus_req,
                                             struct be_sbus_reply_data *data)
{
    return be_sbus_reply(sbus_req, data->err_maj,
                         data->err_min, data->err_msg);
}

void be_terminate_domain_requests(struct be_ctx *be_ctx,
                                  const char *domain)
{
    struct be_req *be_req;
    struct be_req *next_be_req;

    DEBUG(SSSDBG_TRACE_FUNC, "Terminating requests for domain [%s]\n",
                              domain);

    if (domain == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "BUG: domain is NULL\n");
        return;
    }

    be_req = be_ctx->active_requests;
    while (be_req) {
        /* save pointer to next request in case be_req will be freed */
        next_be_req = be_req->next;
        if (strcmp(domain, be_req->domain->name) == 0) {
            be_req_terminate(be_req, DP_ERR_FATAL, ERR_DOMAIN_NOT_FOUND,
                             sss_strerror(ERR_DOMAIN_NOT_FOUND));
        }
        be_req = next_be_req;
    }
}

struct be_async_req {
    be_req_fn_t fn;
    struct be_req *req;
};

static void be_async_req_handler(struct tevent_context *ev,
                                 struct tevent_timer *te,
                                 struct timeval tv, void *pvt)
{
    struct be_async_req *async_req;

    async_req = talloc_get_type(pvt, struct be_async_req);

    async_req->fn(async_req->req);
}

struct be_spy {
    TALLOC_CTX *freectx;
    struct be_spy *double_agent;
};

static int be_spy_destructor(struct be_spy *spy)
{
    /* If there's a double_agent, set its
     * freectx to NULL so that we don't
     * try to loop. When that spy fires,
     * it will just be a no-op.
     */
    spy->double_agent->freectx = NULL;
    talloc_zfree(spy->freectx);
    return 0;
}

static errno_t be_spy_create(TALLOC_CTX *mem_ctx, struct be_req *be_req)
{
    errno_t ret;
    struct be_spy *cli_spy = NULL;
    struct be_spy *req_spy = NULL;

    /* Attach a spy for the be_client so that if it dies,
     * we can free the be_req automatically.
     */
    cli_spy = talloc_zero(be_req->becli, struct be_spy);
    if (!cli_spy) {
        ret = ENOMEM;
        goto done;
    }
    cli_spy->freectx = be_req;

    /* Also create a spy on the be_req so that we
     * can free the other spy when the be_req
     * completes successfully.
     */
    req_spy = talloc_zero(be_req, struct be_spy);
    if (!req_spy) {
        ret = ENOMEM;
        goto done;
    }
    req_spy->freectx = cli_spy;

    /* Create paired spy links to prevent loops */
    cli_spy->double_agent = req_spy;
    req_spy->double_agent = cli_spy;

    /* Now create the destructors that will actually free
     * the opposing spies.
     */
    talloc_set_destructor(cli_spy, be_spy_destructor);
    talloc_set_destructor(req_spy, be_spy_destructor);


    /* Now steal the be_req onto the mem_ctx so that it
     * will be guaranteed that this data will be
     * available for the full duration of execution.
     */
    talloc_steal(mem_ctx, be_req);

    ret = EOK;
done:
    if (ret != EOK) {
        talloc_free(cli_spy);
        talloc_free(req_spy);
    }
    return ret;
}

/* This function alters the memory hierarchy of the be_req
 * to ensure memory safety during shutdown. It creates a
 * spy on the be_cli object so that it will free the be_req
 * if the client is freed.
 *
 * It is generally allocated atop the private data context
 * for the appropriate back-end against which it is being
 * filed.
 */
static errno_t be_file_request(TALLOC_CTX *mem_ctx,
                               struct be_req *be_req,
                               be_req_fn_t fn)
{
    errno_t ret;
    struct be_async_req *areq;
    struct tevent_timer *te;
    struct timeval tv;

    if (!fn || !be_req) return EINVAL;

    ret = be_spy_create(mem_ctx, be_req);
    if (ret != EOK) return ret;

    areq = talloc(be_req, struct be_async_req);
    if (!areq) {
        return ENOMEM;
    }
    areq->fn = fn;
    areq->req = be_req;

    /* fire immediately */
    tv.tv_sec = 0;
    tv.tv_usec = 0;

    te = tevent_add_timer(be_req->be_ctx->ev, be_req,
                          tv, be_async_req_handler, areq);
    if (te == NULL) {
        return EIO;
    }

    return EOK;
}

static errno_t be_queue_request(TALLOC_CTX *queue_mem_ctx,
                                struct bet_queue_item **req_queue,
                                TALLOC_CTX *req_mem_ctx,
                                struct be_req *be_req,
                                be_req_fn_t fn)
{
    struct bet_queue_item *item;
    int ret;

    if (*req_queue == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Queue is empty, " \
                                 "running request immediately.\n");
        ret = be_file_request(req_mem_ctx, be_req, fn);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "be_file_request failed.\n");
            return ret;
        }
    }

    item = talloc_zero(queue_mem_ctx, struct bet_queue_item);
    if (item == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed, cannot add item to " \
                                  "request queue.\n");
    } else {
        DEBUG(SSSDBG_TRACE_ALL, "Adding request to queue.\n");
        item->mem_ctx = req_mem_ctx;
        item->be_req = be_req;
        item->fn = fn;

        DLIST_ADD_END(*req_queue, item, struct bet_queue_item *);
    }

    return EOK;
}

static void be_queue_next_request(struct be_req *be_req, enum bet_type type)
{
    struct bet_queue_item *item;
    struct bet_queue_item *current = NULL;
    struct bet_queue_item **req_queue;
    struct sbus_request *dbus_req;
    int ret;
    struct be_req *next_be_req = NULL;

    req_queue = &be_req->becli->bectx->bet_info[type].req_queue;

    if (*req_queue == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Queue is empty, nothing to do.\n");
        return;
    }

    DLIST_FOR_EACH(item, *req_queue) {
        if (item->be_req == be_req) {
            current = item;
            break;
        }
    }

    if (current != NULL) {
        DLIST_REMOVE(*req_queue, current);
    }

    if (*req_queue == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Request queue is empty.\n");
        return;
    }

    next_be_req = (*req_queue)->be_req;

    ret = be_file_request((*req_queue)->mem_ctx, next_be_req, (*req_queue)->fn);
    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_ALL, "Queued request filed successfully.\n");
        return;
    }

    DEBUG(SSSDBG_OP_FAILURE, "be_file_request failed.\n");

    be_queue_next_request(next_be_req, type);

    dbus_req = (struct sbus_request *) next_be_req->pvt;

    be_sbus_req_reply(dbus_req, DP_ERR_FATAL, ret,
                      "Cannot file back end request");
    talloc_free(next_be_req);
}

bool be_is_offline(struct be_ctx *ctx)
{
    return ctx->offstat.offline;
}

static void check_if_online(struct be_ctx *ctx);

static errno_t
try_to_go_online(TALLOC_CTX *mem_ctx,
                 struct tevent_context *ev,
                 struct be_ctx *be_ctx,
                 struct be_ptask *be_ptask,
                 void *be_ctx_void)
{
    struct be_ctx *ctx = (struct be_ctx*) be_ctx_void;

    check_if_online(ctx);
    return EOK;
}

static int get_offline_timeout(struct be_ctx *ctx)
{
    errno_t ret;
    int offline_timeout;

    ret = confdb_get_int(ctx->cdb, ctx->conf_path,
                         CONFDB_DOMAIN_OFFLINE_TIMEOUT, 60,
                         &offline_timeout);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to get offline_timeout from confdb. "
              "Will use 60 seconds.\n");
        offline_timeout = 60;
    }

    return offline_timeout;
}

void be_mark_offline(struct be_ctx *ctx)
{
    int offline_timeout;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Going offline!\n");

    ctx->offstat.went_offline = time(NULL);
    ctx->offstat.offline = true;
    ctx->run_online_cb = true;

    if (ctx->check_if_online_ptask == NULL) {
        /* This is the first time we go offline - create a periodic task
         * to check if we can switch to online. */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Initialize check_if_online_ptask.\n");

        offline_timeout = get_offline_timeout(ctx);

        ret = be_ptask_create_sync(ctx, ctx,
                                   offline_timeout, offline_timeout,
                                   offline_timeout, 30, offline_timeout,
                                   BE_PTASK_OFFLINE_EXECUTE,
                                   3600 /* max_backoff */,
                                   try_to_go_online,
                                   ctx, "Check if online (periodic)",
                                   &ctx->check_if_online_ptask);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "be_ptask_create_sync failed [%d]: %s\n",
                  ret, sss_strerror(ret));
        }
    } else {
        /* Periodic task was already created. Just enable it. */
        DEBUG(SSSDBG_TRACE_INTERNAL, "Enable check_if_online_ptask.\n");
        be_ptask_enable(ctx->check_if_online_ptask);
    }

    be_run_offline_cb(ctx);
}

static void be_subdom_reset_status(struct tevent_context *ev,
                                  struct tevent_timer *te,
                                  struct timeval current_time,
                                  void *pvt)
{
    struct sss_domain_info *subdom = talloc_get_type(pvt,
                                                     struct sss_domain_info);

    DEBUG(SSSDBG_TRACE_LIBS, "Resetting subdomain %s\n", subdom->name);
    subdom->state = DOM_ACTIVE;
}

static void be_mark_subdom_offline(struct sss_domain_info *subdom,
                                   struct be_ctx *be_ctx)
{
    struct timeval tv;
    struct tevent_timer *timeout = NULL;
    int reset_status_timeout;

    reset_status_timeout = get_offline_timeout(be_ctx);
    tv = tevent_timeval_current_ofs(reset_status_timeout, 0);

    switch (subdom->state) {
    case DOM_DISABLED:
        DEBUG(SSSDBG_MINOR_FAILURE, "Won't touch disabled subdomain\n");
        return;
    case DOM_INACTIVE:
        DEBUG(SSSDBG_TRACE_ALL, "Subdomain already inactive\n");
        return;
    case DOM_ACTIVE:
        DEBUG(SSSDBG_TRACE_LIBS,
              "Marking subdomain %s as inactive\n", subdom->name);
        break;
    }

    timeout = tevent_add_timer(be_ctx->ev, be_ctx, tv,
                               be_subdom_reset_status, subdom);
    if (timeout == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot create timer\n");
        return;
    }

    subdom->state = DOM_INACTIVE;
}

void be_mark_dom_offline(struct sss_domain_info *dom, struct be_ctx *ctx)
{
    if (IS_SUBDOMAIN(dom) == false) {
        DEBUG(SSSDBG_TRACE_LIBS, "Marking back end offline\n");
        be_mark_offline(ctx);
    } else {
        DEBUG(SSSDBG_TRACE_LIBS, "Marking subdomain %s offline\n", dom->name);
        be_mark_subdom_offline(dom, ctx);
    }
}

static void reactivate_subdoms(struct sss_domain_info *head)
{
    struct sss_domain_info *dom;

    DEBUG(SSSDBG_TRACE_LIBS, "Resetting all subdomains\n");

    for (dom = head; dom; dom = get_next_domain(dom, true)) {
        if (sss_domain_get_state(dom) == DOM_INACTIVE) {
            sss_domain_set_state(dom, DOM_ACTIVE);
        }
    }
}

static void be_reset_offline(struct be_ctx *ctx)
{
    ctx->offstat.went_offline = 0;
    ctx->offstat.offline = false;

    reactivate_subdoms(ctx->domain);

    be_ptask_disable(ctx->check_if_online_ptask);
    be_run_online_cb(ctx);
}

static void get_subdomains_callback(struct be_req *req,
                                    int dp_err_type,
                                    int errnum,
                                    const char *errstr)
{
    struct sbus_request *dbus_req;

    be_queue_next_request(req, BET_SUBDOMAINS);

    dbus_req = (struct sbus_request *) req->pvt;

    be_sbus_req_reply(dbus_req, dp_err_type, errnum, errstr);
    talloc_free(req);
}

static int be_get_subdomains(struct sbus_request *dbus_req, void *user_data)
{
    struct be_subdom_req *req;
    struct be_req *be_req = NULL;
    struct be_client *becli;
    char *domain_hint;
    struct be_sbus_reply_data req_reply = BE_SBUS_REPLY_DATA_INIT;
    int ret;

    becli = talloc_get_type(user_data, struct be_client);
    if (!becli) return EINVAL;

    if (!sbus_request_parse_or_finish(dbus_req,
                                      DBUS_TYPE_STRING, &domain_hint,
                                      DBUS_TYPE_INVALID))
        return EOK; /* handled */

    /* return an error if corresponding backend target is not configured */
    if (becli->bectx->bet_info[BET_SUBDOMAINS].bet_ops == NULL) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "Undefined backend target.\n");
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, ENODEV,
                               "Subdomains back end target is not configured");
        goto immediate;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Got get subdomains [%s]\n",
                             domain_hint == NULL ? "no hint": domain_hint );

    /* If we are offline return immediately
     */
    if (becli->bectx->offstat.offline) {
        DEBUG(SSSDBG_TRACE_FUNC, "Cannot proceed, provider is offline.\n");
        be_sbus_reply_data_set(&req_reply, DP_ERR_OFFLINE, EAGAIN,
                               "Provider is offline");
        goto immediate;
    }

    /* process request */

    be_req = be_req_create(becli, becli, becli->bectx, "get subdomains",
                           get_subdomains_callback, dbus_req);
    if (!be_req) {
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, ENOMEM,
                               "Out of memory");
        goto immediate;
    }

    req = talloc(be_req, struct be_subdom_req);
    if (!req) {
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, ENOMEM,
                               "Out of memory");
        goto immediate;
    }
    req->domain_hint = talloc_strdup(req, domain_hint);
    if (!req->domain_hint) {
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, ENOMEM,
                               "Out of memory");
        goto immediate;
    }

    be_req->req_data = req;

    ret = be_queue_request(becli->bectx,
                           &becli->bectx->bet_info[BET_SUBDOMAINS].req_queue,
                           becli->bectx,
                           be_req,
                           becli->bectx->bet_info[BET_SUBDOMAINS].bet_ops->handler);
    if (ret != EOK) {
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, ret,
                               "Cannot file back end request");
        goto immediate;
    }

    return EOK;

immediate:
    talloc_free(be_req);
    be_sbus_req_reply_data(dbus_req, &req_reply);
    return EOK;
}

struct be_initgr_prereq {
    char *user;
    char *domain;
    uint32_t gnum;
    uint32_t *groups;

    void *orig_pvt_data;
    int orig_dp_err_type;
    int orig_errnum;
    const char *orig_errstr;
};

static void acctinfo_callback_initgr_wrap(struct be_req *be_req)
{
    struct be_initgr_prereq *pr = talloc_get_type(be_req->pvt,
                                                  struct be_initgr_prereq);

    be_req->pvt = pr->orig_pvt_data;
    be_req_default_callback(be_req, pr->orig_dp_err_type,
                            pr->orig_errnum, pr->orig_errstr);
}

static void acctinfo_callback_initgr_sbus(DBusPendingCall *pending, void *ptr)
{
    struct be_req *be_req = talloc_get_type(ptr, struct be_req);

    dbus_pending_call_unref(pending);

    acctinfo_callback_initgr_wrap(be_req);
}

static void acctinfo_initgroups_callback(struct be_req *be_req,
                                         int dp_err_type,
                                         int errnum,
                                         const char *errstr)
{
    struct be_initgr_prereq *pr = talloc_get_type(be_req->pvt,
                                                  struct be_initgr_prereq);
    DBusMessage *msg = NULL;
    dbus_bool_t dbret;
    int num;
    int ret;

    pr->orig_dp_err_type = dp_err_type;
    pr->orig_errnum = errnum;
    pr->orig_errstr = errstr;

    if (!be_req->be_ctx->nss_cli || !be_req->be_ctx->nss_cli->conn) {
        DEBUG(SSSDBG_MINOR_FAILURE, "NSS Service not conected\n");
        ret = EACCES;
        goto done;
    }

    /* Set up null request */
    msg = dbus_message_new_method_call(NULL,
                                       DP_PATH,
                                       DATA_PROVIDER_REV_IFACE,
                                       DATA_PROVIDER_REV_IFACE_INITGRCHECK);
    if (!msg) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory?!\n");
        ret = ENOMEM;
        goto done;
    }

    num = pr->gnum;
    dbret = dbus_message_append_args(msg,
                                     DBUS_TYPE_STRING, &pr->user,
                                     DBUS_TYPE_STRING, &pr->domain,
                                     DBUS_TYPE_ARRAY, DBUS_TYPE_UINT32,
                                     &pr->groups, num,
                                     DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory?!\n");
        ret = ENOMEM;
        goto done;
    }

    /* ping the NSS service, no reply expected */
    ret = sbus_conn_send(be_req->be_ctx->nss_cli->conn, msg, -1,
                         acctinfo_callback_initgr_sbus, be_req, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Error contacting NSS responder: %d [%s]\n",
               ret, strerror(ret));
    }

done:
    if (msg) {
        dbus_message_unref(msg);
    }
    if (ret != EOK) {
        /* return immediately if we cannot contact nss provider */
        acctinfo_callback_initgr_wrap(be_req);
    }
}

static errno_t be_initgroups_prereq(struct be_req *be_req)
{
    struct be_acct_req *ar = talloc_get_type(be_req_get_data(be_req),
                                             struct be_acct_req);
    struct be_initgr_prereq *pr;
    struct ldb_result *res;
    errno_t ret;
    const char *tmpstr;
    int i;

    ret = sysdb_initgroups(be_req, be_req->be_ctx->domain, ar->filter_value,
                           &res);
    if (ret && ret != ENOENT) {
        return ret;
    }
    /* if the user is completely missing there is no need to contact NSS,
     * it would be a noop */
    if (ret == ENOENT || res->count == 0) {
        /* yet unknown, ignore */
        return EOK;
    }

    pr = talloc(be_req, struct be_initgr_prereq);
    if (!pr) {
        return ENOMEM;
    }
    pr->groups = talloc_array(pr, gid_t, res->count);
    if (!pr->groups) {
        return ENOMEM;
    }
    tmpstr = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    if (!tmpstr) {
        return EINVAL;
    }
    pr->user = talloc_strdup(pr, tmpstr);
    if (!pr->user) {
        return ENOMEM;
    }
    pr->domain = talloc_strdup(pr, be_req->be_ctx->domain->name);
    if (!pr->domain) {
        return ENOMEM;
    }
    /* The first GID is the primary so it might be duplicated
     * later in the list */
    for (pr->gnum = 0, i = 0; i < res->count; i++) {
        pr->groups[pr->gnum] = ldb_msg_find_attr_as_uint(res->msgs[i],
                                                         SYSDB_GIDNUM, 0);
        /* if 0 it may be a non-posix group, so we skip it */
        if (pr->groups[pr->gnum] != 0) {
            pr->gnum++;
        }
    }

    talloc_zfree(res);

    pr->orig_pvt_data = be_req->pvt;
    be_req->pvt = pr;
    be_req->fn = acctinfo_initgroups_callback;

    return EOK;
}

static errno_t
be_file_account_request(struct be_req *be_req, struct be_acct_req *ar)
{
    errno_t ret;
    struct be_ctx *be_ctx = be_req->be_ctx;

    be_req->req_data = ar;

    /* see if we need a pre request call, only done for initgroups for now */
    if ((ar->entry_type & 0xFF) == BE_REQ_INITGROUPS) {
        ret = be_initgroups_prereq(be_req);
        if (ret) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Prerequest failed\n");
            return ret;
        }
    }

    /* process request */
    ret = be_file_request(be_ctx, be_req,
                          be_ctx->bet_info[BET_ID].bet_ops->handler);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to file request\n");
        return ret;
    }

    return EOK;
}

static errno_t
split_name_extended(TALLOC_CTX *mem_ctx,
                    const char *filter,
                    char **name,
                    char **extended)
{
    char *p;

    *name = talloc_strdup(mem_ctx, filter);
    if (!*name) {
        return ENOENT;
    }

    p = strchr(*name, ':');
    if (p) {
        /* Extended info included */
        *p = '\0';

        *extended = p + 1;
    } else {
        *extended = NULL;
    }

    return EOK;
}

static void
be_get_account_info_done(struct be_req *be_req,
                         int dp_err, int dp_ret,
                         const char *errstr);

struct be_get_account_info_state {
    int err_maj;
    int err_min;
    const char *err_msg;
};

struct tevent_req *
be_get_account_info_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct be_client *becli,
                         struct be_ctx *be_ctx,
                         struct be_acct_req *ar)
{
    struct tevent_req *req;
    struct be_get_account_info_state *state;
    struct be_req *be_req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct be_get_account_info_state);
    if (!req) return NULL;

    be_req = be_req_create(state, becli, be_ctx, "get account info",
                           be_get_account_info_done, req);
    if (!be_req) {
        ret = ENOMEM;
        goto done;
    }

    ret = be_req_set_domain(be_req, ar->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set request domain [%d]: %s\n",
                                    ret, sss_strerror(ret));
        goto done;
    }

    ret = be_file_account_request(be_req, ar);
    if (ret != EOK) {
        goto done;
    }

    return req;

done:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void
be_get_account_info_done(struct be_req *be_req,
                         int dp_err, int dp_ret,
                         const char *errstr)
{
    struct tevent_req *req;
    struct be_get_account_info_state *state;

    req = talloc_get_type(be_req->pvt, struct tevent_req);
    state = tevent_req_data(req, struct be_get_account_info_state);

    state->err_maj = dp_err;
    state->err_min = dp_ret;
    if (errstr) {
        state->err_msg = talloc_strdup(state, errstr);
        if (state->err_msg == NULL) {
            talloc_free(be_req);
            tevent_req_error(req, ENOMEM);
            return;
        }
    }

    talloc_free(be_req);
    tevent_req_done(req);
}

errno_t be_get_account_info_recv(struct tevent_req *req,
                                 TALLOC_CTX *mem_ctx,
                                 int *_err_maj,
                                 int *_err_min,
                                 const char **_err_msg)
{
    struct be_get_account_info_state *state;

    state = tevent_req_data(req, struct be_get_account_info_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_err_maj) {
        *_err_maj = state->err_maj;
    }

    if (_err_min) {
        *_err_min = state->err_min;
    }

    if (_err_msg) {
        *_err_msg = talloc_steal(mem_ctx, state->err_msg);
    }

    return EOK;
}

static int be_get_account_info(struct sbus_request *dbus_req, void *user_data)
{
    struct be_acct_req *req;
    struct be_req *be_req;
    struct be_client *becli;
    uint32_t type;
    char *filter;
    char *domain;
    uint32_t attr_type;
    int ret;
    struct be_sbus_reply_data req_reply = BE_SBUS_REPLY_DATA_INIT;

    be_req = NULL;

    becli = talloc_get_type(user_data, struct be_client);
    if (!becli) return EINVAL;

    if (!sbus_request_parse_or_finish(dbus_req,
                                      DBUS_TYPE_UINT32, &type,
                                      DBUS_TYPE_UINT32, &attr_type,
                                      DBUS_TYPE_STRING, &filter,
                                      DBUS_TYPE_STRING, &domain,
                                      DBUS_TYPE_INVALID))
        return EOK; /* handled */

    DEBUG(SSSDBG_FUNC_DATA,
          "Got request for [%#x][%s][%d][%s]\n", type, be_req2str(type),
          attr_type, filter);

    /* If we are offline and fast reply was requested
     * return offline immediately
     */
    if ((type & BE_REQ_FAST) && becli->bectx->offstat.offline) {
        ret = be_offline_reply(&dbus_req);
        if (ret != EOK) {
            return ret;
        }

        /* This reply will be queued and sent
         * when we reenter the mainloop.
         *
         * Continue processing in case we are
         * going back online.
         */
    }

    be_req = be_req_create(becli, becli, becli->bectx, "get account info",
                           be_req_default_callback, dbus_req);
    if (!be_req) {
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, ENOMEM,
                               "Out of memory");
        goto done;
    }

    ret = be_req_set_domain(be_req, domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set request domain [%d]: %s\n",
                                    ret, sss_strerror(ret));
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL,
                               ret, sss_strerror(ret));
        goto done;
    }

    req = talloc_zero(be_req, struct be_acct_req);
    if (!req) {
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, ENOMEM,
                               "Out of memory");
        goto done;
    }
    req->entry_type = type;
    req->attr_type = (int)attr_type;
    req->domain = talloc_strdup(req, domain);
    if (!req->domain) {
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, ENOMEM,
                               "Out of memory");
        goto done;
    }

    if ((attr_type != BE_ATTR_CORE) &&
        (attr_type != BE_ATTR_MEM) &&
        (attr_type != BE_ATTR_ALL)) {
        /* Unrecognized attr type */
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, EINVAL,
                               "Invalid Attrs Parameter");
        goto done;
    }

    if (filter) {
        ret = EOK;
        if (strncmp(filter, "name=", 5) == 0) {
            req->filter_type = BE_FILTER_NAME;
            ret = split_name_extended(req, &filter[5],
                                      &req->filter_value,
                                      &req->extra_value);
        } else if (strncmp(filter, "idnumber=", 9) == 0) {
            req->filter_type = BE_FILTER_IDNUM;
            ret = split_name_extended(req, &filter[9],
                                      &req->filter_value,
                                      &req->extra_value);
        } else if (strncmp(filter, DP_SEC_ID"=", DP_SEC_ID_LEN + 1) == 0) {
            req->filter_type = BE_FILTER_SECID;
            ret = split_name_extended(req, &filter[DP_SEC_ID_LEN + 1],
                                      &req->filter_value,
                                      &req->extra_value);
        } else if (strncmp(filter, DP_CERT"=", DP_CERT_LEN + 1) == 0) {
            req->filter_type = BE_FILTER_CERT;
            ret = split_name_extended(req, &filter[DP_CERT_LEN + 1],
                                      &req->filter_value,
                                      &req->extra_value);
        } else if (strncmp(filter, DP_WILDCARD"=", DP_WILDCARD_LEN + 1) == 0) {
            req->filter_type = BE_FILTER_WILDCARD;
            ret = split_name_extended(req, &filter[DP_WILDCARD_LEN + 1],
                                      &req->filter_value,
                                      &req->extra_value);
        } else if (strcmp(filter, ENUM_INDICATOR) == 0) {
            req->filter_type = BE_FILTER_ENUM;
            req->filter_value = NULL;
            req->extra_value = NULL;
        } else {
            be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, EINVAL,
                                   "Invalid filter");
            goto done;
        }

        if (ret != EOK) {
            be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, EINVAL,
                                   "Invalid filter");
            goto done;
        }

    } else {
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, EINVAL,
                               "Missing filter parameter");
        goto done;
    }

    ret = be_file_account_request(be_req, req);
    if (ret != EOK) {
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, EINVAL,
                               "Cannot file account request");
        goto done;
    }

    return EOK;

done:
    talloc_free(be_req);
    be_sbus_req_reply_data(dbus_req, &req_reply);
    return EOK;
}

static void be_pam_handler_callback(struct be_req *req,
                                    int dp_err_type,
                                    int errnum,
                                    const char *errstr)
{
    struct be_client *becli = req->becli;
    struct sbus_request *dbus_req;
    struct pam_data *pd;
    DBusMessage *reply;
    dbus_bool_t dbret;
    errno_t ret;

    DEBUG(SSSDBG_CONF_SETTINGS, "Backend returned: (%d, %d, %s) [%s]\n",
              dp_err_type, errnum, errstr?errstr:"<NULL>",
              dp_err_to_string(dp_err_type));

    pd = talloc_get_type(be_req_get_data(req), struct pam_data);

    if (pd->cmd == SSS_PAM_ACCT_MGMT &&
        pd->pam_status == PAM_SUCCESS &&
        req->phase == REQ_PHASE_ACCESS &&
        dp_err_type == DP_ERR_OK) {
        if (!becli->bectx->bet_info[BET_SELINUX].bet_ops) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "SELinux provider doesn't exist, "
                   "not sending the request to it.\n");
        } else {
            req->phase = REQ_PHASE_SELINUX;

            /* Now is the time to call SELinux provider */
            ret = be_file_request(becli->bectx->bet_info[BET_SELINUX].pvt_bet_data,
                                  req,
                                  becli->bectx->bet_info[BET_SELINUX].bet_ops->handler);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "be_file_request failed.\n");
                goto done;
            }
            return;
        }
    }

    DEBUG(SSSDBG_CONF_SETTINGS,
          "Sending result [%d][%s]\n", pd->pam_status, pd->domain);
    dbus_req = (struct sbus_request *)req->pvt;
    reply = dbus_message_new_method_return(dbus_req->message);
    if (reply == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "dbus_message_new_method_return failed, cannot send reply.\n");
        goto done;
    }

    dbret = dp_pack_pam_response(reply, pd);
    if (!dbret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to generate dbus reply\n");
        dbus_message_unref(reply);
        goto done;
    }

    sbus_request_finish(dbus_req, reply);
    dbus_message_unref(reply);

    DEBUG(SSSDBG_CONF_SETTINGS,
          "Sent result [%d][%s]\n", pd->pam_status, pd->domain);

done:
    talloc_free(req);
}

static int be_pam_handler(struct sbus_request *dbus_req, void *user_data)
{
    DBusError dbus_error;
    DBusMessage *reply;
    struct be_client *becli;
    dbus_bool_t ret;
    struct pam_data *pd = NULL;
    struct be_req *be_req = NULL;
    enum bet_type target = BET_NULL;

    becli = talloc_get_type(user_data, struct be_client);
    if (!becli) return EINVAL;

    be_req = be_req_create(becli, becli, becli->bectx, "PAM",
                           be_pam_handler_callback, dbus_req);
    if (!be_req) {
        DEBUG(SSSDBG_TRACE_LIBS, "talloc_zero failed.\n");
        return ENOMEM;
    }

    dbus_error_init(&dbus_error);

    ret = dp_unpack_pam_request(dbus_req->message, be_req, &pd, &dbus_error);
    if (!ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to parse message!\n");
        talloc_free(be_req);
        return EIO;
    }

    pd->pam_status = PAM_SYSTEM_ERR;
    if (pd->domain == NULL) {
        pd->domain = talloc_strdup(pd, becli->bectx->domain->name);
        if (pd->domain == NULL) {
            talloc_free(be_req);
            return ENOMEM;
        }
    }

    ret = be_req_set_domain(be_req, pd->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to set request domain [%d]: %s\n",
                                    ret, sss_strerror(ret));
        pd->pam_status = PAM_SYSTEM_ERR;
        goto done;
    }

    DEBUG(SSSDBG_CONF_SETTINGS, "Got request with the following data\n");
    DEBUG_PAM_DATA(SSSDBG_CONF_SETTINGS, pd);

    switch (pd->cmd) {
        case SSS_PAM_AUTHENTICATE:
        case SSS_PAM_PREAUTH:
            target = BET_AUTH;
            break;
        case SSS_PAM_ACCT_MGMT:
            target = BET_ACCESS;
            be_req->phase = REQ_PHASE_ACCESS;
            break;
        case SSS_PAM_CHAUTHTOK:
        case SSS_PAM_CHAUTHTOK_PRELIM:
            target = BET_CHPASS;
            break;
        case SSS_PAM_OPEN_SESSION:
        case SSS_PAM_SETCRED:
        case SSS_PAM_CLOSE_SESSION:
            pd->pam_status = PAM_SUCCESS;
            goto done;
            break;
        default:
            DEBUG(SSSDBG_TRACE_LIBS,
                  "Unsupported PAM command [%d].\n", pd->cmd);
            pd->pam_status = PAM_MODULE_UNKNOWN;
            goto done;
    }

    /* return PAM_MODULE_UNKNOWN if corresponding backend target is not
     * configured
     */
    if (!becli->bectx->bet_info[target].bet_ops) {
        DEBUG(SSSDBG_TRACE_LIBS, "Undefined backend target.\n");
        pd->pam_status = PAM_MODULE_UNKNOWN;
        goto done;
    }

    be_req->req_data = pd;

    ret = be_file_request(becli->bectx->bet_info[target].pvt_bet_data,
                          be_req,
                          becli->bectx->bet_info[target].bet_ops->handler);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_LIBS, "be_file_request failed.\n");
        goto done;
    }

    return EOK;

done:

    DEBUG(SSSDBG_CONF_SETTINGS, "Sending result [%d][%s]\n",
              pd->pam_status, pd->domain);

    reply = dbus_message_new_method_return(dbus_req->message);
    if (reply == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "dbus_message_new_method_return failed, cannot send reply.\n");
        return ENOMEM;
    }

    ret = dp_pack_pam_response(reply, pd);
    if (!ret) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to generate dbus reply\n");
        talloc_free(be_req);
        dbus_message_unref(reply);
        return EIO;
    }

    /* send reply back immediately */
    sbus_request_finish(dbus_req, reply);
    dbus_message_unref(reply);

    talloc_free(be_req);

    return EOK;
}

static int be_sudo_handler(struct sbus_request *dbus_req, void *user_data)
{
    DBusError dbus_error;
    DBusMessageIter iter;
    DBusMessageIter array_iter;
    struct be_client *be_cli = NULL;
    struct be_req *be_req = NULL;
    struct be_sudo_req *sudo_req = NULL;
    int ret = 0;
    uint32_t type;
    uint32_t rules_num = 0;
    const char *rule = NULL;
    const char *err_msg = NULL;
    int i;

    DEBUG(SSSDBG_TRACE_FUNC, "Entering be_sudo_handler()\n");

    be_cli = talloc_get_type(user_data, struct be_client);
    if (be_cli == NULL) {
        return EINVAL;
    }

    /* create be request */
    be_req = be_req_create(be_cli, be_cli, be_cli->bectx, "sudo",
                           be_req_default_callback, dbus_req);
    if (be_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }

    dbus_error_init(&dbus_error);
    dbus_message_iter_init(dbus_req->message, &iter);

    /* get type of the request */
    if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed, to parse the message!\n");
        ret = EIO;
        err_msg = "Invalid D-Bus message format";
        goto fail;
    }
    dbus_message_iter_get_basic(&iter, &type);
    dbus_message_iter_next(&iter); /* step behind the request type */

    /* If we are offline and fast reply was requested
     * return offline immediately
     */
    if ((type & BE_REQ_FAST) && be_cli->bectx->offstat.offline) {
        be_offline_reply(&dbus_req);
        be_req->pvt = NULL;
        /* This reply will be queued and sent
         * when we reenter the mainloop.
         *
         * Continue processing in case we are
         * going back online.
         */
    }

    /* get and set sudo request data */
    sudo_req = talloc_zero(be_req, struct be_sudo_req);
    if (sudo_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        goto fail;
    }

    sudo_req->type = (~BE_REQ_FAST) & type;

    /* get additional arguments according to the request type */
    switch (sudo_req->type) {
    case BE_REQ_SUDO_FULL:
        /* no arguments required */
        break;
    case BE_REQ_SUDO_RULES:
        /* additional arguments:
         * rules_num
         * rules[rules_num]
         */
        /* read rules_num */
        if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_UINT32) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed, to parse the message!\n");
            ret = EIO;
            err_msg = "Invalid D-Bus message format";
            goto fail;
        }

        dbus_message_iter_get_basic(&iter, &rules_num);

        sudo_req->rules = talloc_array(sudo_req, char*, rules_num + 1);
        if (sudo_req->rules == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_array failed.\n");
            ret = ENOMEM;
            goto fail;
        }

        dbus_message_iter_next(&iter);

        if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Failed, to parse the message!\n");
            ret = EIO;
            err_msg = "Invalid D-Bus message format";
            goto fail;
        }

        dbus_message_iter_recurse(&iter, &array_iter);

        /* read the rules */
        for (i = 0; i < rules_num; i++) {
            if (dbus_message_iter_get_arg_type(&array_iter)
                    != DBUS_TYPE_STRING) {
                DEBUG(SSSDBG_CRIT_FAILURE, "Failed, to parse the message!\n");
                ret = EIO;
                err_msg = "Invalid D-Bus message format";
                goto fail;
            }

            dbus_message_iter_get_basic(&array_iter, &rule);
            sudo_req->rules[i] = talloc_strdup(sudo_req->rules, rule);
            if (sudo_req->rules[i] == NULL) {
                DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
                ret = ENOMEM;
                goto fail;
            }

            dbus_message_iter_next(&array_iter);
        }

        sudo_req->rules[rules_num] = NULL;

        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request type %d\n", sudo_req->type);
        ret = EINVAL;
        err_msg = "Invalid DP request type";
        goto fail;
    }

    be_req->req_data = sudo_req;

    /* return an error if corresponding backend target is not configured */
    if (!be_cli->bectx->bet_info[BET_SUDO].bet_ops) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Undefined backend target.\n");
        ret = ENODEV;
        goto fail;
    }

    ret = be_file_request(be_cli->bectx->bet_info[BET_SUDO].pvt_bet_data,
                          be_req,
                          be_cli->bectx->bet_info[BET_SUDO].bet_ops->handler);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "be_file_request failed.\n");
        err_msg = "Cannot file back end request";
        goto fail;
    }

    return EOK;

fail:
    /* send reply back immediately */
    be_req_default_callback(be_req, DP_ERR_FATAL, ret,
                            err_msg ? err_msg : strerror(ret));
    return EOK;
}

static int be_autofs_handler(struct sbus_request *dbus_req, void *user_data)
{
    struct be_client *be_cli = NULL;
    struct be_req *be_req = NULL;
    struct be_autofs_req *be_autofs_req = NULL;
    int ret = 0;
    uint32_t type;
    char *filter;
    char *filter_val;
    struct be_sbus_reply_data req_reply = BE_SBUS_REPLY_DATA_INIT;

    DEBUG(SSSDBG_TRACE_FUNC, "Entering be_autofs_handler()\n");

    be_cli = talloc_get_type(user_data, struct be_client);
    if (be_cli == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot get back end client context\n");
        return EINVAL;
    }

    if (!sbus_request_parse_or_finish(dbus_req,
                                      DBUS_TYPE_UINT32, &type,
                                      DBUS_TYPE_STRING, &filter,
                                      DBUS_TYPE_INVALID))
        return EOK; /* handled */

    /* If we are offline and fast reply was requested
     * return offline immediately
     */
    if ((type & BE_REQ_FAST) && be_cli->bectx->offstat.offline) {
        be_offline_reply(&dbus_req);
        /* This reply will be queued and sent
         * when we reenter the mainloop.
         *
         * Continue processing in case we are
         * going back online.
         */
    }

    if (filter) {
        if (strncmp(filter, "mapname=", 8) == 0) {
            filter_val = &filter[8];
        } else {
            be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, EINVAL,
                                   "Invalid filter");
            goto done;
        }
    } else {
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, EINVAL,
                               "Missing filter parameter");
        goto done;
    }

    /* create be request */
    be_req = be_req_create(be_cli, be_cli, be_cli->bectx, "autofs",
                           be_req_default_callback, dbus_req);
    if (be_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, ENOMEM,
                               "Out of memory");
        goto done;
    }

    /* set autofs request data */
    be_autofs_req = talloc_zero(be_req, struct be_autofs_req);
    if (be_autofs_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, ENOMEM,
                               "Out of memory");
        goto done;
    }

    be_autofs_req->mapname = talloc_strdup(be_autofs_req, filter_val);
    if (be_autofs_req->mapname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, ENOMEM,
                               "Out of memory");
        goto done;
    }

    be_req->req_data = be_autofs_req;

    if (!be_cli->bectx->bet_info[BET_AUTOFS].bet_ops) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Undefined backend target.\n");
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, ENODEV,
                               "Autofs back end target is not configured");
        goto done;
    }

    ret = be_file_request(be_cli->bectx->bet_info[BET_AUTOFS].pvt_bet_data,
                          be_req,
                          be_cli->bectx->bet_info[BET_AUTOFS].bet_ops->handler);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "be_file_request failed.\n");
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, ret,
                               "Cannot file back end request");
        goto done;
    }

    return EOK;

done:
    talloc_free(be_req);
    be_sbus_req_reply_data(dbus_req, &req_reply);
    return EOK;
}

static int be_host_handler(struct sbus_request *dbus_req, void *user_data)
{
    struct be_host_req *req;
    struct be_req *be_req;
    struct be_client *becli;
    uint32_t flags;
    char *filter;
    int ret;
    struct be_sbus_reply_data req_reply = BE_SBUS_REPLY_DATA_INIT;

    be_req = NULL;

    becli = talloc_get_type(user_data, struct be_client);
    if (!becli) return EINVAL;

    if (!sbus_request_parse_or_finish(dbus_req,
                                      DBUS_TYPE_UINT32, &flags,
                                      DBUS_TYPE_STRING, &filter,
                                      DBUS_TYPE_INVALID))
        return EOK; /* request finished */

    DEBUG(SSSDBG_TRACE_LIBS,
          "Got request for [%u][%s]\n", flags, filter);

    /* If we are offline and fast reply was requested
     * return offline immediately
     */
    if ((flags & BE_REQ_FAST) && becli->bectx->offstat.offline) {
        /* Send back an immediate reply */
        be_offline_reply(&dbus_req);

        /* This reply will be queued and sent
         * when we reenter the mainloop.
         *
         * Continue processing in case we are
         * going back online.
         */
    }

    be_req = be_req_create(becli, becli, becli->bectx, "hostinfo",
                           be_req_default_callback, dbus_req);
    if (!be_req) {
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, ENOMEM,
                               "Out of memory");
        goto done;
    }

    req = talloc(be_req, struct be_host_req);
    if (!req) {
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, ENOMEM,
                               "Out of memory");
        goto done;
    }
    req->type = BE_REQ_HOST | (flags & BE_REQ_FAST);

    be_req->req_data = req;

    if (filter) {
        ret = strncmp(filter, "name=", 5);
        if (ret == 0) {
            req->filter_type = BE_FILTER_NAME;
            ret = split_name_extended(req, &filter[5],
                                      &req->name,
                                      &req->alias);
        }

        if (ret) {
            be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, EINVAL,
                                   "Invalid filter");
            goto done;
        }
    } else {
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, EINVAL,
                               "Missing filter parameter");
        goto done;
    }

    /* process request */

    if (!becli->bectx->bet_info[BET_HOSTID].bet_ops) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Undefined backend target.\n");
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, ENODEV,
                               "HostID back end target is not configured");
        goto done;
    }

    ret = be_file_request(becli->bectx->bet_info[BET_HOSTID].pvt_bet_data,
                          be_req,
                          becli->bectx->bet_info[BET_HOSTID].bet_ops->handler);
    if (ret != EOK) {
        be_sbus_reply_data_set(&req_reply, DP_ERR_FATAL, ret,
                               "Cannot file back end request");
        goto done;
    }

    return EOK;

done:
    talloc_free(be_req);
    be_sbus_req_reply_data(dbus_req, &req_reply);
    return EOK;
}

static int be_client_destructor(void *ctx)
{
    struct be_client *becli = talloc_get_type(ctx, struct be_client);
    if (becli->bectx) {
        if (becli->bectx->nss_cli == becli) {
            DEBUG(SSSDBG_TRACE_FUNC, "Removed NSS client\n");
            becli->bectx->nss_cli = NULL;
        } else if (becli->bectx->pam_cli == becli) {
            DEBUG(SSSDBG_TRACE_FUNC, "Removed PAM client\n");
            becli->bectx->pam_cli = NULL;
        } else if (becli->bectx->sudo_cli == becli) {
            DEBUG(SSSDBG_TRACE_FUNC, "Removed SUDO client\n");
            becli->bectx->sudo_cli = NULL;
        } else if (becli->bectx->autofs_cli == becli) {
            DEBUG(SSSDBG_TRACE_FUNC, "Removed autofs client\n");
            becli->bectx->autofs_cli = NULL;
        } else if (becli->bectx->ssh_cli == becli) {
            DEBUG(SSSDBG_TRACE_FUNC, "Removed SSH client\n");
            becli->bectx->ssh_cli = NULL;
        } else if (becli->bectx->pac_cli == becli) {
            DEBUG(SSSDBG_TRACE_FUNC, "Removed PAC client\n");
            becli->bectx->pac_cli = NULL;
        } else if (becli->bectx->ifp_cli == becli) {
            DEBUG(SSSDBG_TRACE_FUNC, "Removed IFP client\n");
            becli->bectx->ifp_cli = NULL;
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unknown client removed ...\n");
        }
    }
    return 0;
}

static int client_registration(struct sbus_request *dbus_req, void *data)
{
    dbus_uint16_t version = DATA_PROVIDER_VERSION;
    struct sbus_connection *conn;
    struct be_client *becli;
    DBusError dbus_error;
    dbus_uint16_t cli_ver;
    char *cli_name;
    dbus_bool_t dbret;
    int ret;

    conn = dbus_req->conn;
    becli = talloc_get_type(data, struct be_client);
    if (!becli) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Connection holds no valid init data\n");
        return EINVAL;
    }

    /* First thing, cancel the timeout */
    DEBUG(SSSDBG_CONF_SETTINGS, "Cancel DP ID timeout [%p]\n", becli->timeout);
    talloc_zfree(becli->timeout);

    dbus_error_init(&dbus_error);

    dbret = dbus_message_get_args(dbus_req->message, &dbus_error,
                                  DBUS_TYPE_UINT16, &cli_ver,
                                  DBUS_TYPE_STRING, &cli_name,
                                  DBUS_TYPE_INVALID);
    if (!dbret) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to parse message, killing connection\n");
        if (dbus_error_is_set(&dbus_error)) dbus_error_free(&dbus_error);
        sbus_disconnect(conn);
        /* FIXME: should we just talloc_zfree(conn) ? */
        return EIO;
    }

    if (strcasecmp(cli_name, "NSS") == 0) {
        becli->bectx->nss_cli = becli;
    } else if (strcasecmp(cli_name, "PAM") == 0) {
        becli->bectx->pam_cli = becli;
    } else if (strcasecmp(cli_name, "SUDO") == 0) {
        becli->bectx->sudo_cli = becli;
    } else if (strcasecmp(cli_name, "autofs") == 0) {
        becli->bectx->autofs_cli = becli;
    } else if (strcasecmp(cli_name, "SSH") == 0) {
        becli->bectx->ssh_cli = becli;
    } else if (strcasecmp(cli_name, "PAC") == 0) {
        becli->bectx->pac_cli = becli;
    } else if (strcasecmp(cli_name, "InfoPipe") == 0) {
        becli->bectx->ifp_cli = becli;
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown client! [%s]\n", cli_name);
    }
    talloc_set_destructor((TALLOC_CTX *)becli, be_client_destructor);

    DEBUG(SSSDBG_CONF_SETTINGS, "Added Frontend client [%s]\n", cli_name);

    /* reply that all is ok */
    ret = sbus_request_return_and_finish(dbus_req,
                                         DBUS_TYPE_UINT16, &version,
                                         DBUS_TYPE_INVALID);
    if (ret != EOK) {
        sbus_disconnect(conn);
        return ret;
    }

    becli->initialized = true;
    return EOK;
}

static errno_t be_file_check_online_request(struct be_req *req)
{
    int ret;

    req->be_ctx->offstat.went_offline = time(NULL);
    reset_fo(req->be_ctx);

    ret = be_file_request(req->be_ctx, req,
                          req->be_ctx->bet_info[BET_ID].bet_ops->check_online);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "be_file_request failed.\n");
    }

    return ret;
}

static void check_online_callback(struct be_req *req, int dp_err_type,
                                  int errnum, const char *errstr)
{
    int ret;

    DEBUG(SSSDBG_CONF_SETTINGS, "Backend returned: (%d, %d, %s) [%s]\n",
              dp_err_type, errnum, errstr?errstr:"<NULL>",
              dp_err_to_string(dp_err_type));

    req->be_ctx->check_online_ref_count--;

    if (dp_err_type != DP_ERR_OK && req->be_ctx->check_online_ref_count > 0) {
        ret = be_file_check_online_request(req);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "be_file_check_online_request failed.\n");
            goto done;
        }
        return;
    }

done:
    req->be_ctx->check_online_ref_count = 0;
    if (dp_err_type != DP_ERR_OFFLINE) {
        if (dp_err_type != DP_ERR_OK) {
            reset_fo(req->be_ctx);
        }
        be_reset_offline(req->be_ctx);
    }

    talloc_free(req);

    return;
}

static void check_if_online(struct be_ctx *ctx)
{
    int ret;
    struct be_req *be_req = NULL;

    be_run_unconditional_online_cb(ctx);

    if (ctx->offstat.offline == false) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "Backend is already online, nothing to do.\n");
        return;
    }

    /* Make sure nobody tries to go online while we are checking */
    ctx->offstat.went_offline = time(NULL);

    DEBUG(SSSDBG_TRACE_INTERNAL, "Trying to go back online!\n");

    ctx->check_online_ref_count++;

    if (ctx->check_online_ref_count != 1) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "There is an online check already running.\n");
        return;
    }

    if (ctx->bet_info[BET_ID].bet_ops->check_online == NULL) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "ID providers does not provide a check_online method.\n");
        goto failed;
    }

    be_req = be_req_create(ctx, NULL, ctx, "online check",
                           check_online_callback, NULL);
    if (be_req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed.\n");
        goto failed;
    }

    ret = be_file_check_online_request(be_req);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "be_file_check_online_request failed.\n");
        goto failed;
    }

    return;

failed:
    ctx->check_online_ref_count--;
    DEBUG(SSSDBG_CRIT_FAILURE, "Failed to run a check_online test.\n");

    talloc_free(be_req);

    if (ctx->check_online_ref_count == 0) {
        reset_fo(ctx);
        be_reset_offline(ctx);
    }

    return;
}

static void init_timeout(struct tevent_context *ev,
                         struct tevent_timer *te,
                         struct timeval t, void *ptr)
{
    struct be_client *becli;

    DEBUG(SSSDBG_OP_FAILURE,
          "Client timed out before Identification [%p]!\n", te);

    becli = talloc_get_type(ptr, struct be_client);

    sbus_disconnect(becli->conn);
    talloc_zfree(becli);
}

static int be_client_init(struct sbus_connection *conn, void *data)
{
    struct be_ctx *bectx;
    struct be_client *becli;
    struct timeval tv;

    bectx = talloc_get_type(data, struct be_ctx);

    /* hang off this memory to the connection so that when the connection
     * is freed we can potentially call a destructor */

    becli = talloc(conn, struct be_client);
    if (!becli) {
        DEBUG(SSSDBG_FATAL_FAILURE,"Out of memory?!\n");
        talloc_zfree(conn);
        return ENOMEM;
    }
    becli->bectx = bectx;
    becli->conn = conn;
    becli->initialized = false;

    /* Allow access from the SSSD user */
    sbus_allow_uid(conn, &bectx->uid);

    /* 5 seconds should be plenty */
    tv = tevent_timeval_current_ofs(5, 0);

    becli->timeout = tevent_add_timer(bectx->ev, becli,
                                      tv, init_timeout, becli);
    if (!becli->timeout) {
        DEBUG(SSSDBG_FATAL_FAILURE,"Out of memory?!\n");
        talloc_zfree(conn);
        return ENOMEM;
    }
    DEBUG(SSSDBG_CONF_SETTINGS,
          "Set-up Backend ID timeout [%p]\n", becli->timeout);

    return sbus_conn_register_iface(conn, &be_methods.vtable, DP_PATH, becli);
}

/* be_srv_init
 * set up per-domain sbus channel */
static int be_srv_init(struct be_ctx *ctx,
                       uid_t uid, gid_t gid)
{
    char *sbus_address;
    int ret;

    /* Set up SBUS connection to the monitor */
    ret = dp_get_sbus_address(ctx, &sbus_address, ctx->domain->name);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not get sbus backend address.\n");
        return ret;
    }

    ctx->uid = uid;
    ctx->gid = gid;

    ret = sbus_new_server(ctx, ctx->ev, sbus_address, uid, gid,
                          true, &ctx->sbus_srv, be_client_init, ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not set up sbus server.\n");
        return ret;
    }

    return EOK;
}

static void be_target_access_permit(struct be_req *be_req)
{
    struct pam_data *pd =
                    talloc_get_type(be_req_get_data(be_req), struct pam_data);
    DEBUG(SSSDBG_TRACE_ALL,
          "be_target_access_permit called, returning PAM_SUCCESS.\n");

    pd->pam_status = PAM_SUCCESS;
    be_req_terminate(be_req, DP_ERR_OK, PAM_SUCCESS, NULL);
}

static struct bet_ops be_target_access_permit_ops = {
    .check_online = NULL,
    .handler = be_target_access_permit,
    .finalize = NULL
};

static void be_target_access_deny(struct be_req *be_req)
{
    struct pam_data *pd =
                    talloc_get_type(be_req_get_data(be_req), struct pam_data);
    DEBUG(SSSDBG_TRACE_ALL,
          "be_target_access_deny called, returning PAM_PERM_DENIED.\n");

    pd->pam_status = PAM_PERM_DENIED;
    be_req_terminate(be_req, DP_ERR_OK, PAM_PERM_DENIED, NULL);
}

static struct bet_ops be_target_access_deny_ops = {
    .check_online = NULL,
    .handler = be_target_access_deny,
    .finalize = NULL
};

static int load_backend_module(struct be_ctx *ctx,
                               enum bet_type bet_type,
                               struct bet_info *bet_info,
                               const char *default_mod_name)
{
    TALLOC_CTX *tmp_ctx;
    int ret = EINVAL;
    bool already_loaded = false;
    int lb=0;
    char *mod_name = NULL;
    char *path = NULL;
    void *handle;
    char *mod_init_fn_name = NULL;
    bet_init_fn_t mod_init_fn = NULL;

    (*bet_info).bet_type = bet_type;
    (*bet_info).mod_name = NULL;
    (*bet_info).bet_ops = NULL;
    (*bet_info).pvt_bet_data = NULL;

    if (bet_type <= BET_NULL || bet_type >= BET_MAX ||
        bet_type != bet_data[bet_type].bet_type) {
        DEBUG(SSSDBG_OP_FAILURE, "invalid bet_type or bet_data corrupted.\n");
        return EINVAL;
    }

    tmp_ctx = talloc_new(ctx);
    if (!tmp_ctx) {
        DEBUG(SSSDBG_TRACE_LIBS, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = confdb_get_string(ctx->cdb, tmp_ctx, ctx->conf_path,
                            bet_data[bet_type].option_name, NULL,
                            &mod_name);
    if (ret != EOK) {
        ret = EFAULT;
        goto done;
    }
    if (!mod_name) {
        if (default_mod_name != NULL) {
            DEBUG(SSSDBG_FUNC_DATA,
                  "no module name found in confdb, using [%s].\n",
                      default_mod_name);
            mod_name = talloc_strdup(ctx, default_mod_name);
        } else {
            ret = ENOENT;
            goto done;
        }
    }

    if (strcasecmp(mod_name, NO_PROVIDER) == 0) {
        ret = ENOENT;
        goto done;
    }

    if (bet_type == BET_ACCESS) {
        if (strcmp(mod_name, ACCESS_PERMIT) == 0) {
            (*bet_info).bet_ops = &be_target_access_permit_ops;
            (*bet_info).pvt_bet_data = NULL;
            (*bet_info).mod_name = talloc_strdup(ctx, ACCESS_PERMIT);

            ret = EOK;
            goto done;
        }
        if (strcmp(mod_name, ACCESS_DENY) == 0) {
            (*bet_info).bet_ops = &be_target_access_deny_ops;
            (*bet_info).pvt_bet_data = NULL;
            (*bet_info).mod_name = talloc_strdup(ctx, ACCESS_DENY);

            ret = EOK;
            goto done;
        }
    }

    mod_init_fn_name = talloc_asprintf(tmp_ctx,
                                       bet_data[bet_type].mod_init_fn_name_fmt,
                                       mod_name);
    if (mod_init_fn_name == NULL) {
        DEBUG(SSSDBG_TRACE_LIBS, "talloc_asprintf failed\n");
        ret = ENOMEM;
        goto done;
    }


    lb = 0;
    while(ctx->loaded_be[lb].be_name != NULL) {
        if (strncmp(ctx->loaded_be[lb].be_name, mod_name,
                    strlen(mod_name)) == 0) {
            DEBUG(SSSDBG_TRACE_LIBS,
                  "Backend [%s] already loaded.\n", mod_name);
            already_loaded = true;
            break;
        }

        ++lb;
        if (lb >= BET_MAX) {
            DEBUG(SSSDBG_OP_FAILURE, "Backend context corrupted.\n");
            ret = EINVAL;
            goto done;
        }
    }

    if (!already_loaded) {
        path = talloc_asprintf(tmp_ctx, "%s/libsss_%s.so",
                               DATA_PROVIDER_PLUGINS_PATH, mod_name);
        if (!path) {
            ret = ENOMEM;
            goto done;
        }

        DEBUG(SSSDBG_TRACE_LIBS,
              "Loading backend [%s] with path [%s].\n", mod_name, path);
        handle = dlopen(path, RTLD_NOW);
        if (!handle) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Unable to load %s module with path (%s), error: %s\n",
                      mod_name, path, dlerror());
            ret = ELIBACC;
            goto done;
        }

        ctx->loaded_be[lb].be_name = talloc_strdup(ctx, mod_name);
        ctx->loaded_be[lb].handle = handle;
    }

    mod_init_fn = (bet_init_fn_t)dlsym(ctx->loaded_be[lb].handle,
                                           mod_init_fn_name);
    if (mod_init_fn == NULL) {
        if (default_mod_name != NULL &&
            strcmp(default_mod_name, mod_name) == 0 ) {
            /* If the default is used and fails we indicate this to the caller
             * by returning ENOENT. Ths way the caller can decide how to
             * handle the different types of error conditions. */
            ret = ENOENT;
        } else {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Unable to load init fn %s from module %s, error: %s\n",
                      mod_init_fn_name, mod_name, dlerror());
            ret = ELIBBAD;
        }
        goto done;
    }

    ret = mod_init_fn(ctx, &(*bet_info).bet_ops, &(*bet_info).pvt_bet_data);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Error (%d) in module (%s) initialization (%s)!\n",
                  ret, mod_name, mod_init_fn_name);
        goto done;
    }

    (*bet_info).mod_name = talloc_strdup(ctx, mod_name);

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

static void signal_be_offline(struct tevent_context *ev,
                              struct tevent_signal *se,
                              int signum,
                              int count,
                              void *siginfo,
                              void *private_data)
{
    struct be_ctx *ctx = talloc_get_type(private_data, struct be_ctx);
    be_mark_offline(ctx);
}

static void signal_be_reset_offline(struct tevent_context *ev,
                                    struct tevent_signal *se,
                                    int signum,
                                    int count,
                                    void *siginfo,
                                    void *private_data)
{
    struct be_ctx *ctx = talloc_get_type(private_data, struct be_ctx);
    check_if_online(ctx);
}

int be_process_init_sudo(struct be_ctx *be_ctx)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char **services = NULL;
    char *provider = NULL;
    bool responder_enabled = false;
    int i;
    int ret;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    ret = confdb_get_string_as_list(be_ctx->cdb, tmp_ctx,
                                    CONFDB_MONITOR_CONF_ENTRY,
                                    CONFDB_MONITOR_ACTIVE_SERVICES, &services);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to read from confdb [%d]: %s\n",
                                     ret, strerror(ret));
        goto done;
    }

    for (i = 0; services[i] != NULL; i++) {
        if (strcmp(services[i], "sudo") == 0) {
            responder_enabled = true;
            break;
        }
    }

    ret = confdb_get_string(be_ctx->cdb, tmp_ctx, be_ctx->conf_path,
                            CONFDB_DOMAIN_SUDO_PROVIDER, NULL, &provider);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to read from confdb [%d]: %s\n",
                                     ret, strerror(ret));
        goto done;
    }

    if (!responder_enabled && provider == NULL) {
        /* provider is not set explicitly */
        DEBUG(SSSDBG_TRACE_FUNC,
              "SUDO is not listed in services, disabling SUDO module.\n");
        ret = ENOENT;
        goto done;
    }

    if (!responder_enabled && provider != NULL
            && strcmp(provider, NO_PROVIDER) != 0) {
        /* provider is set but responder is disabled */
        DEBUG(SSSDBG_MINOR_FAILURE, "SUDO provider is set, but it is not "
              "listed in active services. SUDO support will not work!\n");
    }

    ret = load_backend_module(be_ctx, BET_SUDO, &be_ctx->bet_info[BET_SUDO],
                              be_ctx->bet_info[BET_ID].mod_name);

done:
    talloc_free(tmp_ctx);
    return ret;
}

int be_process_init(TALLOC_CTX *mem_ctx,
                    const char *be_domain,
                    uid_t uid, gid_t gid,
                    struct tevent_context *ev,
                    struct confdb_ctx *cdb)
{
    struct be_ctx *ctx;
    struct tevent_signal *tes;
    int ret;

    ctx = talloc_zero(mem_ctx, struct be_ctx);
    if (!ctx) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing be_ctx\n");
        return ENOMEM;
    }
    ctx->ev = ev;
    ctx->cdb = cdb;
    ctx->identity = talloc_asprintf(ctx, "%%BE_%s", be_domain);
    ctx->conf_path = talloc_asprintf(ctx, CONFDB_DOMAIN_PATH_TMPL, be_domain);
    if (!ctx->identity || !ctx->conf_path) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Out of memory!?\n");
        ret = ENOMEM;
        goto fail;
    }

    ret = be_init_failover(ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "fatal error initializing failover context\n");
        goto fail;
    }

    ret = sssd_domain_init(ctx, cdb, be_domain, DB_PATH, &ctx->domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error opening cache database\n");
        goto fail;
    }

    ret = sss_monitor_init(ctx, ctx->ev, &monitor_be_methods,
                           ctx->identity, DATA_PROVIDER_VERSION,
                           ctx, &ctx->mon_conn);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "fatal error setting up monitor bus\n");
        goto fail;
    }

    /* We need this for subdomains support, as they have to store fully
     * qualified user and group names for now */
    ret = sss_names_init(ctx->domain, cdb,
                         ctx->domain->name, &ctx->domain->names);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "fatal error setting fully qualified name format for %s\n",
              ctx->domain->name);
        goto fail;
    }

    ret = be_srv_init(ctx, uid, gid);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "fatal error setting up server bus\n");
        goto fail;
    }

    /* Initialize be_refresh periodic task. */
    ctx->refresh_ctx = be_refresh_ctx_init(ctx);
    if (ctx->refresh_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to initialize refresh_ctx\n");
        ret = ENOMEM;
        goto fail;
    }

    if (ctx->domain->refresh_expired_interval > 0) {
        ret = be_ptask_create(ctx, ctx, ctx->domain->refresh_expired_interval,
                              30, 5, 0, ctx->domain->refresh_expired_interval,
                              BE_PTASK_OFFLINE_SKIP, 0,
                              be_refresh_send, be_refresh_recv,
                              ctx->refresh_ctx, "Refresh Records", NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "Unable to initialize refresh periodic task\n");
            goto fail;
        }
    }

    ret = load_backend_module(ctx, BET_ID,
                              &ctx->bet_info[BET_ID], NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "fatal error initializing data providers\n");
        goto fail;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL,
          "ID backend target successfully loaded from provider [%s].\n",
          ctx->bet_info[BET_ID].mod_name);

    ret = load_backend_module(ctx, BET_AUTH,
                              &ctx->bet_info[BET_AUTH],
                              ctx->bet_info[BET_ID].mod_name);
    if (ret != EOK) {
        if (ret != ENOENT) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "fatal error initializing data providers\n");
            goto fail;
        }
        DEBUG(SSSDBG_MINOR_FAILURE,
              "No authentication module provided for [%s] !!\n",
              be_domain);
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "AUTH backend target successfully loaded "
               "from provider [%s].\n", ctx->bet_info[BET_AUTH].mod_name);
    }

    ret = load_backend_module(ctx, BET_ACCESS, &ctx->bet_info[BET_ACCESS],
                              ACCESS_PERMIT);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE,
              "Failed to setup ACCESS backend.\n");
        goto fail;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL,
          "ACCESS backend target successfully loaded "
           "from provider [%s].\n", ctx->bet_info[BET_ACCESS].mod_name);

    ret = load_backend_module(ctx, BET_CHPASS,
                              &ctx->bet_info[BET_CHPASS],
                              ctx->bet_info[BET_AUTH].mod_name);
    if (ret != EOK) {
        if (ret != ENOENT) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "fatal error initializing data providers\n");
            goto fail;
        }
        DEBUG(SSSDBG_MINOR_FAILURE,
              "No change password module provided for [%s] !!\n",
               be_domain);
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "CHPASS backend target successfully loaded "
               "from provider [%s].\n", ctx->bet_info[BET_CHPASS].mod_name);
    }

    ret = be_process_init_sudo(ctx);
    if (ret != EOK) {
        if (ret != ENOENT) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "fatal error initializing data providers\n");
            goto fail;
        }
        DEBUG(SSSDBG_MINOR_FAILURE,
              "No SUDO module provided for [%s] !!\n", be_domain);
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "SUDO backend target successfully loaded "
               "from provider [%s].\n", ctx->bet_info[BET_SUDO].mod_name);
    }

    ret = load_backend_module(ctx, BET_AUTOFS,
                              &ctx->bet_info[BET_AUTOFS],
                              ctx->bet_info[BET_ID].mod_name);
    if (ret != EOK) {
        if (ret != ENOENT) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "fatal error initializing data providers\n");
            goto fail;
        }
        DEBUG(SSSDBG_MINOR_FAILURE,
              "No autofs module provided for [%s] !!\n", be_domain);
    } else {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "autofs backend target successfully loaded "
               "from provider [%s].\n", ctx->bet_info[BET_AUTOFS].mod_name);
    }

    ret = load_backend_module(ctx, BET_SELINUX,
                              &ctx->bet_info[BET_SELINUX],
                              ctx->bet_info[BET_ID].mod_name);
    if (ret != EOK) {
        if (ret != ENOENT) {
            DEBUG(SSSDBG_FATAL_FAILURE, "fatal error initializing data providers\n");
            goto fail;
        }
        DEBUG(SSSDBG_CRIT_FAILURE, "No selinux module provided for [%s] !!\n",
                  be_domain);
    } else {
        DEBUG(SSSDBG_TRACE_ALL, "selinux backend target successfully loaded "
                  "from provider [%s].\n", ctx->bet_info[BET_SELINUX].mod_name);
    }

    ret = load_backend_module(ctx, BET_HOSTID,
                              &ctx->bet_info[BET_HOSTID],
                              ctx->bet_info[BET_ID].mod_name);
    if (ret != EOK) {
        if (ret != ENOENT) {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  "fatal error initializing data providers\n");
            goto fail;
        }
        DEBUG(SSSDBG_CRIT_FAILURE,
              "No host info module provided for [%s] !!\n", be_domain);
    } else {
        DEBUG(SSSDBG_TRACE_ALL,
              "HOST backend target successfully loaded from provider [%s].\n",
               ctx->bet_info[BET_HOSTID].mod_name);
    }

    ret = load_backend_module(ctx, BET_SUBDOMAINS,
                              &ctx->bet_info[BET_SUBDOMAINS],
                              ctx->bet_info[BET_ID].mod_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Subdomains are not supported for [%s] !!\n", be_domain);
    } else {
        DEBUG(SSSDBG_TRACE_ALL, "Get-Subdomains backend target successfully loaded "
                  "from provider [%s].\n",
                  ctx->bet_info[BET_SUBDOMAINS].mod_name);
    }

    /* Handle SIGUSR1 to force offline behavior */
    BlockSignals(false, SIGUSR1);
    tes = tevent_add_signal(ctx->ev, ctx, SIGUSR1, 0,
                            signal_be_offline, ctx);
    if (tes == NULL) {
        ret = EIO;
        goto fail;
    }

    /* Handle SIGUSR2 to force going online */
    BlockSignals(false, SIGUSR2);
    tes = tevent_add_signal(ctx->ev, ctx, SIGUSR2, 0,
                            signal_be_reset_offline, ctx);
    if (tes == NULL) {
        ret = EIO;
        goto fail;
    }

    return EOK;

fail:
    talloc_free(ctx);
    return ret;
}

#ifndef UNIT_TESTING
int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    char *be_domain = NULL;
    char *srv_name = NULL;
    struct main_context *main_ctx;
    char *confdb_path;
    int ret;
    uid_t uid;
    gid_t gid;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        SSSD_SERVER_OPTS(uid, gid)
        {"domain", 0, POPT_ARG_STRING, &be_domain, 0,
         _("Domain of the information provider (mandatory)"), NULL },
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while((opt = poptGetNextOpt(pc)) != -1) {
        switch(opt) {
        default:
        fprintf(stderr, "\nInvalid option %s: %s\n\n",
                  poptBadOption(pc, 0), poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }

    if (be_domain == NULL) {
        fprintf(stderr, "\nMissing option, --domain is a mandatory option.\n\n");
            poptPrintUsage(pc, stderr, 0);
            return 1;
    }

    poptFreeContext(pc);

    DEBUG_INIT(debug_level);

    /* set up things like debug , signals, daemonization, etc... */
    debug_log_file = talloc_asprintf(NULL, "sssd_%s", be_domain);
    if (!debug_log_file) return 2;

    srv_name = talloc_asprintf(NULL, "sssd[be[%s]]", be_domain);
    if (!srv_name) return 2;

    confdb_path = talloc_asprintf(NULL, CONFDB_DOMAIN_PATH_TMPL, be_domain);
    if (!confdb_path) return 2;

    ret = server_setup(srv_name, 0, 0, 0, confdb_path, &main_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not set up mainloop [%d]\n", ret);
        return 2;
    }

    ret = setenv(SSS_DOM_ENV, be_domain, 1);
    if (ret != 0) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Setting "SSS_DOM_ENV" failed, journald "
              "logging mightnot work as expected\n");
    }

    ret = die_if_parent_died();
    if (ret != EOK) {
        /* This is not fatal, don't return */
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not set up to exit when parent process does\n");
    }

    ret = be_process_init(main_ctx,
                          be_domain, uid, gid,
                          main_ctx->event_ctx,
                          main_ctx->confdb_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not initialize backend [%d]\n", ret);
        return 3;
    }

    ret = chown_debug_file(NULL, uid, gid);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot chown the debug files, debugging might not work!\n");
    }

    ret = become_user(uid, gid);
    if (ret != EOK) {
        DEBUG(SSSDBG_FUNC_DATA,
              "Cannot become user [%"SPRIuid"][%"SPRIgid"].\n", uid, gid);
        return ret;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Backend provider (%s) started!\n", be_domain);

    /* loop on main */
    server_loop(main_ctx);

    return 0;
}
#endif

static int data_provider_res_init(struct sbus_request *dbus_req, void *data)
{
    struct be_ctx *be_ctx;
    be_ctx = talloc_get_type(data, struct be_ctx);

    resolv_reread_configuration(be_ctx->be_res->resolv);
    check_if_online(be_ctx);

    return monitor_common_res_init(dbus_req, data);
}

static int data_provider_go_offline(struct sbus_request *dbus_req, void *data)
{
    struct be_ctx *be_ctx;
    be_ctx = talloc_get_type(data, struct be_ctx);
    be_mark_offline(be_ctx);
    return sbus_request_return_and_finish(dbus_req, DBUS_TYPE_INVALID);
}

static int data_provider_reset_offline(struct sbus_request *dbus_req, void *data)
{
    struct be_ctx *be_ctx;
    be_ctx = talloc_get_type(data, struct be_ctx);
    check_if_online(be_ctx);
    return sbus_request_return_and_finish(dbus_req, DBUS_TYPE_INVALID);
}

static int data_provider_logrotate(struct sbus_request *dbus_req, void *data)
{
    errno_t ret;
    struct be_ctx *be_ctx = talloc_get_type(data, struct be_ctx);

    ret = server_common_rotate_logs(be_ctx->cdb, be_ctx->conf_path);
    if (ret != EOK) return ret;

    return sbus_request_return_and_finish(dbus_req, DBUS_TYPE_INVALID);
}
