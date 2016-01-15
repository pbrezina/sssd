/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

#include <talloc.h>

#include "config.h"
#include "providers/data_provider/dp.h"
#include "providers/data_provider/dp_private.h"
#include "providers/backend.h"
#include "util/util.h"

bool dp_check_target_module(struct data_provider *provider,
                            enum dp_targets target,
                            const char *module_name)
{
    struct dp_target *dp_target;

    if (provider == NULL || provider->targets == NULL) {
        return false;
    }

    if (target >= DP_TARGET_SENTINEL) {
        return false;
    }

    dp_target = provider->targets[target];
    if (dp_target == NULL || dp_target->module_name == NULL) {
        return false;
    }

    return strcmp(dp_target->module_name, module_name) == 0;
}

bool dp_module_auth_enabled(struct data_provider *provider,
                            const char *module_name)
{
    if (dp_check_target_module(provider, DPT_AUTH, module_name)) {
        return true;
    }

    if (dp_check_target_module(provider, DPT_CHPASS, module_name)) {
        return true;
    }

    return false;
}

void _dp_set_method(struct dp_method *methods,
                    enum dp_methods method,
                    dp_req_send_fn send_fn,
                    dp_req_recv_fn recv_fn,
                    void *method_data,
                    const char *method_dtype,
                    const char *request_dtype,
                    const char *output_dtype,
                    uint32_t output_size)
{
    if (method >= DP_METHOD_SENTINEL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: invalid method %d\n", method);
        return;
    }

    methods[method].send_fn = send_fn;
    methods[method].recv_fn = recv_fn;
    methods[method].method_data = method_data;

    methods[method].method_dtype = method_dtype;
    methods[method].request_dtype = request_dtype;
    methods[method].output_dtype = output_dtype;
    methods[method].output_size = output_size;
}

struct dp_method *dp_find_method(struct data_provider *provider,
                                 enum dp_targets target,
                                 enum dp_methods method)
{
    struct dp_target *dp_target;
    struct dp_method *execute;

    if (target >= DP_TARGET_SENTINEL || method >= DP_METHOD_SENTINEL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Bug: Invalid target or method ID\n");
        return NULL;
    }

    dp_target = provider->targets[target];

    if (dp_target == NULL || dp_target->initialized == false) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Target %s is not configured\n",
              dp_target_to_string(target));
        return NULL;
    }

    execute = &provider->targets[target]->methods[method];
    if (execute->send_fn == NULL || execute->recv_fn == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Bug: Invalid combination of target and method\n");
        return NULL;
    }

    return execute;
}

static errno_t dp_init_dbus_server(struct data_provider *provider)
{
    const char *domain;
    char *sbus_address;
    errno_t ret;

    domain = provider->be_ctx->domain->name;
    ret = dp_get_sbus_address(NULL, &sbus_address, domain);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not get sbus backend address.\n");
        return ret;
    }

    ret = sbus_new_server(provider, provider->ev, sbus_address,
                          provider->uid, provider->gid, true,
                          &provider->srv_conn,
                          dp_client_init, provider);
    talloc_free(sbus_address);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Could not set up sbus server.\n");
        return ret;
    }

    return EOK;
}

static int dp_destructor(struct data_provider *provider)
{
    enum dp_clients client;

    provider->terminating = true;

    dp_terminate_active_requests(provider);

    for (client = 0; client != DP_CLIENT_SENTINEL; client++) {
        talloc_zfree(provider->clients[client]);
    }

    return 0;
}

errno_t dp_init(struct tevent_context *ev,
                struct be_ctx *be_ctx,
                uid_t uid,
                gid_t gid)
{
    struct data_provider *provider;

    errno_t ret;

    provider = talloc_zero(be_ctx, struct data_provider);
    if (provider == NULL) {
        return ENOMEM;
    }

    provider->ev = ev;
    provider->uid = uid;
    provider->gid = gid;
    provider->be_ctx = be_ctx;

    ret = dp_req_table_init(provider, &provider->requests.reply_table);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize request table "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = dp_init_modules(provider, &provider->modules);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize DP modules "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    ret = dp_init_targets(provider, be_ctx, provider, provider->modules,
                          &provider->targets);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to initialize DP targets "
              "[%d]: %s\n", ret, sss_strerror(ret));
        goto done;
    }

    talloc_set_destructor(provider, dp_destructor);

    ret = dp_init_dbus_server(provider);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to setup service bus [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    be_ctx->provider = provider;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(provider);
    }

    return ret;
}
