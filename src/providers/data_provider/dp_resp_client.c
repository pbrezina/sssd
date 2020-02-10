/*
   SSSD

   Data Provider Responder client - DP calls responder interface

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

#include "config.h"
#include <talloc.h>
#include <tevent.h>

#include "confdb/confdb.h"
#include "providers/data_provider.h"
#include "providers/data_provider/dp_private.h"
#include "sss_iface/sss_iface_async.h"

void dp_sbus_domain_active(struct data_provider *provider,
                           struct sss_domain_info *dom)
{
    sbus_emit_resp_domain_StateChanged(provider->be_ctx->mon_conn,
                                       "/", dom->name, DOM_ACTIVE);
}

void dp_sbus_domain_inconsistent(struct data_provider *provider,
                                 struct sss_domain_info *dom)
{
    sbus_emit_resp_domain_StateChanged(provider->be_ctx->mon_conn,
                                       "/", dom->name, DOM_ACTIVE);
}

void dp_sbus_reset_users_ncache(struct data_provider *provider,
                                struct sss_domain_info *dom)
{
    sbus_emit_resp_negcache_ResetUsers(provider->be_ctx->mon_conn, "/");
}

void dp_sbus_reset_groups_ncache(struct data_provider *provider,
                                 struct sss_domain_info *dom)
{
    sbus_emit_resp_negcache_ResetGroups(provider->be_ctx->mon_conn, "/");
}

void dp_sbus_reset_users_memcache(struct data_provider *provider)
{
    sbus_emit_nss_memcache_InvalidateAllUsers(provider->be_ctx->mon_conn, "/");
}

void dp_sbus_reset_groups_memcache(struct data_provider *provider)
{
    sbus_emit_nss_memcache_InvalidateAllGroups(provider->be_ctx->mon_conn, "/");
}

void dp_sbus_reset_initgr_memcache(struct data_provider *provider)
{
    sbus_emit_nss_memcache_InvalidateAllInitgroups(provider->be_ctx->mon_conn, "/");

    return;
}

void dp_sbus_invalidate_group_memcache(struct data_provider *provider,
                                       gid_t gid)
{
    struct tevent_req *subreq;

    if (provider == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No provider pointer\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Ordering NSS responder to invalidate the group %"PRIu32" \n",
          gid);

    subreq = sbus_call_nss_memcache_InvalidateGroupById_send(provider,
                 provider->sbus_conn, SSS_BUS_NSS, SSS_BUS_PATH,
                 (uint32_t)gid);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        return;
    }

    tevent_req_set_callback(subreq, sbus_unwanted_reply, NULL);

    return;
}
