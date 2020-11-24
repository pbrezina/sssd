/*
    SSSD

    KCM Renewal, private header file

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

#ifndef __KCM_RENEW_H__
#define __KCM_RENEW_H__

#include "providers/krb5/krb5_common.h"
#include "src/providers/krb5/krb5_ccache.h"

errno_t kcm_renewal_init(struct resp_ctx *rctx, struct krb5_ctx *kctx, struct tevent_context *ev,
                         struct kcm_ccdb *db, time_t renew_intv);
errno_t kcm_add_tgt_to_renew_table(struct krb5_ctx *kctx, const char *ccname,
                                   struct tgt_times *tgtt, const char *upn);

#endif /* __KCM_RENEW_H__ */
