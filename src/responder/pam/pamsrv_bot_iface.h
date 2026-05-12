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

#ifndef _PAMSRV_BOT_IFACE_H_
#define _PAMSRV_BOT_IFACE_H_

#include "sbus/sbus.h"

struct pam_ctx;

struct pam_bot_indicators {
    const char *agent;
    const char *model;
    const char *tool;
    const char *request_id;
};

errno_t pam_register_bot_iface(struct sbus_connection *conn,
                               struct pam_ctx *pctx);

struct pam_bot_indicators *
pam_bot_indicators_lookup(struct pam_ctx *pctx, const char *bot_name);

void pam_bot_indicators_delete(struct pam_ctx *pctx, const char *bot_name);

#endif /* _PAMSRV_BOT_IFACE_H_ */
