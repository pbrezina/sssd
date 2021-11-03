/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2021 Red Hat

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

#ifndef _SSS_CHAIN_ID_TEVENT_
#define _SSS_CHAIN_ID_TEVENT_

#include <tevent.h>

/* Setup chain id tracking on tevent context. */
void sss_chain_id_setup(struct tevent_context *ev,
                        const char *fmt);

#endif /* _SSS_CHAIN_ID_TEVENT_ */
