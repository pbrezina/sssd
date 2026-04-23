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

#ifndef _CACHE_REQ_BOT_H_
#define _CACHE_REQ_BOT_H_

#include <talloc.h>

#define CACHE_REQ_BOT_PREFIX "BOT-"
#define CACHE_REQ_BOT_SHELL "/usr/bin/sss-confined-shell"

struct cache_req_bot_account {
    const char *original_name;  /* real user extracted from JSON "n" field */
};

/**
 * Parse a bot account name.
 *
 * If @input_name starts with "BOT-", the remainder is base64-decoded
 * and parsed as JSON. The "n" field is extracted as the real user name.
 *
 * @return Allocated structure on success, NULL if not a bot account
 *         or on parse error.
 */
struct cache_req_bot_account *
cache_req_bot_account_parse(TALLOC_CTX *mem_ctx, const char *input_name);

/**
 * Deep copy a bot account structure to a new talloc context.
 *
 * @return Allocated copy on success, NULL on error.
 */
struct cache_req_bot_account *
cache_req_bot_account_copy(TALLOC_CTX *mem_ctx,
                           struct cache_req_bot_account *bot);

#endif /* _CACHE_REQ_BOT_H_ */
