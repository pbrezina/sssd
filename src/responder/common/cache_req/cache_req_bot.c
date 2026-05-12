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

#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <talloc.h>

#include "util/util.h"
#include "responder/common/cache_req/cache_req_bot.h"

struct cache_req_bot_account *
cache_req_bot_account_parse(TALLOC_CTX *mem_ctx, const char *input_name)
{
    struct cache_req_bot_account *bot;
    const char *uid_start;
    const char *last_dash;
    const char *at;
    char *uid_str;
    char *endptr;
    unsigned long uid_val;
    size_t uid_len;

    if (input_name == NULL
            || strncmp(input_name, CACHE_REQ_BOT_PREFIX,
                       strlen(CACHE_REQ_BOT_PREFIX)) != 0) {
        return NULL;
    }

    /* Skip the "BOT-" prefix. */
    uid_start = input_name + strlen(CACHE_REQ_BOT_PREFIX);
    if (*uid_start == '\0') {
        DEBUG(SSSDBG_MINOR_FAILURE, "BOT account name has empty payload\n");
        return NULL;
    }

    /* Strip @REALM suffix if present. Find the boundary of the
     * BOT-<uid>-<random> part (before any @REALM). */
    at = strchr(uid_start, '@');

    /* Find the last '-' before @REALM (or end of string).
     * This separates the uidNumber from the random suffix:
     *   BOT-<uidNumber>-<random>[@REALM]
     */
    if (at != NULL) {
        /* Search within uid_start..at for the last '-' */
        last_dash = NULL;
        for (const char *p = uid_start; p < at; p++) {
            if (*p == '-') {
                last_dash = p;
            }
        }
    } else {
        last_dash = strrchr(uid_start, '-');
    }

    if (last_dash == NULL || last_dash == uid_start) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "BOT account name has invalid format (no random suffix): %s\n",
              input_name);
        return NULL;
    }

    /* Verify the random suffix is not empty. */
    if (at != NULL) {
        if (last_dash + 1 >= at) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "BOT account name has empty random suffix: %s\n",
                  input_name);
            return NULL;
        }
    } else {
        if (*(last_dash + 1) == '\0') {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "BOT account name has empty random suffix: %s\n",
                  input_name);
            return NULL;
        }
    }

    /* Extract uidNumber string (between "BOT-" and last "-"). */
    uid_len = last_dash - uid_start;
    if (uid_len == 0) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "BOT account name has empty uidNumber: %s\n", input_name);
        return NULL;
    }

    uid_str = strndup(uid_start, uid_len);
    if (uid_str == NULL) {
        return NULL;
    }

    /* Parse uidNumber. */
    errno = 0;
    uid_val = strtoul(uid_str, &endptr, 10);
    if (errno != 0 || *endptr != '\0' || uid_val == 0
            || uid_val > UINT32_MAX) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "BOT account name has invalid uidNumber [%s]: %s\n",
              uid_str, input_name);
        free(uid_str);
        return NULL;
    }
    free(uid_str);

    bot = talloc_zero(mem_ctx, struct cache_req_bot_account);
    if (bot == NULL) {
        return NULL;
    }

    bot->bot_name = talloc_strdup(bot, input_name);
    if (bot->bot_name == NULL) {
        talloc_free(bot);
        return NULL;
    }

    bot->uid = (uint32_t)uid_val;

    DEBUG(SSSDBG_TRACE_FUNC,
          "BOT account [%s] resolved to uid [%"PRIu32"]\n",
          input_name, bot->uid);

    return bot;
}

struct cache_req_bot_account *
cache_req_bot_account_copy(TALLOC_CTX *mem_ctx,
                           struct cache_req_bot_account *bot)
{
    struct cache_req_bot_account *copy;

    if (bot == NULL) {
        return NULL;
    }

    copy = talloc_zero(mem_ctx, struct cache_req_bot_account);
    if (copy == NULL) {
        return NULL;
    }

    copy->bot_name = talloc_strdup(copy, bot->bot_name);
    if (copy->bot_name == NULL) {
        talloc_free(copy);
        return NULL;
    }

    copy->uid = bot->uid;

    return copy;
}
