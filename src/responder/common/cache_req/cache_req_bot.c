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
#include <jansson.h>
#include <talloc.h>

#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "responder/common/cache_req/cache_req_bot.h"

struct cache_req_bot_account *
cache_req_bot_account_parse(TALLOC_CTX *mem_ctx, const char *input_name)
{
    TALLOC_CTX *tmp_ctx;
    struct cache_req_bot_account *bot;
    unsigned char *decoded;
    size_t decoded_len;
    json_t *root = NULL;
    json_t *name_obj;
    json_error_t json_err;
    const char *b64;
    const char *at;
    const char *real_name;
    errno_t ret;

    if (input_name == NULL
            || strncmp(input_name, CACHE_REQ_BOT_PREFIX,
                       strlen(CACHE_REQ_BOT_PREFIX)) != 0) {
        return NULL;
    }

    /* Skip the "BOT-" prefix. */
    b64 = input_name + strlen(CACHE_REQ_BOT_PREFIX);
    if (*b64 == '\0') {
        DEBUG(SSSDBG_MINOR_FAILURE, "BOT account name has empty payload\n");
        return NULL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return NULL;
    }

    /* Strip @REALM suffix if present, it is not part of the payload. */
    at = strchr(b64, '@');
    if (at != NULL) {
        b64 = talloc_strndup(tmp_ctx, b64, at - b64);
        if (b64 == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    decoded = sss_base64_decode(tmp_ctx, b64, &decoded_len);
    if (decoded == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to base64-decode BOT account payload\n");
        ret = EINVAL;
        goto done;
    }

    root = json_loadb((const char *)decoded, decoded_len, 0, &json_err);
    if (root == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Failed to parse BOT account JSON: %s\n", json_err.text);
        ret = EINVAL;
        goto done;
    }

    name_obj = json_object_get(root, "n");
    if (name_obj == NULL || !json_is_string(name_obj)) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "BOT account JSON missing \"n\" string field\n");
        ret = EINVAL;
        goto done;
    }

    real_name = json_string_value(name_obj);

    bot = talloc_zero(tmp_ctx, struct cache_req_bot_account);
    if (bot == NULL) {
        ret = ENOMEM;
        goto done;
    }

    bot->bot_name = talloc_strdup(bot, input_name);
    if (bot->bot_name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (at != NULL) {
        bot->original_name = talloc_asprintf(bot, "%s%s", real_name, at);
    } else {
        bot->original_name = talloc_strdup(bot, real_name);
    }
    if (bot->original_name == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Extract optional fields. */
    name_obj = json_object_get(root, "r");
    if (name_obj != NULL && json_is_string(name_obj)) {
        bot->request_id = talloc_strdup(bot, json_string_value(name_obj));
        if (bot->request_id == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    name_obj = json_object_get(root, "a");
    if (name_obj != NULL && json_is_string(name_obj)) {
        bot->agent = talloc_strdup(bot, json_string_value(name_obj));
        if (bot->agent == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    name_obj = json_object_get(root, "m");
    if (name_obj != NULL && json_is_string(name_obj)) {
        bot->model = talloc_strdup(bot, json_string_value(name_obj));
        if (bot->model == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    name_obj = json_object_get(root, "t");
    if (name_obj != NULL && json_is_string(name_obj)) {
        bot->tool = talloc_strdup(bot, json_string_value(name_obj));
        if (bot->tool == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "BOT account [%s] resolved to user [%s]\n",
          input_name, bot->original_name);

    bot = talloc_steal(mem_ctx, bot);
    ret = EOK;

done:
    if (root != NULL) {
        json_decref(root);
    }

    talloc_free(tmp_ctx);

    if (ret != EOK) {
        return NULL;
    }

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

    copy->original_name = talloc_strdup(copy, bot->original_name);
    if (copy->original_name == NULL) {
        talloc_free(copy);
        return NULL;
    }

    if (bot->request_id != NULL) {
        copy->request_id = talloc_strdup(copy, bot->request_id);
        if (copy->request_id == NULL) {
            talloc_free(copy);
            return NULL;
        }
    }

    if (bot->agent != NULL) {
        copy->agent = talloc_strdup(copy, bot->agent);
        if (copy->agent == NULL) {
            talloc_free(copy);
            return NULL;
        }
    }

    if (bot->model != NULL) {
        copy->model = talloc_strdup(copy, bot->model);
        if (copy->model == NULL) {
            talloc_free(copy);
            return NULL;
        }
    }

    if (bot->tool != NULL) {
        copy->tool = talloc_strdup(copy, bot->tool);
        if (copy->tool == NULL) {
            talloc_free(copy);
            return NULL;
        }
    }

    return copy;
}
