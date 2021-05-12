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

#include <tevent.h>
#include <stdint.h>

#include "util/debug.h"

extern uint64_t debug_chain_id;

struct sss_chain_id_stack {
    uint32_t head;
    uint32_t values[100];
} chain_stack;

static void sss_chain_id_push(uint32_t id)
{
    chain_stack.head++;
    chain_stack.values[chain_stack.head] = id;
}

static uint32_t sss_chain_id_pop(void)
{
    uint32_t id = chain_stack.values[chain_stack.head];
    chain_stack.head--;

    return id;
}

static void sss_chain_id_trace_fd(struct tevent_fd *fde,
                                   enum tevent_event_trace_point point,
                                   void *private_data)
{
    switch (point) {
    case TEVENT_EVENT_TRACE_CREATED:
        /* Assign the current chain id when the event is created. */
        DEBUG(SSSDBG_IMPORTANT_INFO, "FDE %p CREATED %lu\n", fde, debug_chain_id);
        tevent_fd_set_tag(fde, debug_chain_id);
        break;
    case TEVENT_EVENT_TRACE_BEFORE_HANDLER:
        /* Set the chain id when a handler is being called. */
        DEBUG(SSSDBG_IMPORTANT_INFO, "FDE %p PUSH %lu\n", fde, debug_chain_id);
        sss_chain_id_push(debug_chain_id);
        debug_chain_id = tevent_fd_get_tag(fde);
        DEBUG(SSSDBG_IMPORTANT_INFO, "FDE %p SET %lu\n", fde, debug_chain_id);
        break;
    case TEVENT_EVENT_TRACE_AFTER_HANDLER:
        /* Restore original chain id. */
        debug_chain_id = sss_chain_id_pop();
        DEBUG(SSSDBG_IMPORTANT_INFO, "FDE %p RESTORE %lu\n", fde, debug_chain_id);
    default:
        /* Do nothing. */
        break;
    }
}

static void sss_chain_id_trace_signal(struct tevent_signal *se,
                                  enum tevent_event_trace_point point,
                                  void *private_data)
{
    switch (point) {
    case TEVENT_EVENT_TRACE_CREATED:
        /* Assign the current chain id when the event is created. */
        DEBUG(SSSDBG_IMPORTANT_INFO, "SIGNAL %p CREATED %lu\n", se, debug_chain_id);
        tevent_signal_set_tag(se, debug_chain_id);
        break;
    case TEVENT_EVENT_TRACE_BEFORE_HANDLER:
        /* Set the chain id when a handler is being called. */
        DEBUG(SSSDBG_IMPORTANT_INFO, "SIGNAL %p PUSH %lu\n", se, debug_chain_id);
        sss_chain_id_push(debug_chain_id);
        debug_chain_id = tevent_signal_get_tag(se);
        DEBUG(SSSDBG_IMPORTANT_INFO, "SIGNAL %p SET %lu\n", se, debug_chain_id);
        break;
    case TEVENT_EVENT_TRACE_AFTER_HANDLER:
        /* Restore original chain id. */
        debug_chain_id = sss_chain_id_pop();
        DEBUG(SSSDBG_IMPORTANT_INFO, "SIGNAL %p RESTORE %lu\n", se, debug_chain_id);
    default:
        /* Do nothing. */
        break;
    }
}

static void sss_chain_id_trace_timer(struct tevent_timer *timer,
                                     enum tevent_event_trace_point point,
                                     void *private_data)
{
    switch (point) {
    case TEVENT_EVENT_TRACE_CREATED:
        /* Assign the current chain id when the event is created. */
        DEBUG(SSSDBG_IMPORTANT_INFO, "TIMER %p CREATED %lu\n", timer, debug_chain_id);
        tevent_timer_set_tag(timer, debug_chain_id);
        break;
    case TEVENT_EVENT_TRACE_BEFORE_HANDLER:
        /* Set the chain id when a handler is being called. */
        DEBUG(SSSDBG_IMPORTANT_INFO, "TIMER %p PUSH %lu\n", timer, debug_chain_id);
        sss_chain_id_push(debug_chain_id);
        debug_chain_id = tevent_timer_get_tag(timer);
        DEBUG(SSSDBG_IMPORTANT_INFO, "TIMER %p SET %lu\n", timer, debug_chain_id);
        break;
    case TEVENT_EVENT_TRACE_AFTER_HANDLER:
        /* Restore original chain id. */
        debug_chain_id = sss_chain_id_pop();
        DEBUG(SSSDBG_IMPORTANT_INFO, "TIMER %p RESTORE %lu\n", timer, debug_chain_id);
    default:
        /* Do nothing. */
        break;
    }
}

static void sss_chain_id_trace_immediate(struct tevent_immediate *im,
                                  enum tevent_event_trace_point point,
                                  void *private_data)
{
    switch (point) {
    case TEVENT_EVENT_TRACE_CREATED:
        /* Assign the current chain id when the event is created. */
        DEBUG(SSSDBG_IMPORTANT_INFO, "IMM %p CREATED %lu\n", im, debug_chain_id);
        tevent_immediate_set_tag(im, debug_chain_id);
        break;
    case TEVENT_EVENT_TRACE_BEFORE_HANDLER:
        /* Set the chain id when a handler is being called. */
        DEBUG(SSSDBG_IMPORTANT_INFO, "IMM %p PUSH %lu\n", im, debug_chain_id);
        sss_chain_id_push(debug_chain_id);
        debug_chain_id = tevent_immediate_get_tag(im);
        DEBUG(SSSDBG_IMPORTANT_INFO, "IMM %p SET %lu\n", im, debug_chain_id);
        break;
    case TEVENT_EVENT_TRACE_AFTER_HANDLER:
        /* Restore original chain id. */
        debug_chain_id = sss_chain_id_pop();
        DEBUG(SSSDBG_IMPORTANT_INFO, "IMM %p RESTORE %lu\n", im, debug_chain_id);
    default:
        /* Do nothing. */
        break;
    }
}

static void sss_chain_id_trace_req(struct tevent_req *req,
                                   enum tevent_req_trace_point point,
                                   void *private_data)
{
    switch (point) {
    case TEVENT_REQ_TRACE_CREATED:
        /* Assign the current chain id when the event is created. */
        DEBUG(SSSDBG_IMPORTANT_INFO, "REQ %p CREATED %lu\n", req, debug_chain_id);
        tevent_req_set_tag(req, debug_chain_id);
        break;
    case TEVENT_REQ_TRACE_BEFORE_HANDLER:
        /* Set the chain id when a handler is being called. */
        DEBUG(SSSDBG_IMPORTANT_INFO, "REQ %p PUSH %lu\n", req, debug_chain_id);
        sss_chain_id_push(debug_chain_id);
        DEBUG(SSSDBG_IMPORTANT_INFO, "REQ %p SET %lu\n", req, debug_chain_id);
        debug_chain_id = tevent_req_get_tag(req);
        break;
    case TEVENT_REQ_TRACE_AFTER_HANDLER:
        /* Restore original chain id. */
        debug_chain_id = sss_chain_id_pop();
        DEBUG(SSSDBG_IMPORTANT_INFO, "REQ %p RESTORE %lu\n", req, debug_chain_id);
    default:
        /* Do nothing. */
        break;
    }
}

void sss_chain_id_setup(struct tevent_context *ev)
{
    sss_chain_id_push(0);
    tevent_set_trace_fd_callback(ev, sss_chain_id_trace_fd, NULL);
    tevent_set_trace_signal_callback(ev, sss_chain_id_trace_signal, NULL);
    tevent_set_trace_timer_callback(ev, sss_chain_id_trace_timer, NULL);
    tevent_set_trace_immediate_callback(ev, sss_chain_id_trace_immediate, NULL);
    tevent_req_set_trace_callback(sss_chain_id_trace_req, NULL);
}

void sss_chain_id_setup_req(struct tevent_req *req)
{
    //tevent_req_set_trace_callback(req, sss_chain_id_trace_req, NULL);
    return;
}

uint64_t sss_chain_id_set(uint64_t id)
{
    uint64_t old_id = debug_chain_id;
    debug_chain_id = id;
    return old_id;
}
