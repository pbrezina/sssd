/*
    Generated by sbus code generator

    Copyright (C) 2017 Red Hat

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

#ifndef _SBUS_SSS_ARGUMENTS_H_
#define _SBUS_SSS_ARGUMENTS_H_

#include <errno.h>
#include <stdint.h>
#include <talloc.h>
#include <stdbool.h>
#include <dbus/dbus.h>

#include "sss_iface/sss_iface_types.h"

struct _sbus_sss_invoker_args_as {
    const char ** arg0;
};

errno_t
_sbus_sss_invoker_read_as
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_as *args);

errno_t
_sbus_sss_invoker_write_as
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_as *args);

struct _sbus_sss_invoker_args_b {
    bool arg0;
};

errno_t
_sbus_sss_invoker_read_b
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_b *args);

errno_t
_sbus_sss_invoker_write_b
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_b *args);

struct _sbus_sss_invoker_args_o {
    const char * arg0;
};

errno_t
_sbus_sss_invoker_read_o
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_o *args);

errno_t
_sbus_sss_invoker_write_o
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_o *args);

struct _sbus_sss_invoker_args_pam_data {
    struct pam_data * arg0;
};

errno_t
_sbus_sss_invoker_read_pam_data
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_pam_data *args);

errno_t
_sbus_sss_invoker_write_pam_data
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_pam_data *args);

struct _sbus_sss_invoker_args_pam_response {
    struct pam_data * arg0;
};

errno_t
_sbus_sss_invoker_read_pam_response
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_pam_response *args);

errno_t
_sbus_sss_invoker_write_pam_response
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_pam_response *args);

struct _sbus_sss_invoker_args_q {
    uint16_t arg0;
};

errno_t
_sbus_sss_invoker_read_q
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_q *args);

errno_t
_sbus_sss_invoker_write_q
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_q *args);

struct _sbus_sss_invoker_args_qus {
    uint16_t arg0;
    uint32_t arg1;
    const char * arg2;
};

errno_t
_sbus_sss_invoker_read_qus
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_qus *args);

errno_t
_sbus_sss_invoker_write_qus
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_qus *args);

struct _sbus_sss_invoker_args_s {
    const char * arg0;
};

errno_t
_sbus_sss_invoker_read_s
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_s *args);

errno_t
_sbus_sss_invoker_write_s
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_s *args);

struct _sbus_sss_invoker_args_sdomain_state {
    const char * arg0;
    enum sss_domain_state arg1;
};

errno_t
_sbus_sss_invoker_read_sdomain_state
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_sdomain_state *args);

errno_t
_sbus_sss_invoker_write_sdomain_state
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_sdomain_state *args);

struct _sbus_sss_invoker_args_sqq {
    const char * arg0;
    uint16_t arg1;
    uint16_t arg2;
};

errno_t
_sbus_sss_invoker_read_sqq
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_sqq *args);

errno_t
_sbus_sss_invoker_write_sqq
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_sqq *args);

struct _sbus_sss_invoker_args_ss {
    const char * arg0;
    const char * arg1;
};

errno_t
_sbus_sss_invoker_read_ss
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_ss *args);

errno_t
_sbus_sss_invoker_write_ss
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_ss *args);

struct _sbus_sss_invoker_args_ssau {
    const char * arg0;
    const char * arg1;
    uint32_t * arg2;
};

errno_t
_sbus_sss_invoker_read_ssau
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_ssau *args);

errno_t
_sbus_sss_invoker_write_ssau
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_ssau *args);

struct _sbus_sss_invoker_args_u {
    uint32_t arg0;
};

errno_t
_sbus_sss_invoker_read_u
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_u *args);

errno_t
_sbus_sss_invoker_write_u
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_u *args);

struct _sbus_sss_invoker_args_us {
    uint32_t arg0;
    const char * arg1;
};

errno_t
_sbus_sss_invoker_read_us
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_us *args);

errno_t
_sbus_sss_invoker_write_us
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_us *args);

struct _sbus_sss_invoker_args_usq {
    uint32_t arg0;
    const char * arg1;
    uint16_t arg2;
};

errno_t
_sbus_sss_invoker_read_usq
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_usq *args);

errno_t
_sbus_sss_invoker_write_usq
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_usq *args);

struct _sbus_sss_invoker_args_uss {
    uint32_t arg0;
    const char * arg1;
    const char * arg2;
};

errno_t
_sbus_sss_invoker_read_uss
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_uss *args);

errno_t
_sbus_sss_invoker_write_uss
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_uss *args);

struct _sbus_sss_invoker_args_uusss {
    uint32_t arg0;
    uint32_t arg1;
    const char * arg2;
    const char * arg3;
    const char * arg4;
};

errno_t
_sbus_sss_invoker_read_uusss
   (TALLOC_CTX *mem_ctx,
    DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_uusss *args);

errno_t
_sbus_sss_invoker_write_uusss
   (DBusMessageIter *iter,
    struct _sbus_sss_invoker_args_uusss *args);

#endif /* _SBUS_SSS_ARGUMENTS_H_ */
