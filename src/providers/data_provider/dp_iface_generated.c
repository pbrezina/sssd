/* The following definitions are auto-generated from dp_iface.xml */

#include "util/util.h"
#include "sbus/sssd_dbus.h"
#include "sbus/sssd_dbus_meta.h"
#include "sbus/sssd_dbus_invokers.h"
#include "dp_iface_generated.h"

/* invokes a handler with a 's' DBus signature */
static int invoke_s_method(struct sbus_request *dbus_req, void *function_ptr);

/* arguments for org.freedesktop.sssd.DataProvider.Client.Register */
const struct sbus_arg_meta iface_dp_client_Register__in[] = {
    { "Name", "s" },
    { NULL, }
};

int iface_dp_client_Register_finish(struct sbus_request *req)
{
   return sbus_request_return_and_finish(req,
                                         DBUS_TYPE_INVALID);
}

/* methods for org.freedesktop.sssd.DataProvider.Client */
const struct sbus_method_meta iface_dp_client__methods[] = {
    {
        "Register", /* name */
        iface_dp_client_Register__in,
        NULL, /* no out_args */
        offsetof(struct iface_dp_client, Register),
        invoke_s_method,
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.DataProvider.Client */
const struct sbus_interface_meta iface_dp_client_meta = {
    "org.freedesktop.sssd.DataProvider.Client", /* name */
    iface_dp_client__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};

/* methods for org.freedesktop.sssd.dataprovider */
const struct sbus_method_meta iface_dp__methods[] = {
    {
        "pamHandler", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct iface_dp, pamHandler),
        NULL, /* no invoker */
    },
    {
        "sudoHandler", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct iface_dp, sudoHandler),
        NULL, /* no invoker */
    },
    {
        "autofsHandler", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct iface_dp, autofsHandler),
        NULL, /* no invoker */
    },
    {
        "hostHandler", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct iface_dp, hostHandler),
        NULL, /* no invoker */
    },
    {
        "getDomains", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct iface_dp, getDomains),
        NULL, /* no invoker */
    },
    {
        "getAccountInfo", /* name */
        NULL, /* no in_args */
        NULL, /* no out_args */
        offsetof(struct iface_dp, getAccountInfo),
        NULL, /* no invoker */
    },
    { NULL, }
};

/* interface info for org.freedesktop.sssd.dataprovider */
const struct sbus_interface_meta iface_dp_meta = {
    "org.freedesktop.sssd.dataprovider", /* name */
    iface_dp__methods,
    NULL, /* no signals */
    NULL, /* no properties */
    sbus_invoke_get_all, /* GetAll invoker */
};

/* invokes a handler with a 's' DBus signature */
static int invoke_s_method(struct sbus_request *dbus_req, void *function_ptr)
{
    const char * arg_0;
    int (*handler)(struct sbus_request *, void *, const char *) = function_ptr;

    if (!sbus_request_parse_or_finish(dbus_req,
                               DBUS_TYPE_STRING, &arg_0,
                               DBUS_TYPE_INVALID)) {
         return EOK; /* request handled */
    }

    return (handler)(dbus_req, dbus_req->intf->handler_data,
                     arg_0);
}
