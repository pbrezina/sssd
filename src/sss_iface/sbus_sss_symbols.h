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

#ifndef _SBUS_SSS_SYMBOLS_H_
#define _SBUS_SSS_SYMBOLS_H_

#include "sbus/sbus_interface_declarations.h"

extern const struct sbus_method_arguments
_sbus_sss_args_org_freedesktop_FleetCommanderClient_ProcessSSSDFiles;

extern const struct sbus_method_arguments
_sbus_sss_args_org_freedesktop_systemd1_Manager_RestartUnit;

extern const struct sbus_method_arguments
_sbus_sss_args_org_freedesktop_systemd1_Manager_StartUnit;

extern const struct sbus_method_arguments
_sbus_sss_args_org_freedesktop_systemd1_Manager_StopUnit;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_DataProvider_AccessControl_RefreshRules;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_DataProvider_Autofs_Enumerate;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_DataProvider_Autofs_GetEntry;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_DataProvider_Autofs_GetMap;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_DataProvider_Backend_IsOnline;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_DataProvider_Client_Register;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_DataProvider_Failover_ActiveServer;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_DataProvider_Failover_ListServers;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_DataProvider_Failover_ListServices;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_ProxyChild_Auth_PAM;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_ProxyChild_Client_Register;

extern const struct sbus_argument
_sbus_sss_args_sssd_Responder_Domain_StateChanged[];

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_Responder_EnumCache_Clear;

extern const struct sbus_argument
_sbus_sss_args_sssd_Responder_NegativeCache_ResetGroups[];

extern const struct sbus_argument
_sbus_sss_args_sssd_Responder_NegativeCache_ResetUsers[];

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_dataprovider_getAccountDomain;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_dataprovider_getAccountInfo;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_dataprovider_getDomains;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_dataprovider_hostHandler;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_dataprovider_pamHandler;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_dataprovider_sudoHandler;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_monitor_RegisterService;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_nss_MemoryCache_Clear;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_nss_MemoryCache_InvalidateGroupById;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_nss_MemoryCache_UpdateInitgroups;

extern const struct sbus_argument
_sbus_sss_args_sssd_nss_MemoryCache_InvalidateAllGroups[];

extern const struct sbus_argument
_sbus_sss_args_sssd_nss_MemoryCache_InvalidateAllInitgroups[];

extern const struct sbus_argument
_sbus_sss_args_sssd_nss_MemoryCache_InvalidateAllUsers[];

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_service_goOffline;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_service_resInit;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_service_resetOffline;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_service_rotateLogs;

extern const struct sbus_method_arguments
_sbus_sss_args_sssd_service_sysbusReconnect;

#endif /* _SBUS_SSS_SYMBOLS_H_ */
