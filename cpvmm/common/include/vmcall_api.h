/****************************************************************************
* Copyright (c) 2013 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0

* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
****************************************************************************/

#ifndef _VMCALL_API_H_
#define _VMCALL_API_H_

#include "vmm_defs.h"

typedef enum _VMCALL_ID {
    VMCALL_IS_UVMM_RUNNING,
    VMCALL_EMULATOR_TERMINATE,
    VMCALL_EMULATOR_CLI_ACTIVATE,
    VMCALL_EMULATOR_PUTS,
    VMCALL_REGISTER_DEVICE_DRIVER,
    VMCALL_UNREGISTER_DEVICE_DRIVER,
    VMCALL_DEVICE_DRIVER_IOCTL,
    VMCALL_DEVICE_DRIVER_ACK_NOTIFICATION,
    VMCALL_PRINT_DEBUG_MESSAGE,
	VMCALL_ADD_SHARED_MEM,
	VMCALL_REMOVE_SHARED_MEM,
	VMCALL_WRITE_STRING,
	VMCALL_TMSL,

	VMCALL_UPDATE_LVT,        // Temporary for TSC deadline debugging

#ifdef ENABLE_TMSL_PROFILING
	 VMCALL_TMSL_PROFILING = 1022,  // for tmsl profiling.
#endif

    VMCALL_LAST_USED_INTERNAL = 1024  // must be the last
} VMCALL_ID;

#ifdef __GNUC__

#define API_FUNCTION
#define ASM_FUNCTION
#define CDECL
#define STDCALL

#else // MS Compiler

#define API_FUNCTION    __stdcall
#define ASM_FUNCTION    __stdcall
#define STDCALL         __stdcall

#ifndef UNITTESTING
#define CDECL           __cdecl
#endif

#endif


#define VMM_NATIVE_VMCALL_SIGNATURE                                            \
    (  ((UINT32)'$' << 24)                                                     \
    |  ((UINT32)'i' << 16)                                                     \
    |  ((UINT32)'M' << 8)                                                      \
    |  ((UINT32)'@' << 0)                                                      \
    )

/*-----------------------------------------------------------------------------*
*  FUNCTION : hw_vmcall()
*  PURPOSE  : Call for VMM service from the guest environment
*  ARGUMENTS: VMCALL_ID vmcall_id + 3 extra arguments
*  RETURNS  : VMM_OK = ok, other - error code
*-----------------------------------------------------------------------------*/
#ifndef UVMM_DRIVER_BUILD
VMM_STATUS ASM_FUNCTION hw_vmcall( VMCALL_ID vmcall_id, void* arg1, void* arg2, void* arg3 );
#else
VMM_STATUS CDECL hw_vmcall( VMCALL_ID vmcall_id, void* arg1, void* arg2, void* arg3 );
#endif

//=================================================================================

typedef struct VMM_IS_UVMM_RUNNING_PARAMS_S {
    VMCALL_ID vmcall_id;                   // IN must be "VMCALL_IS_UVMM_RUNNING"

    UINT32 version;                        // OUT - currently will be 0
} VMM_IS_UVMM_RUNNING_PARAMS;

/*-----------------------------------------------------------------------------*
*  FUNCTION : hw_vmcall_is_uvmm_running()
*  PURPOSE  : Call for VMM service for quering whether uVMM is running
*  ARGUMENTS: param - pointer to "VMM_IS_UVMM_RUNNING_PARAMS" structure
*  RETURNS  : VMM_OK = ok, other - error code
*
*  VMM_STATUS hw_vmcall_is_uvmm_running(VMM_IS_UVMM_RUNNING_PARAMS* param);
*-----------------------------------------------------------------------------*/
#define hw_vmcall_is_uvmm_running(is_uvmm_running_params_ptr) \
    hw_vmcall(VMCALL_IS_UVMM_RUNNING, (is_uvmm_running_params_ptr), NULL, NULL)

//=================================================================================
typedef struct VMM_DEVICE_DRIVER_REGISTRATION_PARAMS_S {
    VMCALL_ID vmcall_id;                   // IN must be "VMCALL_REGISTER_DEVICE_DRIVER"
    BOOLEAN is_initially_masked;           // IN
    volatile UINT64 notification_area_gva; // IN pointer to BOOLEAN polling variable

    UINT64 descriptor_handle;              // OUT
} VMM_DEVICE_DRIVER_REGISTRATION_PARAMS;

/*-----------------------------------------------------------------------------*
*  FUNCTION : hw_vmcall_register_driver()
*  PURPOSE  : Call for VMM service for registering device driver
*  ARGUMENTS: param - pointer to "VMM_DEVICE_DRIVER_REGISTRATION_PARAMS" structure
*  RETURNS  : VMM_OK = ok, other - error code
*
*  VMM_STATUS hw_vmcall_register_driver(VMM_DEVICE_DRIVER_REGISTRATION_PARAMS* param);
*-----------------------------------------------------------------------------*/
#define hw_vmcall_register_driver(driver_registration_params_ptr) \
    hw_vmcall(VMCALL_REGISTER_DEVICE_DRIVER, (driver_registration_params_ptr), NULL, NULL)

//=================================================================================

typedef struct VMM_DEVICE_DRIVER_UNREGISTRATION_PARAMS_S {
    VMCALL_ID vmcall_id;                   // IN must be "VMCALL_UNREGISTER_DEVICE_DRIVER"
    UINT8 padding[4];
    UINT64 descriptor_handle;              // IN descriptor_handle received upon registration
} VMM_DEVICE_DRIVER_UNREGISTRATION_PARAMS;

/*-----------------------------------------------------------------------------*
*  FUNCTION : hw_vmcall_unregister_driver()
*  PURPOSE  : Call for VMM service for unregistering device driver
*  ARGUMENTS: param - pointer to "VMM_DEVICE_DRIVER_UNREGISTRATION_PARAMS" structure
*  RETURNS  : VMM_OK = ok, other - error code
*
*  VMM_STATUS hw_vmcall_unregister_driver(VMM_DEVICE_DRIVER_UNREGISTRATION_PARAMS* param);
*-----------------------------------------------------------------------------*/
#define hw_vmcall_unregister_driver(driver_unregistration_params_ptr) \
    hw_vmcall(VMCALL_UNREGISTER_DEVICE_DRIVER, (driver_unregistration_params_ptr), NULL, NULL)

//=================================================================================

typedef enum {
    VMM_DEVICE_DRIVER_IOCTL_MASK_NOTIFICATION,
    VMM_DEVICE_DRIVER_IOCTL_UNMASK_NOTIFICATION,
} VMM_DEVICE_DRIVER_IOCTL_ID;

typedef struct VMM_DEVICE_DRIVER_IOCTL_PARAMS_S {
   VMCALL_ID vmcall_id;                   // IN must be "VMCALL_DEVICE_DRIVER_IOCTL"
   VMM_DEVICE_DRIVER_IOCTL_ID ioctl_id;   // IN id of the ioctl operation
   UINT64 descriptor_handle;              // IN descriptor_handle received upon registration
} VMM_DEVICE_DRIVER_IOCTL_PARAMS;

/*-----------------------------------------------------------------------------*
*  FUNCTION : hw_vmcall_driver_ioctl()
*  PURPOSE  : Call for VMM service for controlling device driver
*  ARGUMENTS: param - pointer to "VMM_DEVICE_DRIVER_IOCTL_PARAMS" structure
*  RETURNS  : VMM_OK = ok, other - error code
*
*  VMM_STATUS hw_vmcall_driver_ioctl(VMM_DEVICE_DRIVER_IOCTL_PARAMS* param);
*-----------------------------------------------------------------------------*/
#define hw_vmcall_driver_ioctl(driver_ioctl_params_ptr) \
    hw_vmcall(VMCALL_DEVICE_DRIVER_IOCTL, (driver_ioctl_params_ptr), NULL, NULL)

//=================================================================================

typedef struct VMM_DEVICE_DRIVER_ACK_NOTIFICATION_PARAMS_S {
    VMCALL_ID vmcall_id;                   // IN must be "VMCALL_DEVICE_DRIVER_ACK_NOTIFICATION"
    UINT8 padding[4];
    UINT64 descriptor_handle;              // IN descriptor_handle received upon registration

    UINT64 compontents_that_require_attention; // OUT - bitmask of components that require attention
} VMM_DEVICE_DRIVER_ACK_NOTIFICATION_PARAMS;

/*-----------------------------------------------------------------------------*
*  FUNCTION : hw_vmcall_driver_ack_notification()
*  PURPOSE  : Call for VMM service for acknoledging notification
*  ARGUMENTS: param - pointer to "DEVICE_DRIVER_ACK_NOTIFICATION_PARAMS" structure
*  RETURNS  : VMM_OK = ok, other - error code
*
*  VMM_STATUS hw_vmcall_driver_ack_notification(DEVICE_DRIVER_ACK_NOTIFICATION_PARAMS* param);
*-----------------------------------------------------------------------------*/
#define hw_vmcall_driver_ack_notification(driver_ioctl_params_ptr) \
    hw_vmcall(VMCALL_DEVICE_DRIVER_ACK_NOTIFICATION, (driver_ioctl_params_ptr), NULL, NULL)

//=================================================================================

#define VMM_MAX_DEBUG_MESSAGE_SIZE      252
typedef struct VMM_PRINT_DEBUG_MESSAGE_PARAMS_S {
    VMCALL_ID vmcall_id;                        // IN - must have "VMCALL_PRINT_DEBUG_MESSAGE" value
    char message[VMM_MAX_DEBUG_MESSAGE_SIZE];
} VMM_PRINT_DEBUG_MESSAGE_PARAMS;

/*-----------------------------------------------------------------------------*
*  FUNCTION : hw_vmcall_print_debug_message()
*  PURPOSE  : Call for VMM service for printing debug message
*  ARGUMENTS: param - pointer to "VMM_PRINT_DEBUG_MESSAGE_PARAMS" structure
*  RETURNS  : VMM_OK = ok, other - error code
*
*  VMM_STATUS hw_vmcall_print_debug_message(VMM_PRINT_DEBUG_MESSAGE_PARAMS* param);
*-----------------------------------------------------------------------------*/
#define hw_vmcall_print_debug_message(debug_message_params_ptr) \
    hw_vmcall(VMCALL_PRINT_DEBUG_MESSAGE, (debug_message_params_ptr), NULL, NULL)




/***********************************************************************
  some structures for parameters pass from driver to uVmm
  for testing the driver.
***********************************************************************/
typedef struct VMM_ADD_SHARED_MEM_PARAMS{
	VMCALL_ID vmcall_id;
	UINT8 padding[4];
	UINT64 GuestVirtualAddress;
	UINT32 BufSize;
	int uVMMMemHandle;
	VMM_STATUS status;
	UINT8 padding2[4];
} VMM_ADD_SHARED_MEM_PARAMS;

typedef struct VMM_REMOVE_SHARED_MEM_PARAMS{
	VMCALL_ID vmcall_id;
	int uVMMMemHandle;
	VMM_STATUS status;

} VMM_REMOVE_SHARED_MEM_PARAMS;

typedef struct VMM_WRITE_STRING_PARAMS{
	VMCALL_ID vmcall_id;
	int uVMMMemHandle;
	char  buf[100];
	UINT32 len;
	VMM_STATUS status;

} VMM_WRITE_STRING_PARAMS;


#endif // _VMCALL_API_H_
