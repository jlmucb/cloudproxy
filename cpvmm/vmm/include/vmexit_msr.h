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

#ifndef _VMEXIT_MSR_H_
#define _VMEXIT_MSR_H_

#include "list.h"

// return TRUE if instruction was executed, FAULSE in case of exception
typedef BOOLEAN (*MSR_ACCESS_HANDLER)(GUEST_CPU_HANDLE  gcpu,
                                      MSR_ID            msr_id,
                                      UINT64           *p_value,
                                      void             *context);

typedef struct _MSR_VMEXIT_CONTROL
{
    UINT8          *msr_bitmap;
    LIST_ELEMENT    msr_list[1];
} MSR_VMEXIT_CONTROL;


/*----------------------------------------------------------------------------*
*  FUNCTION : msr_vmexit_on_all()
*  PURPOSE  : Turns VMEXIT on all ON/OFF
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu
*           : BOOLEAN enable
*  RETURNS  : none, must succeed.
*----------------------------------------------------------------------------*/
void msr_vmexit_on_all(GUEST_CPU_HANDLE gcpu, BOOLEAN enable)
    ;

/*----------------------------------------------------------------------------*
*  FUNCTION : msr_vmexit_guest_setup()
*  PURPOSE  : Allocates structures for MSR virtualization
*           : Must be called prior any other function from the package on this gcpu,
*           : but after gcpu VMCS was loaded
*  ARGUMENTS: GUEST_HANDLE guest
*  RETURNS  : none, must succeed.
*----------------------------------------------------------------------------*/
void msr_vmexit_guest_setup(GUEST_HANDLE guest
    );

/*----------------------------------------------------------------------------*
*  FUNCTION : msr_vmexit_activate()
*  PURPOSE  : Register MSR related structures with HW (VMCS)
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu
*  RETURNS  : none, must succeed.
*----------------------------------------------------------------------------*/
void msr_vmexit_activate(GUEST_CPU_HANDLE gcpu
    );

/*----------------------------------------------------------------------------*
*  FUNCTION : msr_vmexit_handler_register()
*  PURPOSE  : Register specific MSR handler with VMEXIT
*  ARGUMENTS: GUEST_HANDLE        guest
*           : MSR_ID              msr_id
*           : MSR_ACCESS_HANDLER  msr_handler,
*           : RW_ACCESS           access
*           : void               *context
*  RETURNS  : VMM_OK if succeeded
*----------------------------------------------------------------------------*/
VMM_STATUS msr_vmexit_handler_register(
    GUEST_HANDLE        guest,
    MSR_ID              msr_id,
    MSR_ACCESS_HANDLER  msr_handler,
    RW_ACCESS           access,
    void               *context
    );

/*----------------------------------------------------------------------------*
*  FUNCTION : msr_vmexit_handler_unregister()
*  PURPOSE  : Unregister specific MSR VMEXIT handler
*  ARGUMENTS: GUEST_HANDLE  guest
*           : MSR_ID        msr_id
*  RETURNS  : VMM_OK if succeeded
*----------------------------------------------------------------------------*/
VMM_STATUS msr_vmexit_handler_unregister(
    GUEST_HANDLE    guest,
    MSR_ID          msr_id,
    RW_ACCESS       access
    );

/*----------------------------------------------------------------------------*
*  FUNCTION : msr_guest_access_inhibit()
*  PURPOSE  : Install handler which prevents access to MSR from the guest space
*  ARGUMENTS: GUEST_HANDLE  guest
*           : MSR_ID        msr_id
*  RETURNS  : VMM_OK if succeeded
*----------------------------------------------------------------------------*/
VMM_STATUS msr_guest_access_inhibit(
    GUEST_HANDLE    guest,
    MSR_ID          msr_id
    );

/*----------------------------------------------------------------------------*
*  FUNCTION : msr_trial_access()
*  PURPOSE  : Try to execute real MSR read/write
*           : If exception was generated, inject it into guest
*  ARGUMENTS: GUEST_CPU_HANDLE    gcpu
*           : MSR_ID              msr_id
*           : RW_ACCESS           access
*  RETURNS  : TRUE if instruction was executed, FALSE otherwise (fault occured)
*----------------------------------------------------------------------------*/
BOOLEAN msr_trial_access(
    GUEST_CPU_HANDLE    gcpu,
    MSR_ID              msr_id,
    RW_ACCESS           access,
    UINT64              *msr_value
    );


/*----------------------------------------------------------------------------*
*  FUNCTION : vmexit_enable_disable_for_msr_in_exclude_list()
*  PURPOSE  : enable/disable msr read/write vmexit for msrs in the exclude list
*  ARGUMENTS: GUEST_CPU_HANDLE    gcpu
*           : MSR_ID              msr_id
*           : RW_ACCESS           access
*			: BOOLEAN			  TRUE to enable write/read vmexit, FALSE to disable vmexit
*  RETURNS  : TRUE if parameters are correct.
*----------------------------------------------------------------------------*/
BOOLEAN vmexit_register_unregister_for_efer(
    GUEST_HANDLE    guest,
    MSR_ID          msr_id,
    RW_ACCESS       access,
	BOOLEAN			reg_dereg);

#endif // _VMEXIT_MSR_H_

