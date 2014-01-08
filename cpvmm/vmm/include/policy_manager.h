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

#ifndef _POLICY_MANAGER_
#define _POLICY_MANAGER_

#include "vmm_defs.h"
#include "vmm_objects.h"

//****************************************************************************
//
//  Define uVMM policy manager
//
//  The Policy Manager is responsible for setting up all switches in different
//  uVMM objects that influence the overall uVMM behavior. The uVMM global
//  behavior should depend on required application behavior it is used for.
//
//****************************************************************************

/*
 * Return codes for the POLICY related functions.
 */
typedef enum _E_POL_RETVAL
{
    POL_RETVAL_SUCCESS = 0,
    POL_RETVAL_FAIL = -256,
    POL_RETVAL_BAD_PARAM,
    POL_RETVAL_BAD_VALUE,
}  POL_RETVAL;


/*
 * Paging POLICY values.
 */
typedef enum _E_VMM_PAGING_POLICY
{
    POL_PG_NO_PAGING,
    POL_PG_VTLB,
    POL_PG_EPT,
    POL_PG_PRIVATE,
    POL_PG_ILLEGAL
}  VMM_PAGING_POLICY;


/*
 * Paging POLICY values.
 */
typedef enum _E_VMM_CACHE_POLICY
{
    POL_CACHE_DIS_NO_INTERVENING,
    POL_CACHE_DIS_VIRTUALIZATION,
    POL_CACHE_DIS_ILLEGAL,
}  VMM_CACHE_POLICY;


/*
 * POLICY types.
 */
typedef UINT64  VMM_POLICY;


//----------------------------------------------------------------------------
//
// Setup the policy
//
// Called by BSP main() before any initializations to setup the uVMM policy.
//
//----------------------------------------------------------------------------

POL_RETVAL global_policy_setup(const VMM_POLICY  *policy);

BOOLEAN global_policy_uses_vtlb(void);

BOOLEAN global_policy_uses_ept(void);

BOOLEAN global_policy_is_cache_dis_virtualized(void);

POL_RETVAL get_global_policy(VMM_POLICY  *policy);


/*
 * Functions to manipulate VMM_POLICY type variables.
 */
POL_RETVAL clear_policy(VMM_POLICY  *policy);

POL_RETVAL copy_policy(VMM_POLICY  *dst_policy, const VMM_POLICY  *src_policy);


/*
 * Functions for cache policy.
 */
POL_RETVAL clear_cache_policy(VMM_POLICY  *policy);
POL_RETVAL set_cache_policy(VMM_POLICY  *policy, VMM_CACHE_POLICY  cache_policy);
POL_RETVAL get_cache_policy(const VMM_POLICY  *policy, VMM_CACHE_POLICY  *cache_policy);


/*
 * Functions for paging policy.
 */
POL_RETVAL clear_paging_policy(VMM_POLICY  *policy);
POL_RETVAL set_paging_policy(VMM_POLICY  *policy, VMM_PAGING_POLICY  pg_policy);
POL_RETVAL get_paging_policy(const VMM_POLICY  *policy, VMM_PAGING_POLICY  *pg_policy);


#endif // _POLICY_MANAGER_

