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

#include "policy_manager.h"
//#include "libc.h"
#include "vmm_dbg.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(POLICY_MANAGER_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(POLICY_MANAGER_C, __condition)

// do not report warning on unused params
#pragma warning (disable: 4100)

#define FIELD_MASK(size, offset) ((BIT_VALUE64((size)) - 1) << (offset))

#define  POL_PG_FIELD_OFFS     0
#define  POL_PG_FIELD_SIZE     10
//#define  POL_PG_MASK           ((BIT_VALUE64(POL_PG_FIELD_SIZE) - 1) << POL_PG_FIELD_OFFS)
#define  POL_PG_MASK           FIELD_MASK(POL_PG_FIELD_SIZE, POL_PG_FIELD_OFFS)

#define  POL_CACHE_FIELD_OFFS  (POL_PG_FIELD_OFFS + POL_PG_FIELD_SIZE)
#define  POL_CACHE_FIELD_SIZE  2
//#define  POL_CACHE_MASK        ((BIT_VALUE64(POL_CACHE_FIELD_SIZE) - 1) << POL_CACHE_FIELD_OFFS)
#define  POL_CACHE_MASK        FIELD_MASK(POL_CACHE_FIELD_SIZE, POL_CACHE_FIELD_OFFS)


static VMM_POLICY g_vmm_policy;
static BOOLEAN    g_init_done = FALSE;
extern VMM_PAGING_POLICY g_pg_policy;


//******************************************************************************
//
// Policy Manager
//
//******************************************************************************

// ---------------------------- Global Policy APIs  --------------------------

//----------------------------------------------------------------------------
//
// Setup the global policy.
//
// Called by BSP main() before any initializations to setup the uVMM policy.
//
//----------------------------------------------------------------------------
POL_RETVAL global_policy_setup(const VMM_POLICY  *policy)
{
    if (!g_init_done)
    {
        clear_policy(&g_vmm_policy);
        g_init_done = TRUE;
    }

    return copy_policy(&g_vmm_policy, policy);
}


BOOLEAN global_policy_uses_vtlb(void)
{
    VMM_PAGING_POLICY  pg_policy;

    get_paging_policy(&g_vmm_policy, &pg_policy);

    return (pg_policy == POL_PG_VTLB);
}


BOOLEAN global_policy_uses_ept(void)
{
    VMM_PAGING_POLICY  pg_policy;

    get_paging_policy(&g_vmm_policy, &pg_policy);

    return (pg_policy == POL_PG_EPT);
}


POL_RETVAL get_global_policy(VMM_POLICY  *policy)
{
    return copy_policy(policy, &g_vmm_policy);
}


BOOLEAN global_policy_is_cache_dis_virtualized(void)
{
    VMM_CACHE_POLICY  cache_policy;

    get_cache_policy(&g_vmm_policy, &cache_policy);

    return (cache_policy == POL_CACHE_DIS_VIRTUALIZATION);
}


// -------------------------- Policy Manipulation APIs  -----------------------


POL_RETVAL clear_policy(VMM_POLICY  *policy)
{
    *policy = 0;

    return POL_RETVAL_SUCCESS;
}


POL_RETVAL copy_policy(VMM_POLICY  *dst_policy, const VMM_POLICY  *src_policy)
{
    VMM_ASSERT(dst_policy != NULL);

    *dst_policy = *src_policy;

    return POL_RETVAL_SUCCESS;
}


static POL_RETVAL get_policy(const VMM_POLICY  *policy, void  *policy_enum, UINT32  offs, UINT32  size,
                             UINT32  err_val)
{
    UINT64      bit = BIT_VALUE64(offs);
    UINT32      count;
    POL_RETVAL  ret = POL_RETVAL_SUCCESS;

    VMM_ASSERT(policy != NULL);
    VMM_ASSERT(policy_enum != NULL);

    for (count = 0; (*policy & bit) == 0 && count < size; count++, bit <<= 1)
        ;

    if (count == size)
    {
        ret = POL_RETVAL_BAD_VALUE;
        *(UINT32 *) policy_enum = err_val;
    }
    else
        *(UINT32 *) policy_enum = count;

    return ret;
}

#ifdef INCLUDE_UNUSED_CODE
POL_RETVAL clear_paging_policy(VMM_POLICY  *policy)
{
    VMM_ASSERT(policy != NULL);

    BITMAP_CLR64(*policy, POL_PG_MASK);

    return POL_RETVAL_SUCCESS;
}
#endif

POL_RETVAL set_paging_policy(VMM_POLICY  *policy, VMM_PAGING_POLICY  pg_policy)
{
    // BEFORE_VMLAUNCH. PARANOID check.
    VMM_ASSERT(policy != NULL);

    BITMAP_ASSIGN64(*policy, POL_PG_MASK, BIT_VALUE64((int) pg_policy + POL_PG_FIELD_OFFS));
	
	g_pg_policy = pg_policy;

    return POL_RETVAL_SUCCESS;
}


POL_RETVAL get_paging_policy(const VMM_POLICY  *policy, VMM_PAGING_POLICY  *pg_policy)
{
    return get_policy(policy, pg_policy, POL_PG_FIELD_OFFS, POL_PG_FIELD_SIZE, POL_CACHE_DIS_ILLEGAL);
}

#ifdef INCLUDE_UNUSED_CODE
POL_RETVAL clear_cache_policy(VMM_POLICY  *policy)
{
    VMM_ASSERT(policy != NULL);

    BITMAP_CLR64(*policy, POL_CACHE_MASK);

    return POL_RETVAL_SUCCESS;
}
#endif

POL_RETVAL set_cache_policy(VMM_POLICY  *policy, VMM_CACHE_POLICY  cache_policy)
{
    // BEFORE_VMLAUNCH. PARANOID check.
    VMM_ASSERT(policy != NULL);

    BITMAP_ASSIGN64(*policy, POL_CACHE_MASK, BIT_VALUE64((int) cache_policy + POL_CACHE_FIELD_OFFS));

    return POL_RETVAL_SUCCESS;
}

POL_RETVAL get_cache_policy(const VMM_POLICY  *policy, VMM_CACHE_POLICY  *cache_policy)
{
    return get_policy(policy, cache_policy, POL_CACHE_FIELD_OFFS, POL_CACHE_FIELD_SIZE, POL_CACHE_DIS_ILLEGAL);
}


