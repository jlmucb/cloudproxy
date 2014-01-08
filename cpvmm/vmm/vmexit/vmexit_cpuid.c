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

#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMEXIT_CPUID_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMEXIT_CPUID_C, __condition)
#include "vmm_defs.h"
#include "list.h"
#include "memory_allocator.h"
#include "guest_cpu.h"
#include "guest.h"
#include "hw_utils.h"
#include "vmexit_cpuid.h"

#define CPUID_EAX 0
#define CPUID_EBX 1
#define CPUID_ECX 2
#define CPUID_EDX 3


#define DESCRIPTOR_L_BIT 0x2000

typedef struct _CPUID_FILTER_DESCRIPTOR {
    LIST_ELEMENT            list;
    ADDRESS                 cpuid;  // cpuid leaf index
    CPUID_FILTER_HANDLER    handler;
} CPUID_FILTER_DESCRIPTOR;

static
void vmexit_cpuid_filter_install(
    GUEST_HANDLE         guest,
    ADDRESS              cpuid,
    CPUID_FILTER_HANDLER handler)
{
    LIST_ELEMENT            *filter_desc_list = guest_get_cpuid_list(guest);
    CPUID_FILTER_DESCRIPTOR *p_filter_desc = vmm_malloc(sizeof(*p_filter_desc));

    VMM_ASSERT(NULL != p_filter_desc);

    if (NULL != p_filter_desc)
    {
        p_filter_desc->cpuid   = cpuid;
        p_filter_desc->handler = handler;
        list_add(filter_desc_list, &p_filter_desc->list);
    }
}

static
VMEXIT_HANDLING_STATUS vmexit_cpuid_instruction(GUEST_CPU_HANDLE gcpu)
{
    CPUID_PARAMS    cpuid_params;
    UINT32          req_id;
    LIST_ELEMENT    *filter_desc_list = guest_get_cpuid_list(gcpu_guest_handle(gcpu));
    LIST_ELEMENT    *list_iterator;
    CPUID_FILTER_DESCRIPTOR *p_filter_desc;

    cpuid_params.m_rax = gcpu_get_native_gp_reg(gcpu, IA32_REG_RAX);
    cpuid_params.m_rbx = gcpu_get_native_gp_reg(gcpu, IA32_REG_RBX);
    cpuid_params.m_rcx = gcpu_get_native_gp_reg(gcpu, IA32_REG_RCX);
    cpuid_params.m_rdx = gcpu_get_native_gp_reg(gcpu, IA32_REG_RDX);

    req_id = (UINT32)cpuid_params.m_rax;

    // get the real h/w values
    hw_cpuid(&cpuid_params);

    // pass to filters for virtualization
    LIST_FOR_EACH(filter_desc_list, list_iterator)
    {
        p_filter_desc = LIST_ENTRY(list_iterator, CPUID_FILTER_DESCRIPTOR, list);
        if (p_filter_desc->cpuid == req_id)
        {
            p_filter_desc->handler(gcpu, &cpuid_params);
        }
    }

    // write back to guest OS
    gcpu_set_native_gp_reg(gcpu, IA32_REG_RAX, cpuid_params.m_rax);
    gcpu_set_native_gp_reg(gcpu, IA32_REG_RBX, cpuid_params.m_rbx);
    gcpu_set_native_gp_reg(gcpu, IA32_REG_RCX, cpuid_params.m_rcx);
    gcpu_set_native_gp_reg(gcpu, IA32_REG_RDX, cpuid_params.m_rdx);


    // increment IP to skip executed CPUID instruction
    gcpu_skip_guest_instruction(gcpu);

    return VMEXIT_HANDLED;
}

#pragma warning( push )
#pragma warning (disable : 4100) // disable unreferenced formal parameters

static 
void cpuid_leaf_1h_filter(
            GUEST_CPU_HANDLE gcpu, 
            CPUID_PARAMS *p_cpuid )
{
    VMM_ASSERT(p_cpuid);

    // hide SMX support
    BIT_CLR64(p_cpuid->m_rcx, CPUID_LEAF_1H_ECX_SMX_SUPPORT);

    // hide VMX support
    BIT_CLR64(p_cpuid->m_rcx, CPUID_LEAF_1H_ECX_VMX_SUPPORT);
}

static 
void cpuid_leaf_3h_filter(
            GUEST_CPU_HANDLE gcpu, 
            CPUID_PARAMS *p_cpuid )
{
    VMM_ASSERT(p_cpuid);

    // use PSN index 3 to indicate whether eVmm is running or not.
    p_cpuid->m_rcx = EVMM_RUNNING_SIGNATURE_VMM;   //"EVMM"
    p_cpuid->m_rdx = EVMM_RUNNING_SIGNATURE_CORP;  //"INTC"


}


static 
void cpuid_leaf_ext_1h_filter(
            GUEST_CPU_HANDLE gcpu, 
            CPUID_PARAMS *p_cpuid )
{
    VMCS_OBJECT* vmcs = gcpu_get_vmcs(gcpu);
    UINT64 guest_cs_ar= vmcs_read(vmcs, VMCS_GUEST_CS_AR);

    VMM_ASSERT(p_cpuid);

    if (BITMAP_GET(guest_cs_ar,DESCRIPTOR_L_BIT) == 0) 
    {
        //Guest is not in 64 bit mode, the bit 11 of EDX should be 
        //cleared since this bit indicates syscall/sysret available
        //in 64 bit mode. See the Intel Software Programmer Manual vol 2A 
        //CPUID instruction

        BIT_CLR64(p_cpuid->m_rdx, CPUID_EXT_LEAF_1H_EDX_SYSCALL_SYSRET);
    }

}



#pragma warning( pop )


void vmexit_cpuid_guest_intialize( GUEST_ID  guest_id)
{
    GUEST_HANDLE guest = guest_handle(guest_id);

    VMM_ASSERT(guest);
    
    // install CPUID vmexit handler
    vmexit_install_handler(
                guest_id,
                vmexit_cpuid_instruction,
                Ia32VmxExitBasicReasonCpuidInstruction);

    // register cpuid(leaf 0x1) filter handler
    vmexit_cpuid_filter_install(guest, CPUID_LEAF_1H,cpuid_leaf_1h_filter);


    // register cpuid(leaf 0x3) filter handler
    vmexit_cpuid_filter_install(guest, CPUID_LEAF_3H,cpuid_leaf_3h_filter);

    // register cpuid(ext leaf 0x80000001) filter handler
    vmexit_cpuid_filter_install(guest, CPUID_EXT_LEAF_1H,cpuid_leaf_ext_1h_filter);

    VMM_LOG(mask_uvmm, level_trace,"finish vmexit_cpuid_guest_intialize\r\n");

    return;
}

