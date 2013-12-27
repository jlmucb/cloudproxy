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
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMEXIT_MSR_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMEXIT_MSR_C, __condition)
#include "vmm_defs.h"
#include "heap.h"
#include "memory_allocator.h"
#include "hw_utils.h"
#include "isr.h"
#include "guest.h"
#include "guest_cpu.h"
#include "guest_cpu_vmenter_event.h"
#include "vmx_ctrl_msrs.h"
#include "vmcs_api.h"
#include "vmexit.h"
#include "vmexit_msr.h"
#include "vmm_dbg.h"
#include "mtrrs_abstraction.h"
#include "host_memory_manager_api.h"
#include "vmm_events_data.h"
#include "pat_manager.h"
#include "local_apic.h"
#include "..\..\guest\guest_cpu\unrestricted_guest.h"
#include "vmm_callback.h"
#include "memory_dump.h"

#define MSR_LOW_RANGE_IN_BITS   ((MSR_LOW_LAST - MSR_LOW_FIRST + 1) / 8)
#define MSR_HIGH_RANGE_IN_BITS  ((MSR_HIGH_LAST - MSR_HIGH_FIRST + 1) / 8)

#define MSR_READ_LOW_OFFSET     0
#define MSR_READ_HIGH_OFFSET    (MSR_READ_LOW_OFFSET  + MSR_LOW_RANGE_IN_BITS)
#define MSR_WRITE_LOW_OFFSET    (MSR_READ_HIGH_OFFSET + MSR_LOW_RANGE_IN_BITS)
#define MSR_WRITE_HIGH_OFFSET   (MSR_WRITE_LOW_OFFSET + MSR_HIGH_RANGE_IN_BITS)

/*
 *    *** Hyper-V MSRs access workaround  ***
 * When we run our pnp launch driver with Alpha4_882 IBAgent,
 * we saw msr read at 0x40000081, since it isn't a real hardware MSR, we got
 * "RDMSR[0x40000081] failed. FaultVector=0x0000000D ErrCode=0x00000000" message
 * in serial port, then got BSOD. After injecting GP to guest in this MSR read,
 * Our PnP driver can work with IBAgent. The address range of Hyper-V
 * MSRs is from 0x40000000 to 0x400000F0). We need to investigate this
 * workaround and check whether it is necessary to extend this fix to any MSR
 * read/write outside 0x00000000 to 0x00001FFF and  0xC0000000 to 0xC0001FFF
 */

#define HYPER_V_MSR_MIN	0x40000000
#define HYPER_V_MSR_MAX	0x400000F0

#define LOW_BITS_32_MASK    ((UINT64)UINT32_ALL_ONES)

typedef struct {
    MSR_ID              msr_id;
    UINT8               pad[4];
    MSR_ACCESS_HANDLER  msr_read_handler;
    MSR_ACCESS_HANDLER  msr_write_handler;
    void               *msr_context;
    LIST_ELEMENT        msr_list;
} MSR_VMEXIT_DESCRIPTOR;


/*---------------------------------Local Data---------------------------------*/
static struct {
    UINT32      msr_id;
    VMCS_FIELD  vmcs_field_id;
} vmcs_resident_guest_msrs[] = {
    { IA32_MSR_SYSENTER_CS,     VMCS_GUEST_SYSENTER_CS },
    { IA32_MSR_SYSENTER_ESP,    VMCS_GUEST_SYSENTER_ESP },
    { IA32_MSR_SYSENTER_EIP,    VMCS_GUEST_SYSENTER_EIP },
    { IA32_MSR_DEBUGCTL,        VMCS_GUEST_DEBUG_CONTROL },
    { IA32_MSR_PERF_GLOBAL_CTRL,VMCS_GUEST_IA32_PERF_GLOBAL_CTRL },
    { IA32_MSR_FS_BASE,         VMCS_GUEST_FS_BASE },
    { IA32_MSR_GS_BASE,         VMCS_GUEST_GS_BASE }
};


/*------------------------------Forward Declarations--------------------------*/

static MSR_VMEXIT_DESCRIPTOR *msr_descriptor_lookup(LIST_ELEMENT *msr_list, MSR_ID msr_id);
/*static*/ VMM_STATUS msr_vmexit_bits_config(UINT8 *p_bitmap, MSR_ID msr_id, RW_ACCESS access, BOOLEAN set);
static BOOLEAN    msr_common_vmexit_handler(GUEST_CPU_HANDLE gcpu, RW_ACCESS access, UINT64 *msr_value);
static BOOLEAN    msr_unsupported_access_handler(GUEST_CPU_HANDLE gcpu, MSR_ID msr_id, UINT64 *value, void *context);
static VMEXIT_HANDLING_STATUS vmexit_msr_read(GUEST_CPU_HANDLE  gcpu);
static VMEXIT_HANDLING_STATUS vmexit_msr_write(GUEST_CPU_HANDLE gcpu);
static BOOLEAN    msr_efer_write_handler(GUEST_CPU_HANDLE gcpu, MSR_ID msr_id, UINT64 *msr_value, void *context);
static BOOLEAN    msr_efer_read_handler(GUEST_CPU_HANDLE gcpu, MSR_ID msr_id, UINT64 *msr_value, void *context);
static BOOLEAN    msr_pat_read_handler(GUEST_CPU_HANDLE gcpu, MSR_ID msr_id, UINT64 *msr_value, void *context);
static BOOLEAN    msr_pat_write_handler(GUEST_CPU_HANDLE gcpu, MSR_ID msr_id, UINT64 *msr_value, void *context);
static BOOLEAN    msr_lapic_base_write_handler(GUEST_CPU_HANDLE gcpu, MSR_ID msr_id, UINT64 *msr_value, void *context);
static BOOLEAN    msr_feature_control_read_handler(GUEST_CPU_HANDLE gcpu, MSR_ID msr_id, UINT64 *msr_value, void *context);
static BOOLEAN    msr_feature_control_write_handler(GUEST_CPU_HANDLE gcpu, MSR_ID msr_id, UINT64 *msr_value, void *context);
static BOOLEAN    msr_mtrr_write_handler(GUEST_CPU_HANDLE gcpu, MSR_ID msr_id, UINT64 *msr_value, void *context);
static BOOLEAN    msr_vmcs_resident_default_handler(GUEST_CPU_HANDLE gcpu, MSR_ID msr_id, RW_ACCESS access, UINT64 *msr_value);
static BOOLEAN 	  msr_misc_enable_write_handler(GUEST_CPU_HANDLE gcpu, MSR_ID msr_id, UINT64 *msr_value, void *context);



/*--------------------------------Code Starts Here----------------------------*/

/*----------------------------------------------------------------------------*
*  FUNCTION : msr_vmexit_on_all()
*  PURPOSE  : Turns VMEXIT on all ON/OFF
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu
*           : BOOLEAN enable
*  RETURNS  : none, must succeed.
*----------------------------------------------------------------------------*/
void msr_vmexit_on_all(GUEST_CPU_HANDLE gcpu, BOOLEAN enable)
{
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS exec_controls_mask;
    VMEXIT_CONTROL                        vmexit_request;

    VMM_ASSERT(gcpu);

    VMM_LOG(mask_uvmm, level_trace,"[msr] VMEXIT on %s\n", enable ? "all" : "bitmap");

    exec_controls_mask.Uint32             = 0;
    exec_controls_mask.Bits.UseMsrBitmaps = 1;

    vmm_memset(&vmexit_request, 0 , sizeof(vmexit_request));
    vmexit_request.proc_ctrls.bit_request = enable ? 0 : UINT64_ALL_ONES;
    vmexit_request.proc_ctrls.bit_mask = exec_controls_mask.Uint32;

    gcpu_control_setup( gcpu, &vmexit_request );
}

// VS2010 generates bad code for BITARRAY_SET() in release mode
// workaround by turning off optimization
#pragma optimize("",off)
VMM_STATUS msr_vmexit_bits_config(
    UINT8       *p_bitmap,
    MSR_ID      msr_id,
    RW_ACCESS   access, // read or write
    BOOLEAN     set)
{
    UINT8       *p_bitarray;
    MSR_ID      bitno;
    RW_ACCESS   access_index;

    for (access_index = WRITE_ACCESS; access_index <= READ_ACCESS; ++access_index)
    {
        if (access_index & access)  // is access of iterest ?
        {
            if (msr_id <= MSR_LOW_LAST)
            {
                bitno = msr_id;
                p_bitarray = READ_ACCESS == access_index ?
                    &p_bitmap[MSR_READ_LOW_OFFSET] :
                    &p_bitmap[MSR_WRITE_LOW_OFFSET];
            }
            else if (MSR_HIGH_FIRST <= msr_id && msr_id <= MSR_HIGH_LAST)
            {
                bitno = msr_id - MSR_HIGH_FIRST;
                p_bitarray = READ_ACCESS == access_index ?
                    &p_bitmap[MSR_READ_HIGH_OFFSET] :
                    &p_bitmap[MSR_WRITE_HIGH_OFFSET];
            }
            else
            {
                VMM_ASSERT(0);  // wrong MSR ID
                return VMM_ERROR;
            }

            if (set)
            {
                BITARRAY_SET(p_bitarray, bitno);
            }
            else
            {
                BITARRAY_CLR(p_bitarray, bitno);
            }
        }


    }
    return VMM_OK;
}
#pragma optimize("",on)


MSR_VMEXIT_DESCRIPTOR * msr_descriptor_lookup(
    LIST_ELEMENT   *msr_list,
    MSR_ID          msr_id)
{
    MSR_VMEXIT_DESCRIPTOR   *p_msr_desc;
    LIST_ELEMENT            *list_iterator;

    LIST_FOR_EACH(msr_list, list_iterator)
    {
        p_msr_desc = LIST_ENTRY(list_iterator, MSR_VMEXIT_DESCRIPTOR, msr_list);
        if (p_msr_desc->msr_id == msr_id)
        {
            return p_msr_desc;  // found
        }
    }
    return NULL;
}

static
void msr_vmexit_register_mtrr_accesses_handler(GUEST_HANDLE guest) {

    UINT32 i,msr_addr;

    msr_vmexit_handler_register(
        guest,
        IA32_MTRRCAP_ADDR,
        msr_mtrr_write_handler,
        WRITE_ACCESS,
        NULL);

    msr_vmexit_handler_register(
        guest,
        IA32_MTRR_DEF_TYPE_ADDR,
        msr_mtrr_write_handler,
        WRITE_ACCESS,
        NULL);

    msr_vmexit_handler_register(
        guest,
        IA32_MTRR_FIX64K_00000_ADDR,
        msr_mtrr_write_handler,
        WRITE_ACCESS,
        NULL);

    msr_vmexit_handler_register(
        guest,
        IA32_MTRR_FIX16K_80000_ADDR,
        msr_mtrr_write_handler,
        WRITE_ACCESS,
        NULL);

    msr_vmexit_handler_register(
        guest,
        IA32_MTRR_FIX16K_A0000_ADDR,
        msr_mtrr_write_handler,
        WRITE_ACCESS,
        NULL);

    msr_vmexit_handler_register(
        guest,
        IA32_MTRR_FIX4K_C0000_ADDR,
        msr_mtrr_write_handler,
        WRITE_ACCESS,
        NULL);

    msr_vmexit_handler_register(
        guest,
        IA32_MTRR_FIX4K_C8000_ADDR,
        msr_mtrr_write_handler,
        WRITE_ACCESS,
        NULL);

    msr_vmexit_handler_register(
        guest,
        IA32_MTRR_FIX4K_D0000_ADDR,
        msr_mtrr_write_handler,
        WRITE_ACCESS,
        NULL);

    msr_vmexit_handler_register(
        guest,
        IA32_MTRR_FIX4K_D8000_ADDR,
        msr_mtrr_write_handler,
        WRITE_ACCESS,
        NULL);

    msr_vmexit_handler_register(
        guest,
        IA32_MTRR_FIX4K_E0000_ADDR,
        msr_mtrr_write_handler,
        WRITE_ACCESS,
        NULL);

    msr_vmexit_handler_register(
        guest,
        IA32_MTRR_FIX4K_E8000_ADDR,
        msr_mtrr_write_handler,
        WRITE_ACCESS,
        NULL);

    msr_vmexit_handler_register(
        guest,
        IA32_MTRR_FIX4K_F0000_ADDR,
        msr_mtrr_write_handler,
        WRITE_ACCESS,
        NULL);

    msr_vmexit_handler_register(
        guest,
        IA32_MTRR_FIX4K_F8000_ADDR,
        msr_mtrr_write_handler,
        WRITE_ACCESS,
        NULL);

    // all other MTRR registers are sequential
    for (msr_addr = IA32_MTRR_PHYSBASE0_ADDR, i=0; i < mtrrs_abstraction_get_num_of_variable_range_regs(); msr_addr += 2, i++) {

    	if(msr_addr > IA32_MTRR_MAX_PHYSMASK_ADDR ) {
    		VMM_LOG(mask_uvmm, level_error, "Error: No. of Variable MTRRs is incorrect\n");
    		VMM_DEADLOOP();
    	}

    	/* Register all MTRR PHYSBASE */
    	msr_vmexit_handler_register(
            guest,
            msr_addr,
            msr_mtrr_write_handler,
            WRITE_ACCESS,
            NULL);

    	/* Register all MTRR PHYSMASK*/
        msr_vmexit_handler_register(
            guest,
            msr_addr + 1,
            msr_mtrr_write_handler,
            WRITE_ACCESS,
            NULL);

    }
}

/*----------------------------------------------------------------------------*
*  FUNCTION : msr_vmexit_guest_setup()
*  PURPOSE  : Allocates structures for MSR virtualization
*           : Must be called prior any other function from the package on this gcpu,
*           : but after gcpu VMCS was loaded
*  ARGUMENTS: GUEST_HANDLE guest
*  RETURNS  : none, must succeed.
*----------------------------------------------------------------------------*/
void msr_vmexit_guest_setup(GUEST_HANDLE guest)
{
    MSR_VMEXIT_CONTROL *p_msr_ctrl;
    MSR_ID msr_id;

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(guest);
    VMM_LOG(mask_uvmm, level_trace,"[msr] Setup for Guest\n");

    p_msr_ctrl = guest_get_msr_control(guest);

    // allocate zero-filled 4K-page to store MSR VMEXIT bitmap
    p_msr_ctrl->msr_bitmap = vmm_memory_alloc(PAGE_4KB_SIZE);
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(p_msr_ctrl->msr_bitmap);

    vmexit_install_handler(guest_get_id(guest), vmexit_msr_read,  Ia32VmxExitBasicReasonMsrRead);
    vmexit_install_handler(guest_get_id(guest), vmexit_msr_write, Ia32VmxExitBasicReasonMsrWrite);

    for (msr_id = IA32_MSR_VMX_FIRST; msr_id <= IA32_MSR_VMX_LAST; ++msr_id)
    {
        msr_guest_access_inhibit(guest, msr_id);
    }

	if( !is_unrestricted_guest_supported() ) 
	{	
		msr_vmexit_handler_register(
			guest,
			IA32_MSR_EFER,
			msr_efer_write_handler,
			WRITE_ACCESS,
			NULL);
	

		msr_vmexit_handler_register(
			guest,
			IA32_MSR_EFER,
			msr_efer_read_handler,
			READ_ACCESS,
			NULL);
	}

    msr_vmexit_handler_register(
        guest,
        IA32_MSR_APIC_BASE,
        msr_lapic_base_write_handler,
        WRITE_ACCESS,
        NULL);

    msr_vmexit_handler_register(
        guest,
        IA32_MSR_FEATURE_CONTROL,
        msr_feature_control_read_handler,
        READ_ACCESS,
        NULL);

    msr_vmexit_handler_register(
        guest,
        IA32_MSR_FEATURE_CONTROL,
        msr_feature_control_write_handler,
        WRITE_ACCESS,
        NULL);

    msr_vmexit_handler_register(
        guest,
        IA32_MSR_MISC_ENABLE,
        msr_misc_enable_write_handler,
        WRITE_ACCESS,
        NULL);
    
    msr_vmexit_register_mtrr_accesses_handler(guest);
}


/*----------------------------------------------------------------------------*
*  FUNCTION : msr_vmexit_activate()
*  PURPOSE  : Register MSR related structures with HW (VMCS)
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu
*  RETURNS  : none, must succeed.
*----------------------------------------------------------------------------*/
void msr_vmexit_activate(GUEST_CPU_HANDLE gcpu)
{
    VMCS_OBJECT                          *vmcs = gcpu_get_vmcs(gcpu);
    GUEST_HANDLE                          guest;
    MSR_VMEXIT_CONTROL                   *p_msr_ctrl;
    UINT64 msr_bitmap;

    VMM_ASSERT(gcpu);

    VMM_LOG(mask_uvmm, level_trace,"[msr] Activated on GCPU\n");

    guest = gcpu_guest_handle(gcpu);
    VMM_ASSERT(guest);
    p_msr_ctrl = guest_get_msr_control(guest);
    msr_bitmap= (UINT64) p_msr_ctrl->msr_bitmap;

    msr_vmexit_on_all(gcpu, FALSE);

    if (NULL != p_msr_ctrl->msr_bitmap)
    {
    	hmm_hva_to_hpa(msr_bitmap, &msr_bitmap);
        vmcs_write(vmcs, VMCS_MSR_BITMAP_ADDRESS, msr_bitmap);
    }
}


/*----------------------------------------------------------------------------*
*  FUNCTION : msr_vmexit_handler_register()
*  PURPOSE  : Register specific MSR handler with VMEXIT
*  ARGUMENTS: GUEST_HANDLE        guest
*           : MSR_ID              msr_id
*           : MSR_ACCESS_HANDLER  msr_handler,
*           : RW_ACCESS           access
*  RETURNS  : VMM_OK if succeeded
*----------------------------------------------------------------------------*/
VMM_STATUS msr_vmexit_handler_register(
    GUEST_HANDLE        guest,
    MSR_ID              msr_id,
    MSR_ACCESS_HANDLER  msr_handler,
    RW_ACCESS           access,
    void               *context)
{
    MSR_VMEXIT_DESCRIPTOR *p_desc;
    VMM_STATUS status = VMM_OK;
    MSR_VMEXIT_CONTROL *p_msr_ctrl = guest_get_msr_control(guest);

    // check first if it already registered
    p_desc = msr_descriptor_lookup(p_msr_ctrl->msr_list, msr_id);

    if (NULL == p_desc)
    {
        // allocate new descriptor and chain it to the list
        p_desc = vmm_malloc(sizeof(*p_desc));
        if (NULL != p_desc)
        {
            vmm_memset(p_desc, 0, sizeof(*p_desc));
            list_add(p_msr_ctrl->msr_list, &p_desc->msr_list);
        }
    }
    else
    {
    	VMM_LOG(mask_uvmm, level_trace,"MSR(%p) handler already registered. Update...\n", msr_id);
    }

    if (NULL != p_desc)
    {
        status = msr_vmexit_bits_config(p_msr_ctrl->msr_bitmap, msr_id, access, TRUE);
        if (VMM_OK == status)
        {
            p_desc->msr_id      = msr_id;
            if (access & WRITE_ACCESS) p_desc->msr_write_handler = msr_handler;
            if (access & READ_ACCESS)  p_desc->msr_read_handler = msr_handler;
            p_desc->msr_context = context;
			// VMM_LOG(mask_uvmm, level_trace,"%s: [msr] Handler(%P) Registered\n", __FUNCTION__, msr_id);
        }
        else
        {
            VMM_LOG(mask_uvmm, level_trace,"MSR(%p) handler registration failed to bad ID\n", msr_id);
        }
    }
    else
    {
        status = VMM_ERROR;
        VMM_LOG(mask_uvmm, level_trace,"MSR(%p) handler registration failed due to lack of space\n", msr_id);
    }
    return status;
}


/*----------------------------------------------------------------------------*
*  FUNCTION : msr_vmexit_handler_unregister()
*  PURPOSE  : Unregister specific MSR VMEXIT handler
*  ARGUMENTS: GUEST_HANDLE  guest
*           : MSR_ID        msr_id
*  RETURNS  : VMM_OK if succeeded, VMM_ERROR if no descriptor for MSR
*----------------------------------------------------------------------------*/
VMM_STATUS msr_vmexit_handler_unregister(
    GUEST_HANDLE    guest,
    MSR_ID          msr_id,
    RW_ACCESS       access)
{
    MSR_VMEXIT_DESCRIPTOR *p_desc;
    VMM_STATUS status = VMM_OK;
    MSR_VMEXIT_CONTROL *p_msr_ctrl = guest_get_msr_control(guest);

    p_desc = msr_descriptor_lookup(p_msr_ctrl->msr_list, msr_id);

    if (NULL == p_desc)
    {
        status = VMM_ERROR;
        VMM_LOG(mask_uvmm, level_trace,"MSR(%p) handler is not registered\n", msr_id);
    }
    else
    {
        msr_vmexit_bits_config(
            p_msr_ctrl->msr_bitmap,
            msr_id,
            access,
            FALSE);

        if (access & WRITE_ACCESS) p_desc->msr_write_handler = NULL;
        if (access & READ_ACCESS)  p_desc->msr_read_handler = NULL;

        if (NULL == p_desc->msr_write_handler &&
            NULL == p_desc->msr_read_handler)
        {
            list_remove(&p_desc->msr_list);
            vmm_mfree(p_desc);
        }
    }
    return status;
}

/*----------------------------------------------------------------------------*
*  FUNCTION : vmexit_msr_read()
*  PURPOSE  : Read handler which calls upon VMEXITs resulting from MSR read access
*           : Read MSR value from HW and if OK, stores the result in EDX:EAX
*  ARGUMENTS: GUEST_CPU_HANDLE gcp
*  RETURNS  :
*----------------------------------------------------------------------------*/
VMEXIT_HANDLING_STATUS vmexit_msr_read(GUEST_CPU_HANDLE gcpu)
{
    UINT64 msr_value = 0;
    MSR_ID msr_id = (MSR_ID) gcpu_get_native_gp_reg(gcpu, IA32_REG_RCX);

    /* hypervisor synthenic MSR is not hardware MSR, inject GP to guest */
	if( (msr_id >= HYPER_V_MSR_MIN) && (msr_id <= HYPER_V_MSR_MAX))
	{
		gcpu_inject_gp0(gcpu);
		return VMEXIT_HANDLED;
	}

    if (TRUE == msr_common_vmexit_handler(gcpu, READ_ACCESS, &msr_value))
    {
        // write back to the guest. store MSR value in EDX:EAX
        gcpu_set_native_gp_reg(gcpu, IA32_REG_RDX, msr_value >> 32);
        gcpu_set_native_gp_reg(gcpu, IA32_REG_RAX, msr_value & LOW_BITS_32_MASK);
    }
    return VMEXIT_HANDLED;
}

/*----------------------------------------------------------------------------*
*  FUNCTION : vmexit_msr_write()
*  PURPOSE  : Write handler which calls upon VMEXITs resulting from MSR write access
*           : Read MSR value from guest EDX:EAX and call registered write handler
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu
*  RETURNS  :
*----------------------------------------------------------------------------*/
VMEXIT_HANDLING_STATUS vmexit_msr_write(GUEST_CPU_HANDLE gcpu)
{
    UINT64 msr_value;
    MSR_ID msr_id = (MSR_ID) gcpu_get_native_gp_reg(gcpu, IA32_REG_RCX);

    /* hypervisor synthenic MSR is not hardware MSR, inject GP to guest */
 	if( (msr_id >= HYPER_V_MSR_MIN) && (msr_id <= HYPER_V_MSR_MAX))
	{
		gcpu_inject_gp0(gcpu);
		return VMEXIT_HANDLED;
	}

    msr_value = (gcpu_get_native_gp_reg(gcpu, IA32_REG_RDX) << 32);
    msr_value |= gcpu_get_native_gp_reg(gcpu, IA32_REG_RAX) & LOW_BITS_32_MASK;

    msr_common_vmexit_handler(gcpu, WRITE_ACCESS, &msr_value);
    return VMEXIT_HANDLED;
}

/*----------------------------------------------------------------------------*
*  FUNCTION : msr_common_vmexit_handler()
*  PURPOSE  : If MSR handler is registered, call it, otherwise executes default
*           : MSR handler. If MSR R/W instruction was executed successfully
*           : from the Guest point of view, Guest IP is moved forward on instruction
*           : length, otherwise exception is injected into Guest CPU.
*  ARGUMENTS: GUEST_CPU_HANDLE    gcpu
*           : RW_ACCESS           access
*  RETURNS  : TRUE if instruction was executed, FALSE otherwise (fault occured)
*----------------------------------------------------------------------------*/
BOOLEAN msr_common_vmexit_handler(
    GUEST_CPU_HANDLE    gcpu,
    RW_ACCESS           access,
    UINT64             *msr_value)
{
    MSR_ID msr_id = (MSR_ID) gcpu_get_native_gp_reg(gcpu, IA32_REG_RCX);
    GUEST_HANDLE guest = NULL;
    MSR_VMEXIT_CONTROL *p_msr_ctrl = NULL;
    MSR_VMEXIT_DESCRIPTOR *msr_descriptor = NULL;
    BOOLEAN instruction_was_executed = FALSE;
    MSR_ACCESS_HANDLER  msr_handler = NULL;

    guest = gcpu_guest_handle(gcpu);
    VMM_ASSERT(guest);
    p_msr_ctrl = guest_get_msr_control(guest);
    VMM_ASSERT(p_msr_ctrl);
    
    msr_descriptor = msr_descriptor_lookup(p_msr_ctrl->msr_list, msr_id);

    if (NULL != msr_descriptor)
    {
		// VMM_LOG(mask_uvmm, level_trace,"%s: msr_descriptor is NOT NULL.\n", __FUNCTION__);
        if (access & WRITE_ACCESS)
            msr_handler = msr_descriptor->msr_write_handler;
        else if (access & READ_ACCESS)
            msr_handler = msr_descriptor->msr_read_handler;
    }

    if (NULL == msr_handler)
    {
		// VMM_LOG(mask_uvmm, level_trace,"%s: msr_handler is NULL.\n", __FUNCTION__);
        instruction_was_executed =
            msr_vmcs_resident_default_handler(gcpu, msr_id, access, msr_value) ||
            msr_trial_access(gcpu, msr_id, access, msr_value);
    }
    else
    {
		// VMM_LOG(mask_uvmm, level_trace,"%s: msr_handler is NOT NULL.\n", __FUNCTION__);
        instruction_was_executed =
            msr_handler(gcpu, msr_id, msr_value, msr_descriptor->msr_context);
    }

    if (TRUE == instruction_was_executed)
    {
        gcpu_skip_guest_instruction(gcpu);
    }
    return instruction_was_executed;
}


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
    UINT64              *msr_value)
{
    BOOLEAN     msr_implemented;
    VECTOR_ID   fault_vector= 0;   // just to shut up the warning
    UINT32      error_code  = 0;   // just to shut up the warning
    VMCS_OBJECT *vmcs       = gcpu_get_vmcs(gcpu);


    switch (access)
    {
    case READ_ACCESS:
        msr_implemented = hw_rdmsr_safe(msr_id, msr_value, &fault_vector, &error_code);
        break;
    case WRITE_ACCESS:
        msr_implemented = hw_wrmsr_safe(msr_id, *msr_value, &fault_vector, &error_code);
        break;
    default:
        VMM_ASSERT(0);  // should not be here
        return FALSE;
    }

    if (FALSE == msr_implemented)
    {
        // inject GP into guest
        VMENTER_EVENT  exception;
        UINT16 inst_length = (UINT16) vmcs_read(vmcs, VMCS_EXIT_INFO_INSTRUCTION_LENGTH);

        vmm_memset(&exception, 0, sizeof(exception));
        exception.interrupt_info.Bits.Valid           = 1;
        exception.interrupt_info.Bits.Vector          = fault_vector;
        exception.interrupt_info.Bits.InterruptType   = VmEnterInterruptTypeHardwareException;
        exception.interrupt_info.Bits.DeliverCode     = 1;
        exception.instruction_length = inst_length;
        exception.error_code = (ADDRESS) error_code;

        gcpu_inject_event(gcpu, &exception);
    }

    return msr_implemented;
}


BOOLEAN msr_vmcs_resident_default_handler(
    GUEST_CPU_HANDLE    gcpu,
    MSR_ID              msr_id,
    RW_ACCESS           access,
    UINT64              *msr_value)
{
    VMCS_OBJECT *vmcs = gcpu_get_vmcs(gcpu);
    VMCS_FIELD  vmcs_field_id = VMCS_FIELD_COUNT;    // invalid
    BOOLEAN found = FALSE;
    unsigned int i;

    // check if it is MSR which resides in Guest part of VMCS
    for (i = 0; i < NELEMENTS(vmcs_resident_guest_msrs); ++i)
    {
        if (vmcs_resident_guest_msrs[i].msr_id == msr_id)
        {
            VM_ENTRY_CONTROLS   vmenter_controls;

            if (IA32_MSR_DEBUGCTL == msr_id)
            {
                vmenter_controls.Uint32 = (UINT32)vmcs_read(vmcs, VMCS_ENTER_CONTROL_VECTOR);
                if (vmenter_controls.Bits.LoadDebugControls)
                {
                    found = TRUE;
                }
            }
            else if (IA32_MSR_PERF_GLOBAL_CTRL == msr_id)
            {
                vmenter_controls.Uint32 = (UINT32)vmcs_read(vmcs, VMCS_ENTER_CONTROL_VECTOR);
                if (vmenter_controls.Bits.Load_IA32_PERF_GLOBAL_CTRL &&
                    vmcs_field_is_supported(vmcs_resident_guest_msrs[i].vmcs_field_id))
                {
                    found = TRUE;
                }
            }
            else
            {
                found = TRUE;
            }
            break;
        }
    }

    if (found)
    {
        vmcs_field_id = vmcs_resident_guest_msrs[i].vmcs_field_id;

        switch (access)
        {
        case READ_ACCESS:
            *msr_value = vmcs_read(vmcs, vmcs_field_id);
            break;
        case WRITE_ACCESS:
            vmcs_write(vmcs, vmcs_field_id, *msr_value);
            break;
        default:
            VMM_DEADLOOP();  // should not be here
            break;
        }
    }

    return found;
}




/*----------------------------------------------------------------------------*
*  FUNCTION : msr_unsupported_access_handler()
*  PURPOSE  : Inject General Protection /fault event into the GCPU
*           : Used for both read and write accesses
*  ARGUMENTS: GUEST_CPU_HANDLE  gcpu
*           : MSR_ID            msr_id - not used
*           : UINT64           *value - not used
*  RETURNS  : FALSE, which means that instruction caused GP fault.
*----------------------------------------------------------------------------*/
#pragma warning( push )
#pragma warning (disable : 4100)  // Supress warnings about unreferenced formal parameter

BOOLEAN msr_unsupported_access_handler(
    GUEST_CPU_HANDLE    gcpu,
    MSR_ID              msr_id UNUSED,
    UINT64             *value  UNUSED,
    void               *context UNUSED)
{
    REPORT_MSR_WRITE_ACCESS_DATA msr_write_access_data;

    msr_write_access_data.msr_id = msr_id;

    // Using write access method for both read/write access here
    if (!report_uvmm_event(UVMM_EVENT_MSR_WRITE_ACCESS, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), &msr_write_access_data))
        return FALSE;

    // inject GP Fault into guest
    gcpu_inject_gp0(gcpu);
    return FALSE;
}
#pragma warning( pop )


/*----------------------------------------------------------------------------*
*  FUNCTION : msr_efer_update_is_gpf0()
*  PURPOSE  : Handle guest access to EFER. Update guest visible value.
*  ARGUMENTS: GUEST_CPU_HANDLE  gcpu
*           : MSR_ID            msr_id
*           : UINT64           *msr_value
*  RETURNS  : TRUE, which means that instruction was executed.
*----------------------------------------------------------------------------*/
#pragma warning( push )
#pragma warning (disable : 4100)  // Supress warnings about unreferenced formal parameter

static
BOOLEAN msr_efer_update_is_gpf0(GUEST_CPU_HANDLE    gcpu,
                                UINT64 new_value) {
    IA32_EFER_S efer;
    efer.Uint64 = new_value;

    if (efer.Bits.LME) {
        EM64T_CR4 cr4;
        cr4.Uint64 = gcpu_get_guest_visible_control_reg_layered(gcpu, IA32_CTRL_CR4, VMCS_MERGED);

        if (!cr4.Bits.PAE) {
            return TRUE;
        }
    }

    return FALSE;
}

BOOLEAN msr_efer_write_handler(
    GUEST_CPU_HANDLE    gcpu,
    MSR_ID              msr_id,
    UINT64             *msr_value,
    void               *context UNUSED)
{
    EVENT_GCPU_GUEST_MSR_WRITE_DATA data;
    RAISE_EVENT_RETVAL event_retval;
    REPORT_MSR_WRITE_ACCESS_DATA msr_write_access_data;

    VMM_ASSERT(IA32_MSR_EFER == msr_id);

    msr_write_access_data.msr_id = msr_id;
    if (!report_uvmm_event(UVMM_EVENT_MSR_WRITE_ACCESS, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), &msr_write_access_data))
        return FALSE;

   if (msr_efer_update_is_gpf0(gcpu, *msr_value)) {
        VMM_LOG(mask_uvmm, level_trace,"%s: EFER update should have caused GPF0 in native mode\n", __FUNCTION__);
        VMM_LOG(mask_uvmm, level_trace,"%s: Changing vmexit to GP is not implemented yet\n", __FUNCTION__);
        VMM_DEADLOOP();
    }

    gcpu_set_msr_reg(gcpu, IA32_VMM_MSR_EFER, *msr_value);

    vmm_memset(&data, 0, sizeof(data));
    data.new_guest_visible_value = *msr_value;
    data.msr_index = msr_id;
    event_retval = event_raise( EVENT_GCPU_AFTER_EFER_MSR_WRITE, gcpu, &data );
    VMM_ASSERT(event_retval != EVENT_NOT_HANDLED);
    return TRUE;
}

BOOLEAN msr_efer_read_handler(
    GUEST_CPU_HANDLE    gcpu,
    MSR_ID              msr_id UNUSED,
    UINT64             *msr_value,
    void               *context UNUSED)
{
////    VMM_LOG(mask_uvmm, level_trace,"ERROR: VMEXIT on Read Access to IA32_MSR_EFER occured\n");
////    VMM_DEADLOOP();
#ifdef USE_MTF_FOR_CR_MSR_AS_WELL
    //if( is_unrestricted_guest_supported() )
    {
        report_uvmm_event(UVMM_EVENT_MSR_READ_ACCESS, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), NULL);
        return FALSE;
    }
#else
    *msr_value = gcpu_get_msr_reg(gcpu, IA32_VMM_MSR_EFER);
    return TRUE;
#endif
}

#pragma warning( pop )

#pragma warning( push )
#pragma warning (disable : 4100)  // Supress warnings about unreferenced formal parameter

BOOLEAN msr_pat_write_handler(
    GUEST_CPU_HANDLE    gcpu,
    MSR_ID              msr_id,
    UINT64             *msr_value,
    void               *context UNUSED)
{
    REPORT_MSR_WRITE_ACCESS_DATA msr_write_access_data;

    VMM_ASSERT(IA32_MSR_PAT== msr_id);
    msr_write_access_data.msr_id = msr_id;
    if (!report_uvmm_event(UVMM_EVENT_MSR_WRITE_ACCESS, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), &msr_write_access_data))
        return FALSE;

    gcpu_set_msr_reg(gcpu, IA32_VMM_MSR_PAT, *msr_value);
    return TRUE;
}

BOOLEAN msr_pat_read_handler(
    GUEST_CPU_HANDLE    gcpu,
    MSR_ID              msr_id,
    UINT64             *msr_value,
    void               *context UNUSED)
{
    VMM_ASSERT(IA32_MSR_PAT== msr_id);

    *msr_value = gcpu_get_msr_reg(gcpu, IA32_VMM_MSR_PAT);
    return TRUE;
}


static
BOOLEAN msr_mtrr_write_handler(
    GUEST_CPU_HANDLE    gcpu,
    MSR_ID              msr_id,
    UINT64             *msr_value,
    void               *context UNUSED)
{
    EVENT_GCPU_GUEST_MSR_WRITE_DATA data;
    RAISE_EVENT_RETVAL event_retval;
    REPORT_MSR_WRITE_ACCESS_DATA msr_write_access_data;

    VMM_ASSERT(msr_id != IA32_MTRRCAP_ADDR); // IA32_MTRRCAP_ADDR is read only mtrr
    msr_write_access_data.msr_id = msr_id;
    if (!report_uvmm_event(UVMM_EVENT_MSR_WRITE_ACCESS, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), &msr_write_access_data))
        return FALSE;

    hw_write_msr(msr_id, *msr_value);
    mtrrs_abstraction_track_mtrr_update(msr_id, *msr_value);

    vmm_memset(&data, 0, sizeof(data));
    data.new_guest_visible_value = *msr_value;
    data.msr_index = msr_id;

    event_retval = event_raise( EVENT_GCPU_AFTER_MTRR_MSR_WRITE, gcpu, &data );
    VMM_ASSERT(event_retval != EVENT_NOT_HANDLED);

    return TRUE;
}

/*----------------------------------------------------------------------------*
*  FUNCTION : msr_lapic_base_write_handler()
*  PURPOSE  : Track Guest writes to Loacal APIC Base Register
*  ARGUMENTS: GUEST_CPU_HANDLE  gcpu
*           : MSR_ID            msr_id
*           : UINT64           *msr_value
*  RETURNS  : TRUE, which means that instruction was executed.
*----------------------------------------------------------------------------*/
BOOLEAN msr_lapic_base_write_handler(
    GUEST_CPU_HANDLE    gcpu,
    MSR_ID              msr_id,
    UINT64             *msr_value,
    void               *context UNUSED)
{
    REPORT_MSR_WRITE_ACCESS_DATA msr_write_access_data;

    VMM_ASSERT(IA32_MSR_APIC_BASE == msr_id);
    msr_write_access_data.msr_id = msr_id;
    if (!report_uvmm_event(UVMM_EVENT_MSR_WRITE_ACCESS, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), &msr_write_access_data))
        return FALSE;

	if( !validate_APIC_BASE_change(*msr_value))
	{
		gcpu_inject_gp0(gcpu);
		return FALSE;
	}

    hw_write_msr(IA32_MSR_APIC_BASE, *msr_value);
    local_apic_setup_changed();
    return TRUE;
}


/*----------------------------------------------------------------------------*
*  FUNCTION : msr_feature_control_read_handler()
*  PURPOSE  : Handles MSR reads on FEATURE_CONTROL MSR (0x3A). 
*             Virtualizes VMX enable bit(bit 2).
*  ARGUMENTS: GUEST_CPU_HANDLE  gcpu
*           : MSR_ID            msr_id
*           : UINT64           *msr_value
*  RETURNS  : TRUE, which means that instruction was executed.
*----------------------------------------------------------------------------*/
BOOLEAN msr_feature_control_read_handler(
	GUEST_CPU_HANDLE	gcpu,
	MSR_ID				msr_id,
	UINT64			   *msr_value,
	void			   *context UNUSED)
{
    VMM_ASSERT(IA32_MSR_FEATURE_CONTROL == msr_id);
    // IA32 spec V2, 5.3,  GETSEC[SENTER]
    // IA32_FEATURE_CONTROL is only available on SMX or VMX enabled processors
    // otherwise, it its treated as reserved.
    VMM_LOG(mask_uvmm, level_trace,"%s: IA32_FEATURE_CONTROL is only available on SMX or VMX enabled processors.\n", __FUNCTION__);
    gcpu_inject_gp0(gcpu);
    return TRUE;
}

/*----------------------------------------------------------------------------*
*  FUNCTION : msr_feature_control_write_handler()
*  PURPOSE  : Handles writes to FEATURE_CONTROL MSR (0x3A). 
*             Induces GP(0) exception.
*  ARGUMENTS: GUEST_CPU_HANDLE  gcpu
*           : MSR_ID            msr_id
*           : UINT64           *msr_value
*  RETURNS  : TRUE, which means that instruction was executed.
*----------------------------------------------------------------------------*/

BOOLEAN msr_feature_control_write_handler(
	GUEST_CPU_HANDLE	gcpu,
	MSR_ID				msr_id,
	UINT64			   *msr_value,
	void			   *context UNUSED)
{
    VMM_ASSERT(IA32_MSR_FEATURE_CONTROL == msr_id);
    // IA32 spec V2, 5.3,  GETSEC[SENTER]
    // IA32_FEATURE_CONTROL is only available on SMX or VMX enabled processors
    // otherwise, it its treated as reserved.
    VMM_LOG(mask_uvmm, level_trace,"%s: IA32_FEATURE_CONTROL is only available on SMX or VMX enabled processors.\n", __FUNCTION__);
    gcpu_inject_gp0(gcpu);
    return TRUE;
}

/*----------------------------------------------------------------------------*
*  FUNCTION : msr_misc_enable_write_handler()
*  PURPOSE  : Handles writes to MISC_ENABLE MSR (0x1A0).
*             Blocks writes to bits that can impact TMSL behavior
*  ARGUMENTS: GUEST_CPU_HANDLE  gcpu
*           : MSR_ID            msr_id
*           : UINT64           *msr_value
*  RETURNS  : TRUE, which means that instruction was executed.
*----------------------------------------------------------------------------*/

BOOLEAN msr_misc_enable_write_handler(
	GUEST_CPU_HANDLE	gcpu,
	MSR_ID				msr_id,
	UINT64			   *msr_value,
	void			   *context UNUSED)
{
    REPORT_MSR_WRITE_ACCESS_DATA msr_write_access_data;

    VMM_ASSERT(IA32_MSR_MISC_ENABLE == msr_id);

    msr_write_access_data.msr_id = msr_id;
    if (!report_uvmm_event(UVMM_EVENT_MSR_WRITE_ACCESS, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), &msr_write_access_data))
    	return FALSE;

    BIT_CLR64(*msr_value, 22);   //Limit CPUID MAXVAL

    hw_write_msr(IA32_MSR_MISC_ENABLE, *msr_value);

    return TRUE;
}

#pragma warning( pop )

/*----------------------------------------------------------------------------*
*  FUNCTION : msr_guest_access_inhibit()
*  PURPOSE  : Install VMEXIT handler which prevents access to MSR from the guest
*  ARGUMENTS: GUEST_HANDLE    guest
*           : MSR_ID      msr_id
*  RETURNS  : VMM_OK if succeeded
*----------------------------------------------------------------------------*/
VMM_STATUS msr_guest_access_inhibit(
    GUEST_HANDLE    guest,
    MSR_ID          msr_id)
{
    return msr_vmexit_handler_register(
                guest,
                msr_id,
                msr_unsupported_access_handler,
                READ_WRITE_ACCESS,
                NULL);
}

#pragma warning( push )
#pragma warning (disable : 4100)  // Supress warnings about unreferenced formal parameter
VMEXIT_HANDLING_STATUS  msr_failed_vmenter_loading_handler(GUEST_CPU_HANDLE gcpu USED_IN_DEBUG_ONLY) {

#ifndef DEBUG
	EM64T_RFLAGS rflags;
	IA32_VMX_VMCS_GUEST_INTERRUPTIBILITY    interruptibility;
#endif

    VMM_LOG(mask_uvmm, level_trace,"%s: VMENTER failed\n", __FUNCTION__);

#ifdef DEBUG
    {
    VMCS_OBJECT* vmcs = vmcs_hierarchy_get_vmcs(gcpu_get_vmcs_hierarchy(gcpu), VMCS_MERGED);
    vmcs_print_vmenter_msr_load_list(vmcs);
    }
    VMM_DEADLOOP();
#else
	vmm_deadloop_internal(VMEXIT_MSR_C, __LINE__, gcpu);

	// clear interrupt flag
	rflags.Uint64 = gcpu_get_gp_reg(gcpu, IA32_REG_RFLAGS);
	rflags.Bits.IFL = 0;
	gcpu_set_gp_reg(gcpu, IA32_REG_RFLAGS, rflags.Uint64);

	interruptibility.Uint32 = gcpu_get_interruptibility_state(gcpu);
	interruptibility.Bits.BlockNextInstruction = 0;
	gcpu_set_interruptibility_state(gcpu, interruptibility.Uint32);

	gcpu_inject_gp0(gcpu);
	gcpu_resume(gcpu);
#endif

    return VMEXIT_NOT_HANDLED;
}
#pragma warning( pop )

BOOLEAN vmexit_register_unregister_for_efer(
    GUEST_HANDLE    guest,
    MSR_ID          msr_id,
    RW_ACCESS       access,
	BOOLEAN			reg_dereg)
{

	if( !is_unrestricted_guest_supported() )
		return FALSE;

	if ( (msr_id == IA32_MSR_EFER) && reg_dereg )
		if ( access == WRITE_ACCESS )
		{
			msr_vmexit_handler_register(
				guest,
				IA32_MSR_EFER,
				msr_efer_write_handler,
				WRITE_ACCESS,
				NULL);
			return TRUE;
		}
		else
		{
			msr_vmexit_handler_register(
				guest,
				IA32_MSR_EFER,
				msr_efer_read_handler,
				READ_ACCESS,
				NULL);
			return TRUE;
		}

	if ( (msr_id == IA32_MSR_EFER) && !reg_dereg )
	{
		msr_vmexit_handler_unregister(
			guest,
			msr_id,
			access);
		return TRUE;
	}

	return FALSE;
}
