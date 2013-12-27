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

/****************************************************************************
* INTEL CONFIDENTIAL
* Copyright 2001-2013 Intel Corporation All Rights Reserved.
*
* The source code contained or described herein and all documents related to
* the source code ("Material") are owned by Intel Corporation or its
* suppliers or licensors.  Title to the Material remains with Intel
* Corporation or its suppliers and licensors.  The Material contains trade
* secrets and proprietary and confidential information of Intel or its
* suppliers and licensors.  The Material is protected by worldwide copyright
* and trade secret laws and treaty provisions.  No part of the Material may
* be used, copied, reproduced, modified, published, uploaded, posted,
* transmitted, distributed, or disclosed in any way without Intel's prior
* express written permission.
*
* No license under any patent, copyright, trade secret or other intellectual
* property right is granted to or conferred upon you by disclosure or
* delivery of the Materials, either expressly, by implication, inducement,
* estoppel or otherwise.  Any license under such intellectual property rights
* must be express and approved by Intel in writing.
****************************************************************************/

#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(VMEXIT_IO_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(VMEXIT_IO_C, __condition)
#include "vmm_defs.h"
#include "vmm_dbg.h"
#include "heap.h"
#include "lock.h"
#include "hw_utils.h"
#include "guest.h"
#include "guest_cpu.h"
#include "vmexit.h"
//#include "vmcs_object.h"
#include "vmcs_api.h"
#include "vmx_ctrl_msrs.h"
#include "host_memory_manager_api.h"
#include "gpm_api.h"
#include "vmexit_io.h"
#include "memory_allocator.h"
#include "address.h"
#include "guest_cpu_vmenter_event.h"


/*-----------------Local Types and Macros Definitions----------------*/

#define IO_VMEXIT_MAX_COUNT   64

typedef struct {
    IO_PORT_ID          io_port;    // in fact only 16 bits are meaningful
    UINT16              pad;
    RW_ACCESS           io_access;
    //IO_PORT_OWNER       io_owner; //TODO: resolve owner conflict issues.
    IO_ACCESS_HANDLER   io_handler; //TODO: will use io_tmsl_handler & io_uvmm_handler.
    void*               io_handler_context;
} IO_VMEXIT_DESCRIPTOR;


typedef struct {
    GUEST_ID             guest_id;
    char                 padding[6];
    UINT8               *io_bitmap;
    IO_VMEXIT_DESCRIPTOR io_descriptors[IO_VMEXIT_MAX_COUNT];
    LIST_ELEMENT         list[1];
} GUEST_IO_VMEXIT_CONTROL;

typedef struct {
    LIST_ELEMENT guest_io_vmexit_controls[1];
} IO_VMEXIT_GLOBAL_STATE;


/*-----------------Local Variables----------------*/

static IO_VMEXIT_GLOBAL_STATE io_vmexit_global_state;



/*-----------------Forward Declarations for Local Functions----------------*/

static VMEXIT_HANDLING_STATUS io_vmexit_handler(GUEST_CPU_HANDLE gcpu);
static IO_VMEXIT_DESCRIPTOR * io_port_lookup(GUEST_ID guest_id, IO_PORT_ID port_id);
static IO_VMEXIT_DESCRIPTOR * io_free_port_lookup(GUEST_ID guest_id);
static void io_blocking_read_handler(
    GUEST_CPU_HANDLE gcpu,
    IO_PORT_ID       port_id,
    unsigned         port_size,
    void             *p_value
    );
static void io_blocking_write_handler(
    GUEST_CPU_HANDLE gcpu,
    IO_PORT_ID       port_id,
    unsigned         port_size,
    void             *p_value
    );
static BOOLEAN io_blocking_handler(
    GUEST_CPU_HANDLE gcpu,
    IO_PORT_ID       port_id,
    unsigned         port_size,
    RW_ACCESS        access,
    BOOLEAN          string_intr,  // ins/outs
    BOOLEAN          rep_prefix,   // rep 
    UINT32           rep_count,
    void             *p_value,
    void             *context UNUSED
    );
void io_transparent_read_handler(
    GUEST_CPU_HANDLE    gcpu,
    IO_PORT_ID          port_id,
    unsigned            port_size, // 1, 2, 4
    void               *p_value
    );
void io_transparent_write_handler(
    GUEST_CPU_HANDLE    gcpu,
    IO_PORT_ID          port_id,
    unsigned            port_size, // 1, 2, 4
    void               *p_value
    );
static GUEST_IO_VMEXIT_CONTROL* io_vmexit_find_guest_io_control(
    GUEST_ID guest_id
    );


/*----------------------------------------------------------------------------*
*  FUNCTION : io_vmexit_setup()
*  PURPOSE  : Allocate and initialize IO VMEXITs related data structures,
*           : common for all guests
*  ARGUMENTS: GUEST_ID    num_of_guests
*  RETURNS  : void
*----------------------------------------------------------------------------*/
void io_vmexit_initialize(void)
{
    vmm_memset( &io_vmexit_global_state, 0, sizeof(io_vmexit_global_state) );

    list_init(io_vmexit_global_state.guest_io_vmexit_controls);
}

/*----------------------------------------------------------------------------*
*  FUNCTION : io_vmexit_guest_setup()
*  PURPOSE  : Allocate and initialize IO VMEXITs related data structures for
*           : specific guest
*  ARGUMENTS: GUEST_ID    guest_id
*  RETURNS  : void
*----------------------------------------------------------------------------*/
void io_vmexit_guest_initialize(GUEST_ID guest_id)
{
    GUEST_IO_VMEXIT_CONTROL *io_ctrl;

    VMM_LOG(mask_anonymous, level_trace,"io_vmexit_guest_initialize start\r\n");

    io_ctrl = (GUEST_IO_VMEXIT_CONTROL *) vmm_malloc(sizeof(GUEST_IO_VMEXIT_CONTROL));
    // BEFORE_VMLAUNCH. MALLOC should not fail.
    VMM_ASSERT(io_ctrl);

    io_ctrl->guest_id = guest_id;
    io_ctrl->io_bitmap = vmm_memory_alloc(2 * PAGE_4KB_SIZE);

    // BEFORE_VMLAUNCH
    VMM_ASSERT(io_ctrl->io_bitmap);

    list_add(io_vmexit_global_state.guest_io_vmexit_controls, io_ctrl->list);

    VMM_LOG(mask_anonymous, level_trace,"io_vmexit_guest_initialize end\r\n");

///// TTTTT    vmm_memset(io_ctrl->io_bitmap, 0xFF, 2 * PAGE_4KB_SIZE);

    vmexit_install_handler(guest_id, io_vmexit_handler, Ia32VmxExitBasicReasonIoInstruction);
}

/*----------------------------------------------------------------------------*
*  FUNCTION : io_vmexit_activate()
*  PURPOSE  : enables in HW IO VMEXITs for specific guest on given CPU
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu
*  RETURNS  : void
*----------------------------------------------------------------------------*/
void io_vmexit_activate(GUEST_CPU_HANDLE gcpu)
{
    PROCESSOR_BASED_VM_EXECUTION_CONTROLS exec_controls;
    VMCS_OBJECT             *vmcs    = gcpu_get_vmcs(gcpu);
    GUEST_HANDLE            guest    = gcpu_guest_handle(gcpu);
    GUEST_ID                guest_id = guest_get_id(guest);
    GUEST_IO_VMEXIT_CONTROL *io_ctrl = NULL;
    HPA                     hpa[2];
    int                     i;
    VMEXIT_CONTROL          vmexit_request;

    VMM_LOG(mask_anonymous, level_trace,"io_vmexit_activate start\r\n");
    io_ctrl = io_vmexit_find_guest_io_control(guest_id);

    VMM_ASSERT(io_ctrl);
	
    vmm_memset(&exec_controls, 0, sizeof(exec_controls));
    vmm_memset(&vmexit_request, 0, sizeof(vmexit_request));

    if (NULL == io_ctrl->io_bitmap)
    {
        VMM_LOG(mask_anonymous, level_trace,"IO bitmap for guest %d is not allocated\n", guest_id);
        VMM_DEADLOOP();
        return;
    }

    // first load bitmap addresses, and if OK, enable bitmap based IO VMEXITs
    for (i = 0; i < 2; ++i)
    {
        if (FALSE == hmm_hva_to_hpa((HVA) &io_ctrl->io_bitmap[PAGE_4KB_SIZE * i], &hpa[i]))
        {
            VMM_LOG(mask_anonymous, level_trace,"IO bitmap page for guest %d is invalid\n", guest_id);
            VMM_DEADLOOP();
            return;
        }
        vmcs_write(vmcs, (VMCS_FIELD)(i + VMCS_IO_BITMAP_ADDRESS_A), hpa[i]);
        VMM_LOG(mask_anonymous, level_trace,"IO bitmap page %c : VA=%P  PA=%P\n", 'A'+i, &io_ctrl->io_bitmap[PAGE_4KB_SIZE * i], hpa[i]);
    }

    exec_controls.Bits.ActivateIoBitmaps = 1;

    vmexit_request.proc_ctrls.bit_request = UINT64_ALL_ONES;
    vmexit_request.proc_ctrls.bit_mask = exec_controls.Uint32;
    gcpu_control_setup( gcpu, &vmexit_request );
}

/*----------------------------------------------------------------------------*
*  FUNCTION : io_port_lookup()
*  PURPOSE  : Look for descriptor for specified port
*  ARGUMENTS: GUEST_ID    guest_id
*           : UINT16      port_id
*  RETURNS  : Pointer to the descriptor, NULL if not found
*----------------------------------------------------------------------------*/
IO_VMEXIT_DESCRIPTOR * io_port_lookup(
    GUEST_ID    guest_id,
    IO_PORT_ID  port_id)
{
    GUEST_IO_VMEXIT_CONTROL *io_ctrl = NULL;
    unsigned i;

    io_ctrl = io_vmexit_find_guest_io_control(guest_id);

	if(NULL == io_ctrl)
	{
		return NULL;
	}

    for (i = 0; i < NELEMENTS(io_ctrl->io_descriptors); ++i)
    {
        if (io_ctrl->io_descriptors[i].io_port == port_id
        &&  io_ctrl->io_descriptors[i].io_handler != NULL)
        {
            return &io_ctrl->io_descriptors[i];
        }
    }
    return NULL;
}

/*----------------------------------------------------------------------------*
*  FUNCTION : io_free_port_lookup()
*  PURPOSE  : Look for unallocated descriptor
*  ARGUMENTS: GUEST_ID    guest_id
*  RETURNS  : Pointer to the descriptor, NULL if not found
*----------------------------------------------------------------------------*/
IO_VMEXIT_DESCRIPTOR * io_free_port_lookup(GUEST_ID guest_id)
{
    GUEST_IO_VMEXIT_CONTROL *io_ctrl = NULL;
    unsigned i;

    io_ctrl = io_vmexit_find_guest_io_control(guest_id);

	if(NULL == io_ctrl)
	{
		return NULL;
	}

    for (i = 0; i < NELEMENTS(io_ctrl->io_descriptors); ++i)
    {
        if (NULL == io_ctrl->io_descriptors[i].io_handler)
        {
            return &io_ctrl->io_descriptors[i];
        }
    }
    return NULL;
}


#pragma warning( push )
#pragma warning (disable : 4100)  // Supress warnings about unreferenced formal parameter

void io_blocking_read_handler(
    GUEST_CPU_HANDLE    gcpu UNUSED,
    IO_PORT_ID          port_id UNUSED,
    unsigned            port_size, // 1, 2, 4
    void               *p_value)
{
    switch (port_size)
    {
    case 1:
    case 2:
    case 4:
        vmm_memset(p_value, 0xFF, port_size);
        break;
    default:
        VMM_LOG(mask_anonymous, level_trace,"Invalid IO port size(%d)\n", port_size);
        VMM_DEADLOOP();
        break;
    }
}

void io_blocking_write_handler(
    GUEST_CPU_HANDLE    gcpu UNUSED,
    IO_PORT_ID          port_id UNUSED,
    unsigned            port_size UNUSED, // 1, 2, 4
    void               *p_value UNUSED)
{
}

/*----------------------------------------------------------------------------*
*  FUNCTION : io_blocking_handler()
*  PURPOSE  : Used as default handler when no IO handler is registered,
*           : but port configured as caused VMEXIT.
*  ARGUMENTS: GUEST_CPU_HANDLE gcpu,
*           : IO_PORT_ID       port_id,
*           : unsigned         port_size,
*           : RW_ACCESS        access,
*           : void             *p_value
*  RETURNS  : void
*----------------------------------------------------------------------------*/
BOOLEAN
io_blocking_handler(
    GUEST_CPU_HANDLE gcpu,
    IO_PORT_ID       port_id,
    unsigned         port_size,
    RW_ACCESS        access,
    BOOLEAN          string_intr,  // ins/outs
    BOOLEAN          rep_prefix,   // rep 
    UINT32           rep_count,
    void             *p_value,
    void             *context UNUSED
    )
{
    switch (access)
    {
    case WRITE_ACCESS:
        io_blocking_write_handler(gcpu, port_id, port_size, p_value);
        break;
    case READ_ACCESS:
        io_blocking_read_handler(gcpu, port_id, port_size, p_value);
        break;
    default:
        VMM_LOG(mask_anonymous, level_trace,"Invalid IO access(%d)\n", access);
        VMM_DEADLOOP();
        break;
    }

    return TRUE;
}


void io_transparent_read_handler(
    GUEST_CPU_HANDLE    gcpu UNUSED,
    IO_PORT_ID          port_id,
    unsigned            port_size, // 1, 2, 4
    void               *p_value)
{
    switch (port_size)
    {
    case 1:
        *(UINT8 *) p_value = hw_read_port_8(port_id);
        break;

    case 2:
        *(UINT16 *) p_value = hw_read_port_16(port_id);
        break;
    case 4:
        *(UINT32 *) p_value = hw_read_port_32(port_id);
        break;
    default:
        VMM_LOG(mask_anonymous, level_trace,"Invalid IO port size(%d)\n", port_size);
        VMM_DEADLOOP();
        break;
    }
}

void io_transparent_write_handler(
    GUEST_CPU_HANDLE    gcpu UNUSED,
    IO_PORT_ID          port_id,
    unsigned            port_size, // 1, 2, 4
    void               *p_value)
{
    switch (port_size)
    {
    case 1:
        hw_write_port_8(port_id, *(UINT8 *) p_value);
        break;

    case 2:
        hw_write_port_16(port_id, *(UINT16 *) p_value);
        break;
    case 4:
        hw_write_port_32(port_id, *(UINT32 *) p_value);
        break;
    default:
        VMM_LOG(mask_anonymous, level_trace,"Invalid IO port size(%d)\n", port_size);
        VMM_DEADLOOP();
        break;
    }
}

void io_vmexit_transparent_handler(
    GUEST_CPU_HANDLE  gcpu,
    UINT16            port_id,
    unsigned          port_size, // 1, 2, 4
    RW_ACCESS         access,
    void              *p_value,
    void              *context UNUSED)
{
    switch (access)
    {
    case WRITE_ACCESS:
        io_transparent_write_handler(gcpu, port_id, port_size, p_value);
        break;
    case READ_ACCESS:
        io_transparent_read_handler(gcpu, port_id, port_size, p_value);
        break;
    default:
        VMM_LOG(mask_anonymous, level_trace,"Invalid IO access(%d)\n", access);
        VMM_DEADLOOP();
        break;
    }
}



#pragma warning( pop )

/*----------------------------------------------------------------------------*
*  FUNCTION : io_vmexit_handler_register()
*  PURPOSE  : Register/update IO handler for spec port/guest pair.
*  ARGUMENTS: GUEST_ID            guest_id
*           : IO_PORT_ID          port_id
*           : IO_ACCESS_HANDLER   handler
*  RETURNS  : status
*----------------------------------------------------------------------------*/
VMM_STATUS io_vmexit_handler_register(
    GUEST_ID            guest_id,
    IO_PORT_ID          port_id,
    IO_ACCESS_HANDLER   handler,
    void*               context)
{
    IO_VMEXIT_DESCRIPTOR *p_desc = io_port_lookup(guest_id, port_id);
    VMM_STATUS           status;
    GUEST_IO_VMEXIT_CONTROL *io_ctrl = NULL;

    io_ctrl = io_vmexit_find_guest_io_control(guest_id);

    VMM_ASSERT(io_ctrl);
    VMM_ASSERT(handler);

    if (NULL != p_desc)
    {
        VMM_LOG(mask_anonymous, level_trace,"IO Handler for Guest(%d) Port(%d) is already regitered. Update...\n",
            guest_id, port_id);
    }
    else
    {
        p_desc = io_free_port_lookup(guest_id);
    }

    if (NULL != p_desc)
    {
        BITARRAY_SET(io_ctrl->io_bitmap, port_id);
        p_desc->io_port    = port_id;
        p_desc->io_handler = handler;
        p_desc->io_handler_context = context;
        status = VMM_OK;
    }
    else
    {
        // if reach the MAX number (IO_VMEXIT_MAX_COUNT) of ports, 
        // return ERROR, but not deadloop.
        status = VMM_ERROR;
        VMM_LOG(mask_anonymous, level_trace,"Not enough space to register IO handler\n");
    }

    return status;
}

/*----------------------------------------------------------------------------*
*  FUNCTION : io_vmexit_handler_unregister()
*  PURPOSE  : Unregister IO handler for spec port/guest pair.
*  ARGUMENTS: GUEST_ID            guest_id
*           : IO_PORT_ID          port_id
*  RETURNS  : status
*----------------------------------------------------------------------------*/
VMM_STATUS io_vmexit_handler_unregister(
    GUEST_ID    guest_id,
    IO_PORT_ID  port_id)
{
    IO_VMEXIT_DESCRIPTOR *p_desc = io_port_lookup(guest_id, port_id);
    VMM_STATUS           status;
    GUEST_IO_VMEXIT_CONTROL *io_ctrl = NULL;

    io_ctrl = io_vmexit_find_guest_io_control(guest_id);

    VMM_ASSERT(io_ctrl);

    if (NULL != p_desc)
    {
        BITARRAY_CLR(io_ctrl->io_bitmap, port_id);
        p_desc->io_handler = NULL;
        p_desc->io_handler_context = NULL;
        status = VMM_OK;
    }
    else
    {
        // if not registered before, still return SUCCESS!
        status = VMM_OK;
        VMM_LOG(mask_anonymous, level_trace,"IO Handler for Guest(%d) Port(%d) is not regitered\n",
            guest_id, port_id);
    }

    return status;
}



//
// VM exits caused by execution of the INS and OUTS instructions 
// have priority over the following faults:
// —-1. A #GP fault due to the relevant segment (ES for INS; DS for
//    OUTS unless overridden by an instruction prefix) being unusable;
// --2. A #GP fault due to an offset (ESI, EDI) beyond the limit of 
//    the relevant segment, for 64bit, check non-canonical form;
// --3. An #AC exception (unaligned memory referenced when CR0.AM=1, 
//    EFLAGS.AC=1, and CPL=3).
// Hence, if those fault/exception above happens,inject back to guest.
static
BOOLEAN io_access_native_fault( GUEST_CPU_HANDLE            gcpu,
                                IA32_VMX_EXIT_QUALIFICATION *qualification
                                )
{
    VMCS_OBJECT     *vmcs     = gcpu_get_vmcs(gcpu);
    IA32_VMX_VMCS_VM_EXIT_INFO_INSTRUCTION_INFO ios_instr_info;
    BOOLEAN                 status = FALSE;
    VMM_SEGMENT_ATTRIBUTES  seg_ar = {0};
    VM_ENTRY_CONTROLS       vmentry_control;
    BOOLEAN                 is_64bit    = FALSE;
    UINT64                  cs_selector = 0;
    EM64T_CR0               guest_cr0;
    EM64T_RFLAGS            guest_rflags ;
    
    VMM_ASSERT(qualification);
    VMM_ASSERT(vmcs);

    // only handle ins/outs string io instructions.
    VMM_ASSERT(qualification->IoInstruction.String == 1);

    ios_instr_info.Uint32  = (UINT32)vmcs_read(vmcs, VMCS_EXIT_INFO_INSTRUCTION_INFO);
    vmentry_control.Uint32 = (UINT32)vmcs_read(vmcs, VMCS_ENTER_CONTROL_VECTOR);

    if (1 == vmentry_control.Bits.Ia32eModeGuest){
        is_64bit = TRUE;
    }

    //
    // 1) check the 1st/2nd condidtion.-- #GP
    // 
    if(qualification->IoInstruction.Direction){
        
        UINT64 Rdi = gcpu_get_native_gp_reg(gcpu, IA32_REG_RDI);

        // for INS -- check ES segement usable?  
        seg_ar.attr32 = (UINT32) vmcs_read(vmcs, VMCS_GUEST_ES_AR);
        if(seg_ar.bits.null_bit == 1){
            // ES unusable, inject #GP 
            VMM_LOG(mask_anonymous, level_trace,
                    "INS - ES segment is un-usable, inject #GP\n");
            
            gcpu_inject_gp0(gcpu);
            return TRUE;
        }


        if(is_64bit){
            // must 64bit address size.
            //VMM_ASSERT(ios_instr_info.InsOutsInstruction.AddrSize == 2);
            
            if(FALSE == addr_is_canonical(Rdi)){
                // address is not canonical , inject #GP 
                VMM_LOG(mask_anonymous, level_trace,
                        "INS - address %P is not canonical, inject #GP\n",
                        Rdi);
            
                gcpu_inject_gp0(gcpu);
                return TRUE;
            }
        }
        else{
            //
            //TODO: OFFSET/rdi check against segment limit.
            //Assume this case doesn't happen for 32bit Win7 OS, do nothing.
            //Need to develop case to test it
        }

        
    }
    else{
        UINT64 Rsi = gcpu_get_native_gp_reg(gcpu, IA32_REG_RSI);
        
        // for OUTS -- segment can be overridden, so check instr info 
        switch(ios_instr_info.InsOutsInstruction.SegReg){
            case 0: // ES
                seg_ar.attr32 = (UINT32)vmcs_read(vmcs, VMCS_GUEST_ES_AR);
                break;
                
            case 1: // CS
                seg_ar.attr32 = (UINT32)vmcs_read(vmcs, VMCS_GUEST_CS_AR);
                break;
                
            case 2: // SS
                seg_ar.attr32 = (UINT32)vmcs_read(vmcs, VMCS_GUEST_SS_AR);
                break;
                
            case 3: // DS
                seg_ar.attr32 = (UINT32)vmcs_read(vmcs, VMCS_GUEST_DS_AR);
                break;
                
            case 4: // FS
                seg_ar.attr32 = (UINT32)vmcs_read(vmcs, VMCS_GUEST_FS_AR);
                break;
                
            case 5: // GS
                seg_ar.attr32 = (UINT32)vmcs_read(vmcs, VMCS_GUEST_GS_AR);
                break;
                
            default:
                // impossible
                VMM_ASSERT(0);
                break;
        }

        if(seg_ar.bits.null_bit == 1){
            // xS segment unusable, inject #GP   

            VMM_LOG(mask_anonymous, level_trace,
                    "OUTS - the relevant segment is un-usable, inject #GP\n");
            
            gcpu_inject_gp0(gcpu);
            return TRUE;
        }

        if(is_64bit){
            // must 64bit address size.
            //VMM_ASSERT(ios_instr_info.InsOutsInstruction.AddrSize == 2);
            
            if(FALSE == addr_is_canonical(Rsi)){
                // address is not canonical , inject #GP 
                VMM_LOG(mask_anonymous, level_trace,
                        "INS - address %P is not canonical, inject #GP\n",
                        Rsi);
            
                gcpu_inject_gp0(gcpu);
                return TRUE;
            }
        }
        else{
            //
            //TODO: OFFSET/rsi check against segment limit.
            //Assume this case doesn't happen for 32bit OS, do nothing.
            //Need to develop case to test it
        }
    }

    //
    // 2) check the 3rd condidtion.-- #AC
    // 
    cs_selector = vmcs_read(vmcs, VMCS_GUEST_CS_SELECTOR);
    if(BITMAP_GET(cs_selector, CS_SELECTOR_CPL_BIT) == 3){
        // ring3 level.
        guest_cr0.Uint64 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR0);
        if(guest_cr0.Bits.AM){
            // CR0.AM = 1
            guest_rflags.Uint64 = vmcs_read(vmcs, VMCS_GUEST_RFLAGS);
            if(guest_rflags.Bits.AC){
                // rflag.ac = 1

                // TODO:check address (rdi/rsi) alignment based on 
                // ios_instr_info.InsOutsInstruction.AddrSize.
                // if not word/dword/qword aligned, then inject #AC to guest

                // Assume this case won't happen unless the IO port is allowed
                // to access in ring3 level by setting I/O Permission Bit Map
                // in TSS data structure.(actually, this is a hacking behavior)

                // so, catch this case with deadloop.
                VMM_DEADLOOP();
            }
        }
        
    }
    

    return status;
        
}


VMEXIT_HANDLING_STATUS io_vmexit_handler(GUEST_CPU_HANDLE gcpu)
{
    GUEST_HANDLE            guest_handle  = gcpu_guest_handle(gcpu);
    GUEST_ID                guest_id      = guest_get_id(guest_handle);
    VMCS_OBJECT            *vmcs          = gcpu_get_vmcs(gcpu);
    UINT64                  qualification = vmcs_read(vmcs, VMCS_EXIT_INFO_QUALIFICATION);
    IA32_VMX_EXIT_QUALIFICATION *p_qualification = (IA32_VMX_EXIT_QUALIFICATION *) &qualification;
    IO_PORT_ID              port_id  = (0 == p_qualification->IoInstruction.OpEncoding) ?
                                (UINT16) gcpu_get_native_gp_reg(gcpu, IA32_REG_RDX) :
                                (UINT16) p_qualification->IoInstruction.PortNumber;
    IO_VMEXIT_DESCRIPTOR   *p_desc   = io_port_lookup(guest_id, port_id);
    unsigned                port_size = (unsigned) p_qualification->IoInstruction.Size + 1;
    RW_ACCESS               access = p_qualification->IoInstruction.Direction ? READ_ACCESS : WRITE_ACCESS;
    IO_ACCESS_HANDLER       handler = ((NULL == p_desc) ? io_blocking_handler : p_desc->io_handler);
    void*                   context = ((NULL == p_desc) ? NULL : p_desc->io_handler_context);
    BOOLEAN                 string_io  = ( p_qualification->IoInstruction.String ? TRUE : FALSE);
    BOOLEAN                 rep_prefix = ( p_qualification->IoInstruction.Rep ? TRUE : FALSE);
    UINT32                  rep_count  = ( rep_prefix ? (UINT32) gcpu_get_native_gp_reg(gcpu, IA32_REG_RCX) : 0);

    UINT64                  io_value = 0;

    IA32_VMX_VMCS_VM_EXIT_INFO_INSTRUCTION_INFO ios_instr_info;


    if (FALSE == string_io){
        
        // ordinary IN/OUT instruction
        // data is stored in guest RAX register, not need to 
        // pass it to Handler here.
        io_value = 0;
    }
    else{        
        // for string INS/OUTS instruction

        // The linear address gva is the base address of 
        // relevant segment plus (E)DI (for INS) or (E)SI 
        // (for OUTS). It is valid only when the relevant 
        // segment is usable. Otherwise, it is undefined.
        UINT64  gva      = vmcs_read(vmcs, VMCS_EXIT_INFO_GUEST_LINEAR_ADDRESS);
        HVA     dumy_hva = 0;


        // if a native fault/exception happens, then let OS handle them.
        // and don't report invalid io-access event to Handler in order
        // to avoid unexpected behaviors.
        if(io_access_native_fault(gcpu, p_qualification) == TRUE){
            
            return VMEXIT_HANDLED;
        }
        

        if( FALSE == gcpu_gva_to_hva(gcpu, gva, &dumy_hva)){
            
            VMM_LOG(mask_anonymous, level_trace,"Guest(%d) Virtual Address %P Is Not Mapped\n", guest_id, gva);

            // catch this failure to avoid further errors:
            // for INS/OUTS instruction, if gva is invalid, which one will happen first?
            // 1) native OS #PF; or 2) An IO VM exit
            // if the testcase can reach here, then fix it.
            VMM_DEADLOOP();
        } 

        ios_instr_info.Uint32  = (UINT32)vmcs_read(vmcs, VMCS_EXIT_INFO_INSTRUCTION_INFO);

        switch(ios_instr_info.InsOutsInstruction.AddrSize){

            case 0: // 16-bit
                gva &= (UINT64)0x0FFFF;
                break;

            case 1: // 32-bit
                gva &= (UINT64)0x0FFFFFFFF;
                break;

            case 2: // 64-bit                
                break;

            default:
                // not h/w supported
                VMM_DEADLOOP();
            
        }
        
        // GVA address
        io_value = (GVA)gva;

    }


    // call to the handler
    if( TRUE == handler( gcpu, 
                         port_id, 
                         port_size, 
                         access, 
                         string_io, 
                         rep_prefix, 
                         rep_count, 
                         (void *)io_value, 
                         context)){
        
        gcpu_skip_guest_instruction(gcpu);
    }

    return VMEXIT_HANDLED;
}

/*----------------------------------------------------------------------------*
*  FUNCTION : io_vmexit_block_port()
*  PURPOSE  : Enable VMEXIT on port without installing handler.
*           : Blocking_handler will be used for such cases.
*  ARGUMENTS: GUEST_ID            guest_id
*           : IO_PORT_ID          port_from
*           : IO_PORT_ID          port_to
*  RETURNS  : void
*----------------------------------------------------------------------------*/
void io_vmexit_block_port(
    GUEST_ID    guest_id,
    IO_PORT_ID  port_from,
    IO_PORT_ID  port_to)
{
    unsigned i;
    GUEST_IO_VMEXIT_CONTROL *io_ctrl = NULL;

    io_ctrl = io_vmexit_find_guest_io_control(guest_id);

    VMM_ASSERT(io_ctrl);

    // unregister handler in case it was installed before
    for (i = port_from; i <= port_to; ++i)
    {
        io_vmexit_handler_unregister(guest_id, (IO_PORT_ID)i);
        BITARRAY_SET(io_ctrl->io_bitmap, i);
    }
}

static
GUEST_IO_VMEXIT_CONTROL* io_vmexit_find_guest_io_control(GUEST_ID guest_id)
{
    LIST_ELEMENT *iter = NULL;
    GUEST_IO_VMEXIT_CONTROL *io_ctrl = NULL;

    LIST_FOR_EACH(io_vmexit_global_state.guest_io_vmexit_controls, iter)
    {
        io_ctrl = LIST_ENTRY(iter, GUEST_IO_VMEXIT_CONTROL, list);
        if(io_ctrl->guest_id == guest_id)
        {
            return io_ctrl;
        }
    }

    return NULL;
}

