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

#include "vmm_bootstrap_utils.h"
#include "libc.h"
#include "heap.h"
#include "vmm_dbg.h"
#include "vmm_startup.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(COPY_INPUT_STRUCTS_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(COPY_INPUT_STRUCTS_C, __condition)


//******************************************************************************
//*
//* Copy input params into heap before changing host virtual memory mapping
//* Required in order to avoid input parameters disrupting
//*
//******************************************************************************

INLINE
void vmm_copy_gcpu_startup_state(VMM_GUEST_CPU_STARTUP_STATE* state_to, const VMM_GUEST_CPU_STARTUP_STATE* state_from) {
    vmm_memcpy(state_to, state_from, state_from->size_of_this_struct);
}

INLINE
void vmm_copy_guest_device(VMM_GUEST_DEVICE* guest_device_to, const VMM_GUEST_DEVICE* guest_device_from) {
    vmm_memcpy(guest_device_to, guest_device_from, guest_device_from->size_of_this_struct);
}

static
BOOLEAN vmm_copy_guest_startup(VMM_GUEST_STARTUP* guest_startup_to, const VMM_GUEST_STARTUP* guest_startup_from) {
    UINT32 size_of_array = 0;
    UINT32 i;
    void* array;
    VMM_GUEST_CPU_STARTUP_STATE* curr_state_to;
    const VMM_GUEST_CPU_STARTUP_STATE* curr_state_from;
    VMM_GUEST_DEVICE* curr_device_to;
    const VMM_GUEST_DEVICE* curr_device_from;

    // Copy the structure (one to one)
    vmm_memcpy(guest_startup_to, guest_startup_from, guest_startup_from->size_of_this_struct);

    // Create copy of VMM_GUEST_CPU_STARTUP_STATE array
    for (i = 0; i < guest_startup_from->cpu_states_count; i++) {
        UINT64 addr_of_cpu_state = guest_startup_from->cpu_states_array + size_of_array;
        const VMM_GUEST_CPU_STARTUP_STATE* state = (const VMM_GUEST_CPU_STARTUP_STATE*)addr_of_cpu_state;

        size_of_array += state->size_of_this_struct;
    }

    guest_startup_to->cpu_states_array = 0;

    if (size_of_array > 0)
    {
        array = vmm_memory_alloc(size_of_array);
        if (array == NULL) {
            return FALSE;
        }
        guest_startup_to->cpu_states_array = (UINT64)array;

        curr_state_from = (const VMM_GUEST_CPU_STARTUP_STATE*)guest_startup_from->cpu_states_array;
        curr_state_to = (VMM_GUEST_CPU_STARTUP_STATE*)array;
        for (i = 0; i < guest_startup_from->cpu_states_count; i++) {
            vmm_copy_gcpu_startup_state(curr_state_to, curr_state_from);
            curr_state_from = (const VMM_GUEST_CPU_STARTUP_STATE*)((UINT64)curr_state_from + curr_state_from->size_of_this_struct);
            curr_state_to = (VMM_GUEST_CPU_STARTUP_STATE*)((UINT64)curr_state_to + curr_state_to->size_of_this_struct);
        }
    }


    // Create copy of VMM_GUEST_DEVICE array
    size_of_array = 0;
    for (i = 0; i < guest_startup_from->devices_count; i++) {
        UINT64 addr_of_device_struct = guest_startup_from->devices_array + size_of_array;
        const VMM_GUEST_DEVICE* device = (const VMM_GUEST_DEVICE*)addr_of_device_struct;

        size_of_array += device->size_of_this_struct;
    }

    guest_startup_to->devices_array = 0;

    if (size_of_array > 0)
    {
        array = vmm_memory_alloc(size_of_array);
        if (array == NULL) {
            return FALSE;
        }
        guest_startup_to->devices_array = (UINT64)array;

        curr_device_from = (const VMM_GUEST_DEVICE*)guest_startup_from->devices_array;
        curr_device_to = (VMM_GUEST_DEVICE*)array;
        for (i = 0; i < guest_startup_from->devices_count; i++) {
            vmm_copy_guest_device(curr_device_to, curr_device_from);
            curr_device_from = (const VMM_GUEST_DEVICE*)((UINT64)curr_device_from + curr_device_from->size_of_this_struct);
            curr_device_to = (VMM_GUEST_DEVICE*)((UINT64)curr_device_to + curr_device_to->size_of_this_struct);
        }
    }

    // For SOS copy image into heap
    if (guest_startup_from->image_size != 0) {
        void* image_heap_addr;

        VMM_ASSERT(guest_startup_from->image_address != 0);
        image_heap_addr = vmm_memory_alloc(guest_startup_from->image_size);
        if (image_heap_addr == NULL) {
            return FALSE;
        }

        vmm_memcpy(image_heap_addr, (void*)(guest_startup_from->image_address), guest_startup_from->image_size);
        guest_startup_to->image_address = (UINT64)image_heap_addr;
    }


    return TRUE;
}

static
const VMM_GUEST_STARTUP* vmm_create_guest_startup_copy(const VMM_GUEST_STARTUP* guest_startup_stack) {
    VMM_GUEST_STARTUP* guest_startup_heap = NULL;

    // BEFORE_VMLAUNCH. Failure check can be included in POSTLAUNCH.
    VMM_ASSERT(guest_startup_stack->size_of_this_struct >= sizeof(VMM_GUEST_STARTUP));
    guest_startup_heap = (VMM_GUEST_STARTUP*)vmm_memory_alloc(guest_startup_stack->size_of_this_struct);
    if (guest_startup_heap == NULL) {
        return NULL;
    }

    if (!vmm_copy_guest_startup(guest_startup_heap, guest_startup_stack)) {
        return NULL;
    }

    return (const VMM_GUEST_STARTUP*)guest_startup_heap;
}

static
void vmm_destroy_guest_startup_struct(const VMM_GUEST_STARTUP* guest_startup) {

    if (guest_startup == NULL) {
        return;
    }

    // For SOS: if the image is in heap, destroy it
    if (guest_startup->image_size != 0) {

        // BEFORE_VMLAUNCH. Failure check can be included in POSTLAUNCH.
        VMM_ASSERT(guest_startup->image_address != 0);
        vmm_memory_free((void*)guest_startup->image_address);
    }

    // Destory all devices
    if (guest_startup->devices_array != 0) {
        vmm_memory_free((void*)guest_startup->devices_array);
    }

    // Destory all cpu state structs
    if (guest_startup->cpu_states_array != 0) {
        vmm_memory_free((void*)guest_startup->cpu_states_array);
    }
}

const VMM_STARTUP_STRUCT* vmm_create_startup_struct_copy(const VMM_STARTUP_STRUCT* startup_struct_stack) {
    VMM_STARTUP_STRUCT* startup_struct_heap = NULL;
    const VMM_GUEST_STARTUP* guest_startup_heap = NULL;
    void* secondary_guests_array;
    UINT32 size_of_array = 0;
    UINT32 i;

    if (startup_struct_stack == NULL) {
        return NULL;
    }

    // BEFORE_VMLAUNCH. Failure check can be included in POSTLAUNCH.
    // Copy all the fields from the struct
    VMM_ASSERT(startup_struct_stack->size_of_this_struct >= sizeof(VMM_STARTUP_STRUCT));
    // BEFORE_VMLAUNCH. Failure check can be included in POSTLAUNCH.
    VMM_ASSERT(ALIGN_BACKWARD((UINT64)startup_struct_stack, VMM_STARTUP_STRUCT_ALIGNMENT) == (UINT64)startup_struct_stack);
    startup_struct_heap = (VMM_STARTUP_STRUCT*)vmm_memory_alloc(startup_struct_stack->size_of_this_struct);
    if (startup_struct_heap == NULL) {
        return NULL;
    }
    // BEFORE_VMLAUNCH. Failure check can be included in POSTLAUNCH.
    VMM_ASSERT(ALIGN_BACKWARD((UINT64)startup_struct_heap, VMM_STARTUP_STRUCT_ALIGNMENT) == (UINT64)startup_struct_heap);
    vmm_memcpy(startup_struct_heap, startup_struct_stack, startup_struct_stack->size_of_this_struct);

    // Create copy of guest startup struct
    if (startup_struct_stack->primary_guest_startup_state != 0) {
        // BEFORE_VMLAUNCH. Failure check can be included in POSTLAUNCH.
        VMM_ASSERT(ALIGN_BACKWARD(startup_struct_stack->primary_guest_startup_state, VMM_GUEST_STARTUP_ALIGNMENT) == startup_struct_stack->primary_guest_startup_state);
        guest_startup_heap = vmm_create_guest_startup_copy((const VMM_GUEST_STARTUP*)startup_struct_stack->primary_guest_startup_state);
        if (guest_startup_heap == NULL) {
            return NULL;
        }
        // BEFORE_VMLAUNCH. Failure check can be included in POSTLAUNCH.
        VMM_ASSERT(ALIGN_BACKWARD((UINT64)guest_startup_heap, VMM_GUEST_STARTUP_ALIGNMENT) == (UINT64)guest_startup_heap);
        startup_struct_heap->primary_guest_startup_state = (UINT64)guest_startup_heap;
    }

    // Create copies of SOSes start up struct
    if (startup_struct_stack->number_of_secondary_guests > 0) {
        const VMM_GUEST_STARTUP* curr_guest_struct = NULL;
        VMM_GUEST_STARTUP* curr_guest_struct_heap = NULL;

        for (i = 0; i < startup_struct_stack->number_of_secondary_guests; i++) {
            UINT64 addr_of_guest_struct = startup_struct_stack->secondary_guests_startup_state_array + size_of_array;

            curr_guest_struct = (const VMM_GUEST_STARTUP*)addr_of_guest_struct;

            // BEFORE_VMLAUNCH. Failure check can be included in POSTLAUNCH.
            VMM_ASSERT(ALIGN_BACKWARD(addr_of_guest_struct, VMM_GUEST_STARTUP_ALIGNMENT) == addr_of_guest_struct);

            size_of_array += curr_guest_struct->size_of_this_struct;
        }


        secondary_guests_array = vmm_memory_alloc(size_of_array);
        if (secondary_guests_array == NULL) {
            return NULL;
        }
        startup_struct_heap->secondary_guests_startup_state_array = (UINT64)secondary_guests_array;

        curr_guest_struct = (const VMM_GUEST_STARTUP*)startup_struct_stack->secondary_guests_startup_state_array;
        curr_guest_struct_heap = (VMM_GUEST_STARTUP*)secondary_guests_array;

        for (i = 0; i < startup_struct_stack->number_of_secondary_guests; i++) {
            if (!vmm_copy_guest_startup(curr_guest_struct_heap, curr_guest_struct)) {
                return NULL;
            }

            curr_guest_struct = (const VMM_GUEST_STARTUP*)((UINT64)curr_guest_struct + curr_guest_struct->size_of_this_struct);
            curr_guest_struct_heap = (VMM_GUEST_STARTUP*)((UINT64)curr_guest_struct_heap + curr_guest_struct_heap->size_of_this_struct);
        }
    }

    return (const VMM_STARTUP_STRUCT*)startup_struct_heap;

}

void vmm_destroy_startup_struct(const VMM_STARTUP_STRUCT* startup_struct) {
    UINT32 i;

    if (startup_struct == NULL) {
        return;
    }

    // Destroy SOSes guest structs
    if (startup_struct->number_of_secondary_guests > 0) {
        const VMM_GUEST_STARTUP* curr_guest_struct = (const VMM_GUEST_STARTUP*)startup_struct->secondary_guests_startup_state_array;

        for (i = 0; i < startup_struct->number_of_secondary_guests; i++) {
            vmm_destroy_guest_startup_struct(curr_guest_struct);
            curr_guest_struct = (const VMM_GUEST_STARTUP*)((UINT64)curr_guest_struct + curr_guest_struct->size_of_this_struct);
        }
        vmm_memory_free((void*)startup_struct->secondary_guests_startup_state_array);
    }

    // Destroy primary guest struct
    if (startup_struct->primary_guest_startup_state != 0) {
        vmm_destroy_guest_startup_struct((const VMM_GUEST_STARTUP*)startup_struct->primary_guest_startup_state);
        vmm_memory_free((void*)startup_struct->primary_guest_startup_state);
    }

    // Destory struct itself
    vmm_memory_free((void*)startup_struct);
}

const VMM_APPLICATION_PARAMS_STRUCT* vmm_create_application_params_struct_copy(const VMM_APPLICATION_PARAMS_STRUCT* application_params_stack) {
    VMM_APPLICATION_PARAMS_STRUCT* application_params_heap;

    if (application_params_stack == NULL) {
        return NULL;
    }

    application_params_heap = (VMM_APPLICATION_PARAMS_STRUCT*)vmm_memory_alloc(application_params_stack->size_of_this_struct);
    if (application_params_heap == NULL) {
        return NULL;
    }
    vmm_memcpy(application_params_heap, application_params_stack, application_params_stack->size_of_this_struct);
    return (VMM_APPLICATION_PARAMS_STRUCT*)application_params_heap;
}

void vmm_destroy_application_params_struct(const VMM_APPLICATION_PARAMS_STRUCT* application_params_struct) {
    if (application_params_struct == NULL) {
        return;
    }
    vmm_memory_free((void*)application_params_struct);
}

//-------------------------------- debug print ------------------------------

#define PRINT_STARTUP_FIELD8( tabs, root, name )  \
            VMM_LOG(mask_anonymous, level_trace,"%s%-42s = 0x%02X\n", tabs, #name, root->name )
#define PRINT_STARTUP_FIELD16( tabs, root, name )  \
            VMM_LOG(mask_anonymous, level_trace,"%s%-42s = 0x%04X\n", tabs, #name, root->name )
#define PRINT_STARTUP_FIELD32( tabs, root, name )  \
            VMM_LOG(mask_anonymous, level_trace,"%s%-42s = 0x%08X\n", tabs, #name, root->name )
#define PRINT_STARTUP_FIELD64( tabs, root, name )  \
            VMM_LOG(mask_anonymous, level_trace,"%s%-42s = 0x%016lX\n", tabs, #name, root->name )
#define PRINT_STARTUP_FIELD128( tabs, root, name )   \
            VMM_LOG(mask_anonymous, level_trace,"%s%-42s = 0x%016lX%016lX\n",     \
                       tabs,                         \
                       #name,                        \
                       ((UINT64 *)&(root->name))[1], \
                       ((UINT64 *)&(root->name))[0])

#ifdef DEBUG
#pragma warning(disable : 4100 4189)
static
void print_guest_device_struct(const VMM_GUEST_DEVICE* startup_struct,
                                    UINT32 dev_idx )
{
    const char* prefix = "    .";

    VMM_LOG(mask_anonymous, level_trace,"\n    ----------------- VMM_GUEST_DEVICE ----------------------\n\n");

    VMM_LOG(mask_anonymous, level_trace,"     =========> Guest device #%d\n", dev_idx );

    if (startup_struct == NULL)
    {
        VMM_LOG(mask_anonymous, level_trace,"    VMM_GUEST_DEVICE is NULL\n");
        goto end;
    }

    PRINT_STARTUP_FIELD16( prefix, startup_struct, size_of_this_struct );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, version_of_this_struct );

    PRINT_STARTUP_FIELD16( prefix, startup_struct, real_vendor_id );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, real_device_id );

    PRINT_STARTUP_FIELD16( prefix, startup_struct, virtual_vendor_id );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, virtual_device_id );

end:
    VMM_LOG(mask_anonymous, level_trace,"\n    ----------------- END of VMM_GUEST_DEVICE ---------------\n\n");
}
#pragma warning(default : 4100 4189)

//pragma is needed because in "release" VMM_LOG translates to nothing
//and parameters are not used
#pragma warning(disable : 4100 4189)
static
void print_guest_cpu_startup_struct(const VMM_GUEST_CPU_STARTUP_STATE* startup_struct,
                                    UINT32 gcpu_idx )
{
    const char* prefix = "    .";

    VMM_LOG(mask_anonymous, level_trace,"\n    ----------------- VMM_GUEST_CPU_STARTUP_STATE ----------------------\n\n");

    VMM_LOG(mask_anonymous, level_trace,"     =========> Guest CPU #%d %s\n", gcpu_idx,
                                    (gcpu_idx == 0) ? "(BSP)" : "" );

    if (startup_struct == NULL)
    {
        VMM_LOG(mask_anonymous, level_trace,"    VMM_GUEST_CPU_STARTUP_STATE is NULL\n");
        goto end;
    }

    PRINT_STARTUP_FIELD16( prefix, startup_struct, size_of_this_struct );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, version_of_this_struct );

    PRINT_STARTUP_FIELD64( prefix, startup_struct, gp.reg[IA32_REG_RAX] );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, gp.reg[IA32_REG_RBX] );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, gp.reg[IA32_REG_RCX] );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, gp.reg[IA32_REG_RDX] );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, gp.reg[IA32_REG_RDI] );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, gp.reg[IA32_REG_RSI] );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, gp.reg[IA32_REG_RBP] );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, gp.reg[IA32_REG_RSP] );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, gp.reg[IA32_REG_R8]  );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, gp.reg[IA32_REG_R9]  );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, gp.reg[IA32_REG_R10] );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, gp.reg[IA32_REG_R11] );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, gp.reg[IA32_REG_R12] );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, gp.reg[IA32_REG_R13] );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, gp.reg[IA32_REG_R14] );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, gp.reg[IA32_REG_R15] );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, gp.reg[IA32_REG_RIP] );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, gp.reg[IA32_REG_RFLAGS] );

    PRINT_STARTUP_FIELD128( prefix, startup_struct, xmm.reg[IA32_REG_XMM0] );
    PRINT_STARTUP_FIELD128( prefix, startup_struct, xmm.reg[IA32_REG_XMM1] );
    PRINT_STARTUP_FIELD128( prefix, startup_struct, xmm.reg[IA32_REG_XMM2] );
    PRINT_STARTUP_FIELD128( prefix, startup_struct, xmm.reg[IA32_REG_XMM3] );
    PRINT_STARTUP_FIELD128( prefix, startup_struct, xmm.reg[IA32_REG_XMM4] );
    PRINT_STARTUP_FIELD128( prefix, startup_struct, xmm.reg[IA32_REG_XMM5] );
    PRINT_STARTUP_FIELD128( prefix, startup_struct, xmm.reg[IA32_REG_XMM6] );
    PRINT_STARTUP_FIELD128( prefix, startup_struct, xmm.reg[IA32_REG_XMM7] );
    PRINT_STARTUP_FIELD128( prefix, startup_struct, xmm.reg[IA32_REG_XMM8] );
    PRINT_STARTUP_FIELD128( prefix, startup_struct, xmm.reg[IA32_REG_XMM9] );
    PRINT_STARTUP_FIELD128( prefix, startup_struct, xmm.reg[IA32_REG_XMM10]);
    PRINT_STARTUP_FIELD128( prefix, startup_struct, xmm.reg[IA32_REG_XMM11]);
    PRINT_STARTUP_FIELD128( prefix, startup_struct, xmm.reg[IA32_REG_XMM12]);
    PRINT_STARTUP_FIELD128( prefix, startup_struct, xmm.reg[IA32_REG_XMM13]);
    PRINT_STARTUP_FIELD128( prefix, startup_struct, xmm.reg[IA32_REG_XMM14]);
    PRINT_STARTUP_FIELD128( prefix, startup_struct, xmm.reg[IA32_REG_XMM15]);

    PRINT_STARTUP_FIELD64( prefix, startup_struct, seg.segment[IA32_SEG_CS].base );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, seg.segment[IA32_SEG_CS].limit );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, seg.segment[IA32_SEG_CS].attributes );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, seg.segment[IA32_SEG_CS].selector );

    PRINT_STARTUP_FIELD64( prefix, startup_struct, seg.segment[IA32_SEG_DS].base );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, seg.segment[IA32_SEG_DS].limit );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, seg.segment[IA32_SEG_DS].attributes );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, seg.segment[IA32_SEG_DS].selector );

    PRINT_STARTUP_FIELD64( prefix, startup_struct, seg.segment[IA32_SEG_SS].base );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, seg.segment[IA32_SEG_SS].limit );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, seg.segment[IA32_SEG_SS].attributes );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, seg.segment[IA32_SEG_SS].selector );

    PRINT_STARTUP_FIELD64( prefix, startup_struct, seg.segment[IA32_SEG_ES].base );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, seg.segment[IA32_SEG_ES].limit );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, seg.segment[IA32_SEG_ES].attributes );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, seg.segment[IA32_SEG_ES].selector );

    PRINT_STARTUP_FIELD64( prefix, startup_struct, seg.segment[IA32_SEG_FS].base );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, seg.segment[IA32_SEG_FS].limit );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, seg.segment[IA32_SEG_FS].attributes );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, seg.segment[IA32_SEG_FS].selector );

    PRINT_STARTUP_FIELD64( prefix, startup_struct, seg.segment[IA32_SEG_GS].base );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, seg.segment[IA32_SEG_GS].limit );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, seg.segment[IA32_SEG_GS].attributes );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, seg.segment[IA32_SEG_GS].selector );

    PRINT_STARTUP_FIELD64( prefix, startup_struct, seg.segment[IA32_SEG_LDTR].base );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, seg.segment[IA32_SEG_LDTR].limit );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, seg.segment[IA32_SEG_LDTR].attributes );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, seg.segment[IA32_SEG_LDTR].selector );

    PRINT_STARTUP_FIELD64( prefix, startup_struct, seg.segment[IA32_SEG_TR].base );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, seg.segment[IA32_SEG_TR].limit );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, seg.segment[IA32_SEG_TR].attributes );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, seg.segment[IA32_SEG_TR].selector );

    PRINT_STARTUP_FIELD64( prefix, startup_struct, control.cr[IA32_CTRL_CR0]);
    PRINT_STARTUP_FIELD64( prefix, startup_struct, control.cr[IA32_CTRL_CR2]);
    PRINT_STARTUP_FIELD64( prefix, startup_struct, control.cr[IA32_CTRL_CR3]);
    PRINT_STARTUP_FIELD64( prefix, startup_struct, control.cr[IA32_CTRL_CR4]);
    PRINT_STARTUP_FIELD64( prefix, startup_struct, control.cr[IA32_CTRL_CR8]);

    PRINT_STARTUP_FIELD64( prefix, startup_struct, control.gdtr.base );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, control.gdtr.limit );

    PRINT_STARTUP_FIELD64( prefix, startup_struct, control.idtr.base );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, control.idtr.limit );

    PRINT_STARTUP_FIELD64( prefix, startup_struct, msr.msr_debugctl );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, msr.msr_efer );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, msr.msr_pat );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, msr.msr_sysenter_esp );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, msr.msr_sysenter_eip );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, msr.pending_exceptions );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, msr.msr_sysenter_cs );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, msr.interruptibility_state );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, msr.activity_state );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, msr.smbase );

end:
    VMM_LOG(mask_anonymous, level_trace,"\n    ----------------- END of VMM_GUEST_CPU_STARTUP_STATE ---------------\n\n");
}

#pragma warning(default : 4100 4189)

//pragma is needed because in "release" VMM_LOG translates to nothing
//and parameters are not used
#pragma warning(disable : 4189)
static
void print_guest_startup_struct(const VMM_GUEST_STARTUP* startup_struct,
                                UINT32 guest_idx ) // if -1 - primary
{
    const char* prefix = "  .";
    const VMM_GUEST_CPU_STARTUP_STATE* gcpu;
    const VMM_GUEST_DEVICE*            dev;
    UINT32 i;

    VMM_LOG(mask_anonymous, level_trace,"\n  ----------------- VMM_GUEST_STARTUP ----------------------\n\n");

    if (guest_idx == (UINT32)-1)
    {
        VMM_LOG(mask_anonymous, level_trace,"   =========> The PRIMARY guest\n");
    }
    else
    {
        VMM_LOG(mask_anonymous, level_trace,"   =========> Secondary guest #%d\n", guest_idx );
    }

    if (startup_struct == NULL)
    {
        VMM_LOG(mask_anonymous, level_trace,"  VMM_GUEST_STARTUP is NULL\n");
        goto end;
    }

    PRINT_STARTUP_FIELD16( prefix, startup_struct, size_of_this_struct );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, version_of_this_struct );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, flags );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, guest_magic_number );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, cpu_affinity );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, cpu_states_count );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, devices_count );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, image_size );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, image_address );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, physical_memory_size );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, image_offset_in_guest_physical_memory );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, cpu_states_array );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, devices_array );

    gcpu = (const VMM_GUEST_CPU_STARTUP_STATE*)(startup_struct->cpu_states_array);

    for (i = 0; i < startup_struct->cpu_states_count; ++i)
    {
        print_guest_cpu_startup_struct( gcpu + i, i );
    }

    dev = (const VMM_GUEST_DEVICE*)(startup_struct->devices_array);

    for (i = 0; i < startup_struct->devices_count; ++i)
    {
        print_guest_device_struct( dev + i, i );
    }

end:
    VMM_LOG(mask_anonymous, level_trace,"\n  ----------------- END of VMM_GUEST_STARTUP ---------------\n\n");
}
#pragma warning(default : 4189)

//pragma is needed because in "release" VMM_LOG translates to nothing
//and parameters are not used
#pragma warning(disable : 4189)

void print_startup_struct(const VMM_STARTUP_STRUCT* startup_struct)
{
    const char* prefix = ".";
    UINT16  idx;

    VMM_LOG(mask_anonymous, level_trace,"\n----------------- VMM_STARTUP_STRUCT ----------------------\n\n");
    if (startup_struct == NULL)
    {
        VMM_LOG(mask_anonymous, level_trace,"VMM_STARTUP_STRUCT is NULL\n");
        goto end;
    }

    PRINT_STARTUP_FIELD16( prefix, startup_struct, size_of_this_struct );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, version_of_this_struct );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, number_of_processors_at_install_time );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, number_of_processors_at_boot_time );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, number_of_secondary_guests );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, size_of_vmm_stack );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, unsupported_vendor_id );
    PRINT_STARTUP_FIELD16( prefix, startup_struct, unsupported_device_id );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, flags );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, default_device_owner );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, acpi_owner );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, nmi_owner );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, vmm_memory_layout[uvmm_image].total_size );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, vmm_memory_layout[uvmm_image].image_size );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, vmm_memory_layout[uvmm_image].base_address );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, physical_memory_layout_E820 );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, primary_guest_startup_state );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, secondary_guests_startup_state_array );
    PRINT_STARTUP_FIELD8(  prefix, startup_struct, debug_params.verbosity );
    PRINT_STARTUP_FIELD64( prefix, startup_struct, debug_params.mask );
    PRINT_STARTUP_FIELD8(  prefix, startup_struct, debug_params.port.type );
    PRINT_STARTUP_FIELD8(  prefix, startup_struct, debug_params.port.virt_mode );
    PRINT_STARTUP_FIELD8(  prefix, startup_struct, debug_params.port.ident_type );
    PRINT_STARTUP_FIELD32( prefix, startup_struct, debug_params.port.ident.ident32 );

    print_guest_startup_struct( (const VMM_GUEST_STARTUP*)(startup_struct->primary_guest_startup_state ),
                                (UINT32)-1);

    for (idx = 0; idx < startup_struct->number_of_secondary_guests; ++idx)
    {
        const VMM_GUEST_STARTUP* sec = (const VMM_GUEST_STARTUP*)(startup_struct->secondary_guests_startup_state_array );
        print_guest_startup_struct( sec + idx, idx );
    }

end:
    VMM_LOG(mask_anonymous, level_trace,"\n----------------- END of VMM_STARTUP_STRUCT ---------------\n\n");
}
#pragma warning(default : 4189)
#endif //DEBUG
