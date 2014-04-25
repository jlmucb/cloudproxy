/*
 * Copyright (c) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _GUEST_CPU_INTERNAL_H
#define _GUEST_CPU_INTERNAL_H

#include "vmm_defs.h"
#include "guest_cpu.h"
#include "guest_cpu_control.h"
#include <common_libc.h>
#include "vmcs_hierarchy.h"
#include "vmcs_actual.h"
#include "emulator_if.h"
#include "flat_page_tables.h"
#include "guest_save_area.h"


// Guest CPU
// Guest CPU may be in 2 different modes:
//    16 mode - run under emulator
//    any other mode - run native
// Defines save area for guest registers, not saved in VMCS
// Data structure to access IA-32 General Purpose Registers referenced by 
// VM Exit Handlers.  This is also the structure used to save/restore general 
// purpose registers in assembly code for the VMEXIT and VMENTER handlers

#pragma PACK_ON

// Do not show to the guest the real values of the following bits +
// perform VMEXIT on writes to this bits
#define GCPU_CR4_VMM_CONTROLLED_BITS     (CR4_PAE|CR4_SMXE)
#define GCPU_CR0_VMM_CONTROLLED_BITS     0

// main save area
#define CR2_SAVE_AREA IA32_REG_RSP
#define CR3_SAVE_AREA IA32_REG_RFLAGS
#define CR8_SAVE_AREA IA32_REG_RIP

#pragma PACK_OFF

typedef struct _VE_DESCRIPTOR {
    UINT64                      ve_info_hva;
    UINT64                      ve_info_hpa;
    BOOLEAN                     ve_enabled;
    UINT8                       pad[4];
} VE_DESCRIPTOR;

// per-cpu data/state
typedef struct _FVS_CPU_DESCRIPTOR {
    UINT64  vmentry_eptp;
    BOOLEAN enabled;
    UINT32  padding;
} FVS_CPU_DESCRIPTOR;


// invalid CR3 value used to specify that CR3_SAVE_AREA is not up-to-date
#define INVALID_CR3_SAVED_VALUE     UINT64_ALL_ONES

typedef struct _GUEST_CPU {
    // save_area and vmcs must come first due to alignment. Do not move !
    GUEST_CPU_SAVE_AREA         save_area;
    VMCS_HIERARCHY              vmcs_hierarchy;
    GUEST_HANDLE                guest_handle;
    FPT_FLAT_PAGE_TABLES_HANDLE active_flat_pt_handle;
    UINT64                      active_flat_pt_hpa;

    EMULATOR_HANDLE             emulator_handle;

    VIRTUAL_CPU_ID              vcpu;
    UINT8                       last_guest_level;   // get values from GUEST_LEVEL
    UINT8                       next_guest_level;   // get values from GUEST_LEVEL
    UINT8                       state_flags;    // GCPU_STATE_ENUM
    UINT8                       caching_flags;  // GCPU_CACHINE_FLAGS_ENUM
    UINT32                      hw_enforcements;
    UINT8                       merge_required;
    UINT8                       cached_activity_state; // Used to determine activity state switch
    UINT8                       pad;
    UINT8                       use_host_page_tables;

    GCPU_VMEXIT_CONTROLS        vmexit_setup;
    struct _GUEST_CPU           *next_gcpu;
    GCPU_RESUME_FUNC            resume_func;
    GCPU_VMEXIT_FUNC            vmexit_func;
    void                        *vmdb;  // guest debugger handler
    void                        *timer;

    GPM_HANDLE                  active_gpm;

#ifdef FAST_VIEW_SWITCH
    FVS_CPU_DESCRIPTOR          fvs_cpu_desc;
#else
        UINT8                       pad1[16];
#endif
        UINT32                      trigger_log_event;
        UINT8                       pad2[4];
        VE_DESCRIPTOR               ve_desc;

} GUEST_CPU;


typedef enum _GCPU_STATE_ENUM {
    GCPU_EMULATOR_FLAG = 0,                 // 1 - emulator is active, 0 - native
    GCPU_FLAT_PAGES_TABLES_32_FLAG,         // 1 - 32bit flat page tables in use
    GCPU_FLAT_PAGES_TABLES_64_FLAG,         // 1 - 64bit flat page tables in use
    GCPU_ACTIVITY_STATE_CHANGED_FLAG,       // 1 - Activity/Sleep state changed
    GCPU_EXCEPTION_RESOLUTION_REQUIRED_FLAG,// 1 - VMEXIT caused by exception. Have to handle prior event injection/resume
    GCPU_EXPLICIT_EMULATOR_REQUEST,         // 1 - emulator run was requested explicitly
    GCPU_UNRESTRICTED_GUEST_FLAG,           // 1 - Unrestricted guest enabled, 0 - unrestreicted guest disabled
    GCPU_IMPORTANT_EVENT_OCCURED_FLAG = 7,  // 1 - CR0/EFER changed
} GCPU_STATE_ENUM;

#define SET_EMULATOR_FLAG( gcpu )                BIT_SET( (gcpu)->state_flags, GCPU_EMULATOR_FLAG)
#define CLR_EMULATOR_FLAG( gcpu )                BIT_CLR( (gcpu)->state_flags, GCPU_EMULATOR_FLAG)
#define GET_EMULATOR_FLAG( gcpu )                BIT_GET( (gcpu)->state_flags, GCPU_EMULATOR_FLAG)

#define SET_FLAT_PAGES_TABLES_32_FLAG( gcpu )    BIT_SET( (gcpu)->state_flags, GCPU_FLAT_PAGES_TABLES_32_FLAG)
#define CLR_FLAT_PAGES_TABLES_32_FLAG( gcpu )    BIT_CLR( (gcpu)->state_flags, GCPU_FLAT_PAGES_TABLES_32_FLAG)
#define GET_FLAT_PAGES_TABLES_32_FLAG( gcpu )    BIT_GET( (gcpu)->state_flags, GCPU_FLAT_PAGES_TABLES_32_FLAG)

#define SET_FLAT_PAGES_TABLES_64_FLAG( gcpu )    BIT_SET( (gcpu)->state_flags, GCPU_FLAT_PAGES_TABLES_64_FLAG)
#define CLR_FLAT_PAGES_TABLES_64_FLAG( gcpu )    BIT_CLR( (gcpu)->state_flags, GCPU_FLAT_PAGES_TABLES_64_FLAG)
#define GET_FLAT_PAGES_TABLES_64_FLAG( gcpu )    BIT_GET( (gcpu)->state_flags, GCPU_FLAT_PAGES_TABLES_64_FLAG)

#define SET_ACTIVITY_STATE_CHANGED_FLAG( gcpu )  BIT_SET( (gcpu)->state_flags, GCPU_ACTIVITY_STATE_CHANGED_FLAG)
#define CLR_ACTIVITY_STATE_CHANGED_FLAG( gcpu )  BIT_CLR( (gcpu)->state_flags, GCPU_ACTIVITY_STATE_CHANGED_FLAG)
#define GET_ACTIVITY_STATE_CHANGED_FLAG( gcpu )  BIT_GET( (gcpu)->state_flags, GCPU_ACTIVITY_STATE_CHANGED_FLAG)

#define SET_EXCEPTION_RESOLUTION_REQUIRED_FLAG( gcpu )  BIT_SET( (gcpu)->state_flags, GCPU_EXCEPTION_RESOLUTION_REQUIRED_FLAG)
#define CLR_EXCEPTION_RESOLUTION_REQUIRED_FLAG( gcpu )  BIT_CLR( (gcpu)->state_flags, GCPU_EXCEPTION_RESOLUTION_REQUIRED_FLAG)
#define GET_EXCEPTION_RESOLUTION_REQUIRED_FLAG( gcpu )  BIT_GET( (gcpu)->state_flags, GCPU_EXCEPTION_RESOLUTION_REQUIRED_FLAG)

#define SET_EXPLICIT_EMULATOR_REQUEST_FLAG( gcpu )  BIT_SET( (gcpu)->state_flags, GCPU_EXPLICIT_EMULATOR_REQUEST)
#define CLR_EXPLICIT_EMULATOR_REQUEST_FLAG( gcpu )  BIT_CLR( (gcpu)->state_flags, GCPU_EXPLICIT_EMULATOR_REQUEST)
#define GET_EXPLICIT_EMULATOR_REQUEST_FLAG( gcpu )  BIT_GET( (gcpu)->state_flags, GCPU_EXPLICIT_EMULATOR_REQUEST)

#define SET_IMPORTANT_EVENT_OCCURED_FLAG( gcpu ) BIT_SET( (gcpu)->state_flags, GCPU_IMPORTANT_EVENT_OCCURED_FLAG)
#define CLR_IMPORTANT_EVENT_OCCURED_FLAG( gcpu ) BIT_CLR( (gcpu)->state_flags, GCPU_IMPORTANT_EVENT_OCCURED_FLAG)
#define GET_IMPORTANT_EVENT_OCCURED_FLAG( gcpu ) BIT_GET( (gcpu)->state_flags, GCPU_IMPORTANT_EVENT_OCCURED_FLAG)

#define IS_MODE_EMULATOR( gcpu )    (GET_EMULATOR_FLAG( gcpu ) == 1)
#define SET_MODE_EMULATOR( gcpu )   SET_EMULATOR_FLAG( gcpu )

#ifdef ENABLE_EMULATOR
#define IS_MODE_NATIVE( gcpu )      ((GET_EMULATOR_FLAG( gcpu ) == 0)   ||      \
                                     ((gcpu)->emulator_handle == NULL)  ||      \
                                     !emul_is_running((gcpu)->emulator_handle))
#else
#define IS_MODE_NATIVE( gcpu )      (1)
#endif
#define SET_MODE_NATIVE( gcpu )     CLR_EMULATOR_FLAG( gcpu )


#define IS_FLAT_PT_INSTALLED( gcpu ) (GET_FLAT_PAGES_TABLES_32_FLAG(gcpu) || GET_FLAT_PAGES_TABLES_64_FLAG(gcpu))


typedef enum _GCPU_CACHINE_FLAGS_ENUM {
    GCPU_FX_STATE_CACHED_FLAG = 0,
    GCPU_DEBUG_REGS_CACHED_FLAG,

    GCPU_FX_STATE_MODIFIED_FLAG,
    GCPU_DEBUG_REGS_MODIFIED_FLAG,
} GCPU_CACHINE_FLAGS_ENUM;

#define SET_FX_STATE_CACHED_FLAG( gcpu )   BIT_SET( (gcpu)->caching_flags, GCPU_FX_STATE_CACHED_FLAG)
#define CLR_FX_STATE_CACHED_FLAG( gcpu )   BIT_CLR( (gcpu)->caching_flags, GCPU_FX_STATE_CACHED_FLAG)
#define GET_FX_STATE_CACHED_FLAG( gcpu )   BIT_GET( (gcpu)->caching_flags, GCPU_FX_STATE_CACHED_FLAG)
#define SET_DEBUG_REGS_CACHED_FLAG( gcpu ) BIT_SET( (gcpu)->caching_flags, GCPU_DEBUG_REGS_CACHED_FLAG)
#define CLR_DEBUG_REGS_CACHED_FLAG( gcpu ) BIT_CLR( (gcpu)->caching_flags, GCPU_DEBUG_REGS_CACHED_FLAG)
#define GET_DEBUG_REGS_CACHED_FLAG( gcpu ) BIT_GET( (gcpu)->caching_flags, GCPU_DEBUG_REGS_CACHED_FLAG)

#define SET_FX_STATE_MODIFIED_FLAG( gcpu )   BIT_SET( (gcpu)->caching_flags, GCPU_FX_STATE_MODIFIED_FLAG)
#define CLR_FX_STATE_MODIFIED_FLAG( gcpu )   BIT_CLR( (gcpu)->caching_flags, GCPU_FX_STATE_MODIFIED_FLAG)
#define GET_FX_STATE_MODIFIED_FLAG( gcpu )   BIT_GET( (gcpu)->caching_flags, GCPU_FX_STATE_MODIFIED_FLAG)

#define SET_DEBUG_REGS_MODIFIED_FLAG( gcpu ) BIT_SET( (gcpu)->caching_flags, GCPU_DEBUG_REGS_MODIFIED_FLAG)
#define CLR_DEBUG_REGS_MODIFIED_FLAG( gcpu ) BIT_CLR( (gcpu)->caching_flags, GCPU_DEBUG_REGS_MODIFIED_FLAG)
#define GET_DEBUG_REGS_MODIFIED_FLAG( gcpu ) BIT_GET( (gcpu)->caching_flags, GCPU_DEBUG_REGS_MODIFIED_FLAG)

#define SET_ALL_MODIFIED( gcpu )            {(gcpu)->caching_flags = (UINT8)-1;}
#define CLR_ALL_CACHED( gcpu )              {(gcpu)->caching_flags = 0;}


// this is a shortcut pointer for assembler code
extern GUEST_CPU_SAVE_AREA** g_guest_regs_save_area;

void cache_debug_registers( const GUEST_CPU* gcpu );
void cache_fx_state( const GUEST_CPU* gcpu );
#ifdef INCLUDE_UNUSED_CODE
void restore_hw_debug_registers( GUEST_CPU* gcpu );
void restore_fx_state( GUEST_CPU* gcpu );
#endif

INLINE UINT64 gcpu_get_msr_reg_internal( const GUEST_CPU_HANDLE gcpu,
                           VMM_IA32_MODEL_SPECIFIC_REGISTERS reg )
{
    return gcpu_get_msr_reg_internal_layered(gcpu, reg, VMCS_MERGED);
}

#define SET_CACHED_ACTIVITY_STATE( __gcpu, __value )                            \
    { (__gcpu)->cached_activity_state = (UINT8)(__value); }

#define GET_CACHED_ACTIVITY_STATE( __gcpu )                                     \
    ((IA32_VMX_VMCS_GUEST_SLEEP_STATE)((__gcpu)->cached_activity_state))

#define IS_STATE_INACTIVE( activity_state )                                     \
    (Ia32VmxVmcsGuestSleepStateWaitForSipi == (activity_state))

#endif // _GUEST_CPU_INTERNAL_H
