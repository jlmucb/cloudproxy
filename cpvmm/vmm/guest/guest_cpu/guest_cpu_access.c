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

#include "file_codes.h"
#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(GUEST_CPU_ACCESS_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(GUEST_CPU_ACCESS_C, __condition)
#include "guest_cpu_internal.h"
#include "heap.h"
#include "array_iterators.h"
#include "gpm_api.h"
#include "scheduler.h"
#include "vmx_ctrl_msrs.h"
#include "vmm_dbg.h"
#include "vmcs_init.h"
#include "page_walker.h"
#include "gpm_api.h"
#include "guest.h"
#include "msr_defs.h"
#include "host_memory_manager_api.h"
#include "unrestricted_guest.h"
#include "vmm_callback.h"
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif

#pragma warning( push )
#pragma warning (disable : 4100)

typedef struct _SEGMENT_2_VMCS {
    VMCS_FIELD sel, base, limit, ar;
} SEGMENT_2_VMCS;

// encoding table for segments
const SEGMENT_2_VMCS g_segment_2_vmcs[IA32_SEG_COUNT] = {
    /*IA32_SEG_CS*/ { VMCS_GUEST_CS_SELECTOR,
                      VMCS_GUEST_CS_BASE,
                      VMCS_GUEST_CS_LIMIT,
                      VMCS_GUEST_CS_AR },
    /*IA32_SEG_DS*/ { VMCS_GUEST_DS_SELECTOR,
                      VMCS_GUEST_DS_BASE,
                      VMCS_GUEST_DS_LIMIT,
                      VMCS_GUEST_DS_AR },
    /*IA32_SEG_SS*/ { VMCS_GUEST_SS_SELECTOR,
                      VMCS_GUEST_SS_BASE,
                      VMCS_GUEST_SS_LIMIT,
                      VMCS_GUEST_SS_AR },
    /*IA32_SEG_ES*/ { VMCS_GUEST_ES_SELECTOR,
                      VMCS_GUEST_ES_BASE,
                      VMCS_GUEST_ES_LIMIT,
                      VMCS_GUEST_ES_AR },
    /*IA32_SEG_FS*/ { VMCS_GUEST_FS_SELECTOR,
                      VMCS_GUEST_FS_BASE,
                      VMCS_GUEST_FS_LIMIT,
                      VMCS_GUEST_FS_AR },
    /*IA32_SEG_GS*/ { VMCS_GUEST_GS_SELECTOR,
                      VMCS_GUEST_GS_BASE,
                      VMCS_GUEST_GS_LIMIT,
                      VMCS_GUEST_GS_AR },
    /*IA32_SEG_LDTR*/{VMCS_GUEST_LDTR_SELECTOR,
                      VMCS_GUEST_LDTR_BASE,
                      VMCS_GUEST_LDTR_LIMIT,
                      VMCS_GUEST_LDTR_AR },
    /*IA32_SEG_TR*/ { VMCS_GUEST_TR_SELECTOR,
                      VMCS_GUEST_TR_BASE,
                      VMCS_GUEST_TR_LIMIT,
                      VMCS_GUEST_TR_AR }
};

// encoding table for msrs
VMCS_FIELD  g_msr_2_vmcs[] = {
    /*IA32_VMM_MSR_DEBUGCTL*/              VMCS_GUEST_DEBUG_CONTROL,
    /*IA32_VMM_MSR_EFER*/                  VMCS_GUEST_EFER,
    /*IA32_VMM_MSR_PAT*/                   VMCS_GUEST_PAT,
    /*IA32_VMM_MSR_SYSENTER_ESP*/          VMCS_GUEST_SYSENTER_ESP,
    /*IA32_VMM_MSR_SYSENTER_EIP*/          VMCS_GUEST_SYSENTER_EIP,
    /*IA32_VMM_MSR_SYSENTER_CS*/           VMCS_GUEST_SYSENTER_CS,
    /*IA32_VMM_MSR_SMBASE*/                VMCS_GUEST_SMBASE,
    /*IA32_VMM_MSR_PERF_GLOBAL_CTRL*/      VMCS_GUEST_IA32_PERF_GLOBAL_CTRL,
    /*IA32_MSR_FS_BASE*/                    VMCS_GUEST_FS_BASE,
    /*IA32_MSR_GS_BASE*/                    VMCS_GUEST_GS_BASE
};

const UINT32 g_msr_2_index[] = {
    /*IA32_VMM_MSR_DEBUGCTL*/              IA32_MSR_DEBUGCTL,
    /*IA32_VMM_MSR_EFER*/                  IA32_MSR_EFER,
    /*IA32_VMM_MSR_PAT*/                   IA32_MSR_PAT,
    /*IA32_VMM_MSR_SYSENTER_ESP*/          IA32_MSR_SYSENTER_ESP,
    /*IA32_VMM_MSR_SYSENTER_EIP*/          IA32_MSR_SYSENTER_EIP,
    /*IA32_VMM_MSR_SYSENTER_CS*/           IA32_MSR_SYSENTER_CS,
    /*IA32_VMM_MSR_SMBASE*/                IA32_INVALID_MSR_INDEX,
    /*IA32_VMM_MSR_PERF_GLOBAL_CTRL*/      IA32_MSR_PERF_GLOBAL_CTRL,
    /*IA32_MSR_FS_BASE*/                    IA32_MSR_FS_BASE,
    /*IA32_MSR_GS_BASE*/                    IA32_MSR_GS_BASE
};


BOOLEAN gcpu_is_native_execution( GUEST_CPU_HANDLE gcpu )
{
    return IS_MODE_NATIVE(gcpu);
}

UINT64 gcpu_get_native_gp_reg_layered( const GUEST_CPU_HANDLE gcpu,
                               VMM_IA32_GP_REGISTERS reg, VMCS_LEVEL level )
{
    VMM_ASSERT(reg < IA32_REG_GP_COUNT);
    switch (reg) {
        case IA32_REG_RSP:
            return vmcs_read(vmcs_hierarchy_get_vmcs(&gcpu->vmcs_hierarchy, level), 
                              VMCS_GUEST_RSP);
        case IA32_REG_RIP:
            return vmcs_read(vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level), 
                              VMCS_GUEST_RIP );
        case IA32_REG_RFLAGS:
            return vmcs_read(vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level), 
                              VMCS_GUEST_RFLAGS );
        default:
            return gcpu->save_area.gp.reg[reg];
    }
}

void   gcpu_set_native_gp_reg_layered(GUEST_CPU_HANDLE gcpu,
                  VMM_IA32_GP_REGISTERS reg, UINT64  value, VMCS_LEVEL level)
{
    VMM_ASSERT(reg < IA32_REG_GP_COUNT);

    switch (reg) {
        case IA32_REG_RSP:
            vmcs_write( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), 
                              VMCS_GUEST_RSP, value );
            return;
        case IA32_REG_RIP:
            vmcs_write( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), 
                              VMCS_GUEST_RIP, value );
            return;
        case IA32_REG_RFLAGS:
            vmcs_write( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), 
                              VMCS_GUEST_RFLAGS, value );
            return;
        default:
            gcpu->save_area.gp.reg[reg] = value;
            return;
    }
}

#ifdef INCLUDE_UNUSED_CODE
void gcpu_get_all_gp_regs_internal( const GUEST_CPU_HANDLE gcpu, UINT64 *GPreg )
{
    VMM_ASSERT(gcpu);

    *GPreg = gcpu->save_area.gp.reg[IA32_REG_RAX];
    *(GPreg + 1) = gcpu->save_area.gp.reg[IA32_REG_RBX];
    *(GPreg + 2) = gcpu->save_area.gp.reg[IA32_REG_RCX];
    *(GPreg + 3) = gcpu->save_area.gp.reg[IA32_REG_RDX];
    *(GPreg + 5) = gcpu->save_area.gp.reg[IA32_REG_RBP];
    *(GPreg + 6) = gcpu->save_area.gp.reg[IA32_REG_RSI];
    *(GPreg + 7) = gcpu->save_area.gp.reg[IA32_REG_RDI];
    *(GPreg + 8) = gcpu->save_area.gp.reg[IA32_REG_R8];
    *(GPreg + 9) = gcpu->save_area.gp.reg[IA32_REG_R9];
    *(GPreg + 10) = gcpu->save_area.gp.reg[IA32_REG_R10];
    *(GPreg + 11) = gcpu->save_area.gp.reg[IA32_REG_R11];
    *(GPreg + 12) = gcpu->save_area.gp.reg[IA32_REG_R12];
    *(GPreg + 13) = gcpu->save_area.gp.reg[IA32_REG_R13];
    *(GPreg + 14) = gcpu->save_area.gp.reg[IA32_REG_R14];
    *(GPreg + 15) = gcpu->save_area.gp.reg[IA32_REG_R15];
    // Copy PAT
    *(GPreg + 17) = gcpu->save_area.temporary_cached_msrs.pat;
}
#endif

UINT64 gcpu_get_gp_reg_layered( const GUEST_CPU_HANDLE gcpu,
                  VMM_IA32_GP_REGISTERS reg, VMCS_LEVEL level )
{
    VMM_ASSERT(gcpu);
    return gcpu_get_native_gp_reg_layered( gcpu, reg, level );
}

void gcpu_set_all_gp_regs_internal( const GUEST_CPU_HANDLE gcpu, UINT64 *GPReg )
{
    gcpu->save_area.gp.reg[IA32_REG_RAX] = *GPReg;
    gcpu->save_area.gp.reg[IA32_REG_RBX] = *(GPReg + 1);
    gcpu->save_area.gp.reg[IA32_REG_RCX] = *(GPReg + 2);
    gcpu->save_area.gp.reg[IA32_REG_RDX] = *(GPReg + 3);
    gcpu->save_area.gp.reg[IA32_REG_RBP] = *(GPReg + 5);
    gcpu->save_area.gp.reg[IA32_REG_RSI] = *(GPReg + 6);
    gcpu->save_area.gp.reg[IA32_REG_RDI] = *(GPReg + 7);
    gcpu->save_area.gp.reg[IA32_REG_R8]  = *(GPReg + 8);
    gcpu->save_area.gp.reg[IA32_REG_R9]  = *(GPReg + 9);
    gcpu->save_area.gp.reg[IA32_REG_R10] = *(GPReg + 10);
    gcpu->save_area.gp.reg[IA32_REG_R11] = *(GPReg + 11);
    gcpu->save_area.gp.reg[IA32_REG_R12] = *(GPReg + 12);
    gcpu->save_area.gp.reg[IA32_REG_R13] = *(GPReg + 13);
    gcpu->save_area.gp.reg[IA32_REG_R14] = *(GPReg + 14);
    gcpu->save_area.gp.reg[IA32_REG_R15] = *(GPReg + 15);
}

void gcpu_set_gp_reg_layered( GUEST_CPU_HANDLE gcpu, VMM_IA32_GP_REGISTERS reg,
                             UINT64 value, VMCS_LEVEL level )
{
    VMM_ASSERT(gcpu);

    gcpu_set_native_gp_reg_layered( gcpu, reg, value, level );
}

#ifdef INCLUDE_UNUSED_CODE
UINT128 gcpu_get_xmm_reg( const GUEST_CPU_HANDLE gcpu,
                               VMM_IA32_XMM_REGISTERS reg )
{
    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));
    VMM_ASSERT(reg < IA32_REG_XMM_COUNT);
    return gcpu->save_area.xmm.reg[reg];
}
#endif

void   gcpu_set_xmm_reg( GUEST_CPU_HANDLE gcpu, VMM_IA32_XMM_REGISTERS reg, UINT128 value )
{
    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));
    VMM_ASSERT(reg < IA32_REG_XMM_COUNT);
    gcpu->save_area.xmm.reg[reg] = value;
}

void gcpu_get_segment_reg_layered(const GUEST_CPU_HANDLE gcpu, 
                VMM_IA32_SEGMENT_REGISTERS reg, UINT16* selector, 
                UINT64* base, UINT32* limit, UINT32* attributes, 
                VMCS_LEVEL level )
{
    const SEGMENT_2_VMCS* seg2vmcs;
    VMCS_OBJECT *vmcs;

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT( reg < IA32_SEG_COUNT );
    vmcs = vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level );

    seg2vmcs = &g_segment_2_vmcs[reg];
    if (selector) {
        *selector = (UINT16)vmcs_read( vmcs, seg2vmcs->sel );
    }
    if (base) {
        *base     = vmcs_read( vmcs, seg2vmcs->base );
    }
    if (limit) {
        *limit    = (UINT32)vmcs_read( vmcs, seg2vmcs->limit );
    }
    if (attributes) {
        *attributes= (UINT32)vmcs_read( vmcs, seg2vmcs->ar );
    }
}

void   gcpu_set_segment_reg_layered( GUEST_CPU_HANDLE gcpu, VMM_IA32_SEGMENT_REGISTERS reg,
                              UINT16  selector, UINT64  base,
                              UINT32  limit, UINT32  attributes, VMCS_LEVEL level )
{
    const SEGMENT_2_VMCS* seg2vmcs;
    VMCS_OBJECT *vmcs;

    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));
    VMM_ASSERT( reg < IA32_SEG_COUNT );
    vmcs = vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level );
    seg2vmcs = &g_segment_2_vmcs[reg];
    vmcs_write( vmcs, seg2vmcs->sel, selector );
    vmcs_write( vmcs, seg2vmcs->base, base );
    vmcs_write( vmcs, seg2vmcs->limit, limit );
    vmcs_write( vmcs, seg2vmcs->ar, attributes );
}

UINT64 gcpu_get_control_reg_layered(const GUEST_CPU_HANDLE gcpu,
                              VMM_IA32_CONTROL_REGISTERS reg, VMCS_LEVEL level )
{
    VMM_ASSERT(gcpu);
    VMM_ASSERT( reg < IA32_CTRL_COUNT );

    switch (reg) {
        case IA32_CTRL_CR0:
            return vmcs_read( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_GUEST_CR0 );
        case IA32_CTRL_CR2:
            return gcpu->save_area.gp.reg[ CR2_SAVE_AREA ];
        case IA32_CTRL_CR3:
            return vmcs_read( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_GUEST_CR3 );
        case IA32_CTRL_CR4:
            return vmcs_read( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_GUEST_CR4 );
        case IA32_CTRL_CR8:
            return gcpu->save_area.gp.reg[CR8_SAVE_AREA];
        default:
            VMM_LOG(mask_anonymous, level_trace,"unknown control register\n");
            VMM_DEADLOOP();
    }
    // if we get here - something is wrong
    return 0;
}

void  gcpu_set_control_reg_layered(GUEST_CPU_HANDLE  gcpu, VMM_IA32_CONTROL_REGISTERS reg,
                UINT64 value, VMCS_LEVEL level )
{
    VMCS_OBJECT *vmcs;

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT( reg < IA32_CTRL_COUNT );

    vmcs = gcpu_get_vmcs_layered(gcpu, level);

    switch (reg) {
        case IA32_CTRL_CR0:
            if (vmcs == gcpu_get_vmcs(gcpu)) {
                value = vmcs_hw_make_compliant_cr0( value );
            }
            vmcs_write( vmcs, VMCS_GUEST_CR0, value );
            break;

        case IA32_CTRL_CR2:
            gcpu->save_area.gp.reg[ CR2_SAVE_AREA ] = value;
            break;

        case IA32_CTRL_CR3:
            vmcs_write( vmcs, VMCS_GUEST_CR3, value );
            break;

        case IA32_CTRL_CR4:
            if (vmcs == gcpu_get_vmcs(gcpu)) {
                value = vmcs_hw_make_compliant_cr4( value );
            }
            vmcs_write( vmcs, VMCS_GUEST_CR4, value );
            break;

        case IA32_CTRL_CR8:
            value = vmcs_hw_make_compliant_cr8( value );
            gcpu->save_area.gp.reg[CR8_SAVE_AREA] = value;
            break;

        default:
            VMM_LOG(mask_anonymous, level_trace,"unknown control register\n");
            // BEFORE_VMLAUNCH. This case should not happen.
            VMM_DEADLOOP();
    }
}

// special case of CR registers - some bits of CR0 and CR4 may be overridden by
// VMM, so that guest will see not real values
// all other registers return the same value as gcpu_get_control_reg()
// Valid for CR0, CR3, CR4
UINT64 gcpu_get_guest_visible_control_reg_layered( const GUEST_CPU_HANDLE gcpu,
                    VMM_IA32_CONTROL_REGISTERS reg, VMCS_LEVEL level)
{
    UINT64  mask;
    UINT64  shadow;
    UINT64  real_value;
    VMCS_OBJECT *vmcs = vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level );

    VMM_ASSERT(gcpu);

    if (reg == IA32_CTRL_CR3) {
        real_value = gcpu->save_area.gp.reg[ CR3_SAVE_AREA ];

        if (INVALID_CR3_SAVED_VALUE == real_value) {
            real_value = gcpu_get_control_reg_layered( gcpu, IA32_CTRL_CR3, level );
        }
        return real_value;
    }

    real_value = gcpu_get_control_reg_layered( gcpu, reg, level );

    if (reg == IA32_CTRL_CR0) {
        mask    = vmcs_read( vmcs, VMCS_CR0_MASK );
        shadow  = vmcs_read( vmcs, VMCS_CR0_READ_SHADOW );
    }
    else if (reg == IA32_CTRL_CR4) {
        mask    = vmcs_read( vmcs, VMCS_CR4_MASK );
        shadow  = vmcs_read( vmcs, VMCS_CR4_READ_SHADOW );
    }
    else {
        return real_value;
    }

    return (real_value & ~mask) | (shadow & mask);
}

// valid only for CR0, CR3 and CR4
void gcpu_set_guest_visible_control_reg_layered( const GUEST_CPU_HANDLE gcpu,
                              VMM_IA32_CONTROL_REGISTERS reg,
                              UINT64 value, VMCS_LEVEL level )
{
    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));

    if (reg == IA32_CTRL_CR3) {
        VMM_ASSERT(level == VMCS_MERGED);
        gcpu->save_area.gp.reg[ CR3_SAVE_AREA ] = value;
    }
    else if (reg == IA32_CTRL_CR0) {
        SET_IMPORTANT_EVENT_OCCURED_FLAG(gcpu);
        vmcs_write( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_CR0_READ_SHADOW, value  );
    }
    else if (reg == IA32_CTRL_CR4) {
        vmcs_write( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_CR4_READ_SHADOW, value  );
    }
    else {
        gcpu_set_control_reg_layered(gcpu, reg, value, level); // pass thru
    }
}

#ifdef INCLUDE_UNUSED_CODE
void   gcpu_get_tr_reg_layered( const GUEST_CPU_HANDLE gcpu, UINT64* base,
                             UINT32* limit, VMCS_LEVEL level )
{
    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));

    if (base) {
        *base = vmcs_read( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_GUEST_TR_BASE );
    }
    if (limit) {
        *limit = (UINT32)vmcs_read( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_GUEST_TR_LIMIT );
    }
}

void   gcpu_set_tr_reg_layered(const GUEST_CPU_HANDLE gcpu, UINT64 base,
                             UINT32 limit, VMCS_LEVEL  level )
{
    VMCS_OBJECT *vmcs = vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level );

    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));

    vmcs_write( vmcs, VMCS_GUEST_TR_BASE, base );
    vmcs_write( vmcs, VMCS_GUEST_TR_LIMIT, limit );
}
#endif

#ifdef INCLUDE_UNUSED_CODE
void   gcpu_get_ldt_reg_layered(const GUEST_CPU_HANDLE  gcpu, UINT64* base,
                             UINT32* limit, VMCS_LEVEL level )
{
    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));

    if (base) {
        *base = vmcs_read( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_GUEST_LDTR_BASE );
    }
    if (limit) {
        *limit = (UINT32)vmcs_read( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_GUEST_LDTR_LIMIT );
    }
}

void   gcpu_set_ldt_reg_layered(const GUEST_CPU_HANDLE gcpu, UINT64 base,
                             UINT32 limit, VMCS_LEVEL level )
{
    VMCS_OBJECT *vmcs = vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level );

    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));
    vmcs_write( vmcs, VMCS_GUEST_LDTR_BASE, base );
    vmcs_write( vmcs, VMCS_GUEST_LDTR_LIMIT, limit );
}
#endif

void   gcpu_get_gdt_reg_layered( const GUEST_CPU_HANDLE gcpu, UINT64* base,
                                UINT32* limit, VMCS_LEVEL level )
{
    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));

    if (base) {
        *base = vmcs_read( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_GUEST_GDTR_BASE );
    }
    if (limit) {
        *limit = (UINT32)vmcs_read( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_GUEST_GDTR_LIMIT );
    }
}

void   gcpu_set_gdt_reg_layered(const GUEST_CPU_HANDLE gcpu, UINT64 base,
                                UINT32 limit, VMCS_LEVEL level )
{
    VMCS_OBJECT *vmcs = vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level );
    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));
    vmcs_write( vmcs, VMCS_GUEST_GDTR_BASE, base );
    vmcs_write( vmcs, VMCS_GUEST_GDTR_LIMIT, limit );
}

void   gcpu_get_idt_reg_layered( const GUEST_CPU_HANDLE gcpu,
                             UINT64* base, UINT32* limit, VMCS_LEVEL level )
{
    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));

    if (base) {
        *base = vmcs_read( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_GUEST_IDTR_BASE );
    }
    if (limit) {
        *limit = (UINT32)vmcs_read( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_GUEST_IDTR_LIMIT );
    }
}

void   gcpu_set_idt_reg_layered(const GUEST_CPU_HANDLE gcpu, UINT64 base,
                             UINT32  limit, VMCS_LEVEL level )
{
    VMCS_OBJECT *vmcs = vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level );

    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));
    vmcs_write( vmcs, VMCS_GUEST_IDTR_BASE, base );
    vmcs_write( vmcs, VMCS_GUEST_IDTR_LIMIT, limit );
}

UINT64 gcpu_get_debug_reg_layered(const GUEST_CPU_HANDLE gcpu,
                              VMM_IA32_DEBUG_REGISTERS reg, VMCS_LEVEL level )
{
    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));
    VMM_ASSERT( reg < IA32_REG_DEBUG_COUNT );

    if (reg == IA32_REG_DR7) {
        return vmcs_read( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_GUEST_DR7 );
    }
    else {
        if (!GET_DEBUG_REGS_CACHED_FLAG (gcpu)) {
            cache_debug_registers( gcpu );
        }
        return gcpu->save_area.debug.reg[ reg ];
    }
}

void gcpu_set_debug_reg_layered(const GUEST_CPU_HANDLE gcpu, VMM_IA32_DEBUG_REGISTERS reg,
                              UINT64 value, VMCS_LEVEL level )
{
    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));
    VMM_ASSERT( reg < IA32_REG_DEBUG_COUNT );

    if (reg == IA32_REG_DR7) {
        vmcs_write( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_GUEST_DR7, value );
    }
    else {
        if (!GET_DEBUG_REGS_CACHED_FLAG (gcpu)) {
            cache_debug_registers( gcpu );
        }
        gcpu->save_area.debug.reg[ reg ] = value;
        SET_DEBUG_REGS_MODIFIED_FLAG(gcpu);
    }
}

UINT32 gcpu_get_interruptibility_state_layered(const GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level)
{
    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));

    return (UINT32)vmcs_read( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_GUEST_INTERRUPTIBILITY );
}

void gcpu_set_interruptibility_state_layered( const GUEST_CPU_HANDLE gcpu,
                                UINT32 value, VMCS_LEVEL level)
{
    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));

    vmcs_write( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_GUEST_INTERRUPTIBILITY, value );
}

IA32_VMX_VMCS_GUEST_SLEEP_STATE
    gcpu_get_activity_state_layered( const GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level)
{
    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));
    return vmcs_read( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_GUEST_SLEEP_STATE );
}

void gcpu_set_activity_state_layered( GUEST_CPU_HANDLE gcpu, 
                            IA32_VMX_VMCS_GUEST_SLEEP_STATE  value, VMCS_LEVEL level)
{
    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));

    vmcs_write( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_GUEST_SLEEP_STATE, value );

    if ((value != GET_CACHED_ACTIVITY_STATE(gcpu)) &&
        (!gcpu_is_vmcs_layered(gcpu) || (VMCS_MERGED == level))) {
        SET_ACTIVITY_STATE_CHANGED_FLAG(gcpu);
        SET_IMPORTANT_EVENT_OCCURED_FLAG(gcpu);
    }
}

UINT64 gcpu_get_pending_debug_exceptions_layered( const GUEST_CPU_HANDLE gcpu,
                                VMCS_LEVEL level)
{
    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));

    return vmcs_read( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_GUEST_PEND_DBE );
}


void gcpu_set_pending_debug_exceptions_layered(const GUEST_CPU_HANDLE gcpu,
                                UINT64 value, VMCS_LEVEL level)
{
    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));

    vmcs_write( vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level ), VMCS_GUEST_PEND_DBE, value );
}

void gcpu_set_vmenter_control_layered(const GUEST_CPU_HANDLE gcpu, VMCS_LEVEL level)
{
    VM_ENTRY_CONTROLS  entry_ctrl_mask;
    UINT64 value;
#ifdef JLMDEBUG
    bprint("gcpu_set_vmenter_control_layered returning early (FIX)0x%016lx %d\n", 
           gcpu, level);
    return;
#endif

    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));
    //IA Manual 3B Appendix G.6 - On processors that support UG
    //VM exits store the value of IA32_EFER.LMA into the “IA-32e
    //mode guest” VM-entry control  
    value = gcpu_get_msr_reg(gcpu, IA32_VMM_MSR_EFER);
    entry_ctrl_mask.Uint32 = 0;
    entry_ctrl_mask.Bits.Ia32eModeGuest = 1;
    vmcs_update(vmcs_hierarchy_get_vmcs(&gcpu->vmcs_hierarchy, level),
                       VMCS_ENTER_CONTROL_VECTOR,
                       (value & EFER_LMA) ? UINT64_ALL_ONES : 0,
                       (UINT64) entry_ctrl_mask.Uint32);
}

static BOOLEAN gcpu_get_msr_value_from_list(IN UINT32 msr_index, IN IA32_VMX_MSR_ENTRY* list,
                IN UINT32 count, OUT UINT64* value) {
    if (msr_index == IA32_INVALID_MSR_INDEX) {
        return FALSE;
    }
    if(NULL == list){
        return FALSE;
    }
    for (; count > 0; count--) {
        if (list[count - 1].MsrIndex == msr_index) {
            *value = list[count - 1].MsrData;
            return TRUE;
        }
    }
    return FALSE;
}

static BOOLEAN gcpu_set_msr_value_in_list(IN UINT32 msr_index, IN UINT64 value,
                       IN IA32_VMX_MSR_ENTRY* list, IN UINT32 count) {

    if (msr_index == IA32_INVALID_MSR_INDEX) {
        return FALSE;
    }
    if (list == NULL){
        return FALSE;
    }
    for (; count > 0; count--) {
        if (list[count - 1].MsrIndex == msr_index) {
            list[count - 1].MsrData = value;
            return TRUE;
        }
    }
    return FALSE;
}

/*
 * The input reg of index value of MSR must be less than the number of element
 * in g_msr_2_vmcs and g_msr_2_index. 
 */
UINT64 gcpu_get_msr_reg_internal_layered(const GUEST_CPU_HANDLE gcpu,
                VMM_IA32_MODEL_SPECIFIC_REGISTERS reg, VMCS_LEVEL level ) {
    VMCS_OBJECT* vmcs = vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level );
    UINT64 vmexit_store_msr_list_addr;
    UINT32 vmexit_store_msr_list_count;
    IA32_VMX_MSR_ENTRY* vmexit_store_msr_list_ptr = NULL;
    UINT64 value = 0;
    VM_EXIT_CONTROLS may1_vm_exit_ctrl = vmcs_hw_get_vmx_constraints()->may1_vm_exit_ctrl;

    VMM_ASSERT(gcpu);
    VMM_DEBUG_CODE(VMM_ASSERT(reg < NELEMENTS(g_msr_2_vmcs) &&
                       reg < NELEMENTS(g_msr_2_index)));

    if (((g_msr_2_vmcs[reg] == VMCS_GUEST_DEBUG_CONTROL) && (may1_vm_exit_ctrl.Bits.SaveDebugControls == 1)) ||
        ((g_msr_2_vmcs[reg] == VMCS_GUEST_SYSENTER_ESP) && (may1_vm_exit_ctrl.Bits.SaveSysEnterMsrs == 1)) ||
        ((g_msr_2_vmcs[reg] == VMCS_GUEST_SYSENTER_EIP) && (may1_vm_exit_ctrl.Bits.SaveSysEnterMsrs == 1)) ||
        ((g_msr_2_vmcs[reg] == VMCS_GUEST_SYSENTER_CS) && (may1_vm_exit_ctrl.Bits.SaveSysEnterMsrs == 1)) ||
        ((g_msr_2_vmcs[reg] == VMCS_GUEST_EFER) && (may1_vm_exit_ctrl.Bits.SaveEfer == 1)) ||
        ((g_msr_2_vmcs[reg] == VMCS_GUEST_PAT) && (may1_vm_exit_ctrl.Bits.SavePat == 1)) ||
        ((g_msr_2_vmcs[reg] == VMCS_GUEST_IA32_PERF_GLOBAL_CTRL) && (may1_vm_exit_ctrl.Bits.Load_IA32_PERF_GLOBAL_CTRL == 1))) {
        return vmcs_read( vmcs, g_msr_2_vmcs[reg] );
    }

    vmexit_store_msr_list_addr = vmcs_read(vmcs, VMCS_EXIT_MSR_STORE_ADDRESS);
    vmexit_store_msr_list_count = (UINT32)vmcs_read(vmcs, VMCS_EXIT_MSR_STORE_COUNT);

    VMM_ASSERT(0 == vmexit_store_msr_list_count ||
            ALIGN_BACKWARD((UINT64)vmexit_store_msr_list_addr, sizeof(IA32_VMX_MSR_ENTRY)) == (UINT64)vmexit_store_msr_list_addr);

    if ((level == VMCS_MERGED) ||
        (gcpu_get_guest_level(gcpu) == GUEST_LEVEL_1_SIMPLE)) {
        if ((vmexit_store_msr_list_count != 0) && (!hmm_hpa_to_hva(vmexit_store_msr_list_addr, (HVA*)&vmexit_store_msr_list_ptr))) {
            VMM_LOG(mask_anonymous, level_trace,"%s: Failed to translate HPA to HVA\n", __FUNCTION__);
            VMM_DEADLOOP();
        }
    }
    else {
        vmexit_store_msr_list_ptr = (IA32_VMX_MSR_ENTRY*)vmexit_store_msr_list_addr;
    }

    if (gcpu_get_msr_value_from_list(g_msr_2_index[reg], vmexit_store_msr_list_ptr, vmexit_store_msr_list_count, &value)) {
        return value;
    }
    // Will never reach here
    return 0;

}


UINT64 gcpu_get_msr_reg_layered(const GUEST_CPU_HANDLE gcpu,
                VMM_IA32_MODEL_SPECIFIC_REGISTERS reg, VMCS_LEVEL level )
{
    VMM_ASSERT(gcpu && IS_MODE_NATIVE(gcpu));

    return gcpu_get_msr_reg_internal_layered( gcpu, reg, level );
}


UINT64 gcpu_get_msr_reg_by_index_layered( GUEST_CPU_HANDLE gcpu,
                              UINT32 msr_index, VMCS_LEVEL level) {
    UINT32 i;
    UINT64 value = 0;
    BOOLEAN found = FALSE;
    VMCS_OBJECT* vmcs = vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level );
    UINT64 vmexit_store_msr_list_addr;
    UINT64 vmenter_load_msr_list_addr;
    UINT32 vmenter_load_msr_list_count;
    IA32_VMX_MSR_ENTRY* vmenter_load_msr_list_ptr = NULL;

    VMM_ASSERT(gcpu);

    for (i = 0; i < NELEMENTS(g_msr_2_index); i++) {
        if (g_msr_2_index[i] == msr_index) {
            value = gcpu_get_msr_reg_layered(gcpu, (VMM_IA32_MODEL_SPECIFIC_REGISTERS)i, level);
            found = TRUE;
            break;
        }
    }

    if (!found) {
        vmenter_load_msr_list_addr = vmcs_read(vmcs, VMCS_ENTER_MSR_LOAD_ADDRESS);
        vmenter_load_msr_list_count = (UINT32)vmcs_read(vmcs, VMCS_ENTER_MSR_LOAD_COUNT);

        VMM_ASSERT(0 == vmenter_load_msr_list_count ||
        ALIGN_BACKWARD((UINT64)vmenter_load_msr_list_addr, sizeof(IA32_VMX_MSR_ENTRY)) == (UINT64)vmenter_load_msr_list_addr);


        if ((level == VMCS_MERGED) || (gcpu_get_guest_level(gcpu) == GUEST_LEVEL_1_SIMPLE)) {
            if ((vmenter_load_msr_list_count != 0) && (!hmm_hpa_to_hva(vmenter_load_msr_list_addr, (HVA*)&vmenter_load_msr_list_ptr))) {
                VMM_LOG(mask_anonymous, level_trace,"%s: Failed to translate HPA %P to HVA (gcpu = %P ; vmcs = %P; msr_index = 0x%X)\n", __FUNCTION__, vmenter_load_msr_list_addr, gcpu, vmcs, msr_index);
                VMM_DEADLOOP();
            }
        }
        else {
            vmenter_load_msr_list_ptr = (IA32_VMX_MSR_ENTRY*)vmenter_load_msr_list_addr;
        }

        found = gcpu_get_msr_value_from_list(msr_index, vmenter_load_msr_list_ptr, vmenter_load_msr_list_count, &value);
                
        if (!found) {
            vmexit_store_msr_list_addr = vmcs_read(vmcs, VMCS_EXIT_MSR_STORE_ADDRESS);
            VMM_ASSERT(0 == vmcs_read(vmcs, VMCS_ENTER_MSR_LOAD_COUNT) ||
            ALIGN_BACKWARD((UINT64)vmexit_store_msr_list_addr, sizeof(IA32_VMX_MSR_ENTRY)) == (UINT64)vmexit_store_msr_list_addr);

            if (vmexit_store_msr_list_addr != vmenter_load_msr_list_addr) {
                IA32_VMX_MSR_ENTRY* vmexit_store_load_msr_list_ptr = NULL;
                UINT32 vmexit_store_msr_list_count = (UINT32)vmcs_read(vmcs, VMCS_ENTER_MSR_LOAD_COUNT);

                if ((level == VMCS_MERGED) ||
                    (gcpu_get_guest_level(gcpu) == GUEST_LEVEL_1_SIMPLE)) {
                    if ((vmexit_store_msr_list_count != 0) && (!hmm_hpa_to_hva(vmexit_store_msr_list_addr, (HVA*)&vmexit_store_load_msr_list_ptr))) {
                        VMM_LOG(mask_anonymous, level_trace,"%s: Failed to translate HPA %P to HVA\n", __FUNCTION__, vmexit_store_msr_list_addr);
                        VMM_DEADLOOP();
                    }
                }
                else {
                    vmexit_store_load_msr_list_ptr = (IA32_VMX_MSR_ENTRY*)vmexit_store_msr_list_addr;
                }
                found = gcpu_get_msr_value_from_list(msr_index, vmexit_store_load_msr_list_ptr, vmexit_store_msr_list_count, &value);
            }
        }
        if (!found) {
            if ( msr_index == IA32_MSR_GS_BASE )
                return value = vmcs_read(vmcs, VMCS_GUEST_GS_BASE);
            else if (msr_index == IA32_MSR_FS_BASE)
                return value = vmcs_read(vmcs, VMCS_GUEST_FS_BASE);

            value = hw_read_msr(msr_index);
        }
    }
    return value;
}

void gcpu_set_msr_reg_by_index_layered(GUEST_CPU_HANDLE gcpu, UINT32  msr_index,
                              UINT64  value, VMCS_LEVEL level) {
    UINT32 i;
    BOOLEAN found = FALSE;
    VMCS_OBJECT* vmcs = vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level );
    UINT64 vmexit_store_msr_list_addr;
    UINT64 vmenter_load_msr_list_addr;
    UINT32 vmenter_load_msr_list_count;
    IA32_VMX_MSR_ENTRY* vmenter_load_msr_list_ptr = NULL;

    VMM_ASSERT(gcpu);

    for (i = 0; i < NELEMENTS(g_msr_2_index); i++) {
        if (g_msr_2_index[i] == msr_index) {
            gcpu_set_msr_reg_layered(gcpu, (VMM_IA32_MODEL_SPECIFIC_REGISTERS)i, value, level);
            found = TRUE;
            break;
        }
    }

    if (!found) {
        vmenter_load_msr_list_addr = vmcs_read(vmcs, VMCS_ENTER_MSR_LOAD_ADDRESS);
        vmenter_load_msr_list_count = (UINT32)vmcs_read(vmcs, VMCS_ENTER_MSR_LOAD_COUNT);
        VMM_ASSERT(0 == vmenter_load_msr_list_count ||
        ALIGN_BACKWARD((UINT64)vmenter_load_msr_list_addr, sizeof(IA32_VMX_MSR_ENTRY)) == (UINT64)vmenter_load_msr_list_addr);

        if ((level == VMCS_MERGED) ||
            (gcpu_get_guest_level(gcpu) == GUEST_LEVEL_1_SIMPLE)) {
            if ((vmenter_load_msr_list_count != 0) && (!hmm_hpa_to_hva(vmenter_load_msr_list_addr, (HVA*)&vmenter_load_msr_list_ptr))) {
                VMM_LOG(mask_anonymous, level_trace,"%s: Failed to translate HPA %P to HVA (gcpu = %P ; vmcs = %P; msr_index = 0x%X)\n", __FUNCTION__, vmenter_load_msr_list_addr, gcpu, vmcs, msr_index);
                VMM_DEADLOOP();
            }
        }
        else {
            vmenter_load_msr_list_ptr = (IA32_VMX_MSR_ENTRY*)vmenter_load_msr_list_addr;
        }

        gcpu_set_msr_value_in_list(msr_index, value, vmenter_load_msr_list_ptr, vmenter_load_msr_list_count);

        vmexit_store_msr_list_addr = vmcs_read(vmcs, VMCS_EXIT_MSR_STORE_ADDRESS);
        VMM_ASSERT(0 == vmcs_read(vmcs, VMCS_ENTER_MSR_LOAD_COUNT) ||
        ALIGN_BACKWARD((UINT64)vmexit_store_msr_list_addr, sizeof(IA32_VMX_MSR_ENTRY)) == (UINT64)vmexit_store_msr_list_addr);

        if (vmexit_store_msr_list_addr != vmenter_load_msr_list_addr) {
            IA32_VMX_MSR_ENTRY* vmexit_store_load_msr_list_ptr = NULL;
            UINT32 vmexit_store_msr_list_count = (UINT32)vmcs_read(vmcs, VMCS_ENTER_MSR_LOAD_COUNT);

            if ((level == VMCS_MERGED) ||
                (gcpu_get_guest_level(gcpu) == GUEST_LEVEL_1_SIMPLE)) {
                if ((vmexit_store_msr_list_count != 0) && (!hmm_hpa_to_hva(vmexit_store_msr_list_addr, (HVA*)&vmexit_store_load_msr_list_ptr))) {
                    VMM_LOG(mask_anonymous, level_trace,"%s: Failed to translate HPA %P to HVA\n", __FUNCTION__, vmexit_store_msr_list_addr);
                    VMM_DEADLOOP();
                }
            }
            else {
                vmexit_store_load_msr_list_ptr = (IA32_VMX_MSR_ENTRY*)vmexit_store_msr_list_addr;
            }
            gcpu_set_msr_value_in_list(msr_index, value, vmexit_store_load_msr_list_ptr, vmexit_store_msr_list_count);
        }
    }
    if (!found) {
            hw_write_msr(msr_index, value);
    }
}

 //The input reg of index value of MSR must be less than the number of element
 //in g_msr_2_vmcs and g_msr_2_index. 
 void gcpu_set_msr_reg_layered(GUEST_CPU_HANDLE  gcpu, VMM_IA32_MODEL_SPECIFIC_REGISTERS reg,
                UINT64 value, VMCS_LEVEL level ) {
    VMCS_OBJECT* vmcs = vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, level );
    UINT64 vmexit_store_msr_list_addr;
    UINT64 vmenter_load_msr_list_addr;
    UINT32 vmenter_load_msr_list_count;
    IA32_VMX_MSR_ENTRY* vmenter_load_msr_list_ptr = NULL;
    VM_EXIT_CONTROLS may1_vm_exit_ctrl = vmcs_hw_get_vmx_constraints()->may1_vm_exit_ctrl;

    VMM_ASSERT(gcpu);
    VMM_DEBUG_CODE(VMM_ASSERT(reg<NELEMENTS(g_msr_2_vmcs) && reg<NELEMENTS(g_msr_2_index)));

    if (reg == IA32_VMM_MSR_EFER) {
        SET_IMPORTANT_EVENT_OCCURED_FLAG(gcpu);

        if (level != VMCS_LEVEL_1) {
            /*
            ** If EFER is changed, update VMCS_ENTER_CONTROL_VECTOR.Ia32eModeGuest
            ** accordingly. It is not done for Lvl-1 in order not to hide
            ** possible 3rd party bugs.
            */
            VM_ENTRY_CONTROLS  entry_ctrl_mask;
            entry_ctrl_mask.Uint32 = 0;
            entry_ctrl_mask.Bits.Ia32eModeGuest = 1;

            // Update IA32e and LMA based on LME (since PG is always 1)
            if (!IS_MODE_UNRESTRICTED_GUEST(gcpu)) {
                vmcs_update(vmcs, VMCS_ENTER_CONTROL_VECTOR,
                        (value & EFER_LME) ? UINT64_ALL_ONES : 0 ,
                        (UINT64) entry_ctrl_mask.Uint32);
                /* IA Manual 3B: 27.9.4
                    If the “load IA32_EFER” VM-entry control is 1, the value of 
                    the LME and LMA bits in the IA32_EFER field in the guest-state
                    area must be the value of the “IA-32e-mode guest” VM-exit 
                    control. Otherwise, the VM entry fails. */
                if (value & EFER_LME)
                    value |= EFER_LMA;
                else
                    value &= ~EFER_LMA;
            }
        }
    }

    if (((g_msr_2_vmcs[reg] == VMCS_GUEST_DEBUG_CONTROL) && (may1_vm_exit_ctrl.Bits.SaveDebugControls == 1)) ||
        ((g_msr_2_vmcs[reg] == VMCS_GUEST_SYSENTER_ESP) && (may1_vm_exit_ctrl.Bits.SaveSysEnterMsrs == 1)) ||
        ((g_msr_2_vmcs[reg] == VMCS_GUEST_SYSENTER_EIP) && (may1_vm_exit_ctrl.Bits.SaveSysEnterMsrs == 1)) ||
        ((g_msr_2_vmcs[reg] == VMCS_GUEST_SYSENTER_CS) && (may1_vm_exit_ctrl.Bits.SaveSysEnterMsrs == 1)) ||
        ((g_msr_2_vmcs[reg] == VMCS_GUEST_EFER) && (may1_vm_exit_ctrl.Bits.SaveEfer == 1)) ||
        ((g_msr_2_vmcs[reg] == VMCS_GUEST_PAT) && (may1_vm_exit_ctrl.Bits.SavePat == 1)) ||
        ((g_msr_2_vmcs[reg] == VMCS_GUEST_IA32_PERF_GLOBAL_CTRL) && (may1_vm_exit_ctrl.Bits.Load_IA32_PERF_GLOBAL_CTRL == 1))) {

        vmcs_write( vmcs, g_msr_2_vmcs[reg], value );
        return;
    }

    vmenter_load_msr_list_addr = vmcs_read(vmcs, VMCS_ENTER_MSR_LOAD_ADDRESS);
    vmenter_load_msr_list_count = (UINT32)vmcs_read(vmcs, VMCS_ENTER_MSR_LOAD_COUNT);

    VMM_ASSERT(0 == vmenter_load_msr_list_count ||
    ALIGN_BACKWARD((UINT64)vmenter_load_msr_list_addr, sizeof(IA32_VMX_MSR_ENTRY)) == (UINT64)vmenter_load_msr_list_addr);

    if ((level == VMCS_MERGED) || (gcpu_get_guest_level(gcpu) == GUEST_LEVEL_1_SIMPLE)) {
        if ((vmenter_load_msr_list_count != 0) && (!hmm_hpa_to_hva(vmenter_load_msr_list_addr, (HVA*)&vmenter_load_msr_list_ptr))) {
            VMM_LOG(mask_anonymous, level_trace,"%s: Failed to translate HPA %P to HVA (gcpu = %P ; vmcs = %P; reg = %d)\n", __FUNCTION__, vmenter_load_msr_list_addr, gcpu, vmcs, reg);
            VMM_DEADLOOP();
        }
    }
    else {
        vmenter_load_msr_list_ptr = (IA32_VMX_MSR_ENTRY*)vmenter_load_msr_list_addr;
    }

    if (!gcpu_set_msr_value_in_list(g_msr_2_index[reg], value, vmenter_load_msr_list_ptr, vmenter_load_msr_list_count)) {
        if (g_msr_2_vmcs[reg] != VMCS_FIELD_COUNT) {
            vmcs_write( vmcs, g_msr_2_vmcs[reg], value );
        }
    }

    vmexit_store_msr_list_addr = vmcs_read(vmcs, VMCS_EXIT_MSR_STORE_ADDRESS);
    VMM_ASSERT(0 == vmcs_read(vmcs, VMCS_ENTER_MSR_LOAD_COUNT) ||
    ALIGN_BACKWARD((UINT64)vmexit_store_msr_list_addr, sizeof(IA32_VMX_MSR_ENTRY)) == (UINT64)vmexit_store_msr_list_addr);

    if (vmexit_store_msr_list_addr != vmenter_load_msr_list_addr) {
        IA32_VMX_MSR_ENTRY* vmexit_store_load_msr_list_ptr = NULL;
        UINT32 vmexit_store_msr_list_count = (UINT32)vmcs_read(vmcs, VMCS_ENTER_MSR_LOAD_COUNT);

        if ((level == VMCS_MERGED) ||
            (gcpu_get_guest_level(gcpu) == GUEST_LEVEL_1_SIMPLE)) {
            if ((vmexit_store_msr_list_count != 0) && (!hmm_hpa_to_hva(vmexit_store_msr_list_addr, (HVA*)&vmexit_store_load_msr_list_ptr))) {
                VMM_LOG(mask_anonymous, level_trace,"%s: Failed to translate HPA %P to HVA\n", __FUNCTION__, vmexit_store_msr_list_addr);
                VMM_DEADLOOP();
            }
        }
        else {
            vmexit_store_load_msr_list_ptr = (IA32_VMX_MSR_ENTRY*)vmexit_store_msr_list_addr;
        }

        gcpu_set_msr_value_in_list(g_msr_2_index[reg], value, vmexit_store_load_msr_list_ptr, vmexit_store_msr_list_count);
    }
}

void gcpu_skip_guest_instruction( GUEST_CPU_HANDLE gcpu )
{
    VMCS_OBJECT *vmcs = vmcs_hierarchy_get_vmcs( &gcpu->vmcs_hierarchy, VMCS_MERGED );
    UINT64 inst_length = vmcs_read(vmcs, VMCS_EXIT_INFO_INSTRUCTION_LENGTH);
    UINT64 rip         = vmcs_read(vmcs, VMCS_GUEST_RIP);

    vmcs_write(vmcs, VMCS_GUEST_RIP, rip + inst_length);
    report_uvmm_event(UVMM_EVENT_SINGLE_STEPPING_CHECK, (VMM_IDENTIFICATION_DATA)gcpu, (const GUEST_VCPU*)guest_vcpu(gcpu), NULL);
}

GUEST_LEVEL_ENUM gcpu_get_guest_level(GUEST_CPU_HANDLE gcpu)
{
    return (GUEST_LEVEL_ENUM) gcpu->last_guest_level;
}

#ifdef INCLUDE_UNUSED_CODE
void gcpu_set_guest_level(GUEST_CPU_HANDLE gcpu, GUEST_LEVEL_ENUM guest_level)
{
    gcpu->last_guest_level = (UINT8) guest_level;
}
#endif

#ifdef INCLUDE_UNUSED_CODE
GUEST_LEVEL_ENUM gcpu_get_next_guest_level(GUEST_CPU_HANDLE gcpu)
{
    return (GUEST_LEVEL_ENUM) gcpu->next_guest_level;
}
#endif

void gcpu_set_next_guest_level(GUEST_CPU_HANDLE gcpu, GUEST_LEVEL_ENUM guest_level)
{
    gcpu->next_guest_level = (UINT8) guest_level;
}

static UINT64 gcpu_read_pdpt_entry_from_memory(void* pdpte_ptr) {
    volatile UINT64* pdpte = (volatile UINT64*)pdpte_ptr;
    UINT64 value1 = *pdpte;
    UINT64 value2 = *pdpte;

    while (value1 != value2) {
        value1 = value2;
        value2 = *pdpte;
    }

    return value1;
}

#ifdef INCLUDE_UNUSED_CODE
UINT64 gcpu_read_get_32_bit_pdpt_entry(GUEST_CPU_HANDLE gcpu, UINT32 entry_index) {
    // TODO: read PDPTE from VMCS in v2
    UINT64 cr3 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR3);
    GUEST_HANDLE guest_handle = gcpu_guest_handle(gcpu);
    GPM_HANDLE gpm_handle = gcpu_get_current_gpm(guest_handle);
    GPA pdpt_gpa;
    HVA pdpt_hva;
    UINT64* pdpte;

    VMM_ASSERT(entry_index < PW_NUM_OF_PDPT_ENTRIES_IN_32_BIT_MODE);
    VMM_ASSERT(gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR0) & CR0_PG);
    VMM_ASSERT(gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR0) & CR0_PE);
    VMM_ASSERT(gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR4) & CR4_PAE);

    pdpt_gpa = ALIGN_BACKWARD(cr3, PW_SIZE_OF_PAE_ENTRY * PW_NUM_OF_PDPT_ENTRIES_IN_32_BIT_MODE);
    if (!gpm_gpa_to_hva(gpm_handle, pdpt_gpa, &pdpt_hva)) {
        VMM_LOG(mask_anonymous, level_trace,"%s: Failed to retrieve pointer to guest PDPT\n", __FUNCTION__);
        VMM_DEADLOOP();
    }

    pdpte = (UINT64*)(pdpt_hva + (PW_SIZE_OF_PAE_ENTRY * entry_index));
    return gcpu_read_pdpt_entry_from_memory(pdpte);
}
#endif

BOOLEAN gcpu_get_32_bit_pdpt(GUEST_CPU_HANDLE gcpu, void* pdpt_ptr) {
    // TODO: read PDPTE from VMCS in v2
    UINT64* pdpt_out = (UINT64*)pdpt_ptr;
    UINT64 cr3 = gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR3);
    GUEST_HANDLE guest_handle = gcpu_guest_handle(gcpu);
    GPM_HANDLE gpm_handle = gcpu_get_current_gpm(guest_handle);
    GPA pdpt_gpa;
    HVA pdpt_hva;
    UINT32 i;

    if (!IS_MODE_UNRESTRICTED_GUEST(gcpu)) {
        // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
        VMM_ASSERT(gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR0) & CR0_PG);
        // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
        VMM_ASSERT(gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR0) & CR0_PE);
    }
    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR4) & CR4_PAE);

    pdpt_gpa = ALIGN_BACKWARD(cr3, (UINT64)(PW_SIZE_OF_PAE_ENTRY * PW_NUM_OF_PDPT_ENTRIES_IN_32_BIT_MODE));
    if (!gpm_gpa_to_hva(gpm_handle, pdpt_gpa, &pdpt_hva)) {
        VMM_LOG(mask_anonymous, level_trace,"%s: Failed to retrieve pointer to guest PDPT\n", __FUNCTION__);
//        VMM_DEADLOOP();
        return FALSE;
    }

    for (i = 0; i < PW_NUM_OF_PDPT_ENTRIES_IN_32_BIT_MODE; i++) {
        UINT64* pdpte = (UINT64*)(pdpt_hva + (PW_SIZE_OF_PAE_ENTRY * i));
        pdpt_out[i] = gcpu_read_pdpt_entry_from_memory(pdpte);
    }
    return TRUE;
}

void gcpu_load_segment_reg_from_gdt( GUEST_CPU_HANDLE guest_cpu, UINT64 gdt_base,
                    UINT16 selector, VMM_IA32_SEGMENT_REGISTERS  reg_id)
{
    ADDRESS base;
    UINT32  limit;
    UINT32  attributes;
    VMM_STATUS status;

    status = hw_gdt_parse_entry((UINT8 *) gdt_base, selector, &base, &limit, &attributes);
    VMM_ASSERT(status == VMM_OK);
    gcpu_set_segment_reg(guest_cpu, reg_id, selector, base, limit, attributes);
}

void *gcpu_get_vmdb(GUEST_CPU_HANDLE gcpu)
{
    return gcpu->vmdb;
}

void gcpu_set_vmdb(GUEST_CPU_HANDLE gcpu, void * vmdb)
{
    gcpu->vmdb = vmdb;
}


void * gcpu_get_timer(GUEST_CPU_HANDLE gcpu)
{
    return gcpu->timer;
}

void gcpu_assign_timer(GUEST_CPU_HANDLE gcpu, void *timer)
{
    gcpu->timer = timer;
}

#pragma pack(1)
/// ARBTYE format
typedef union arch_arbyte_s {
    UINT32 as_uint32;
    struct {
        UINT32 type:4;                 /* bits 3:0   */
        UINT32 s_bit:1;                /* bit  4     */
        UINT32 dpl:2;                  /* bit2 6:5   */
        UINT32 p_bit:1;                /* bit  7     */
        UINT32 reserved_11_8:4;        /* bits 11:8  */
        UINT32 avl_bit:1;              /* bit  12    */
        UINT32 l_bit:1;                /* bit  13    */
        UINT32 db_bit:1;               /* bit  14    */
        UINT32 g_bit:1;                /* bit  15    */
        UINT32 null_bit:1;             /* bit  16    */
        UINT32 reserved_31_17:15;      /* bits 31:17 */
    } bits;
} arch_arbyte_t;

typedef struct seg_reg64_s {
    UINT16            selector;
    UINT64            base;
    UINT32            limit;
    arch_arbyte_t arbyte;
} seg_reg64_t;

#pragma pack()

static void arch_make_segreg_real_mode_compliant( seg_reg64_t *p_segreg,
                    VMM_IA32_SEGMENT_REGISTERS  reg_id)
{
    BOOLEAN g_must_be_zero = FALSE;
    BOOLEAN g_must_be_one = FALSE;

    // if LDTR points to NULL entry, mark as unusable
    if (p_segreg->selector < 8 && IA32_SEG_LDTR == reg_id) {
        p_segreg->arbyte.bits.null_bit = 1;
    }
    // TR and CS must be usable !!!
    if (IA32_SEG_TR == reg_id || IA32_SEG_CS == reg_id) {
        p_segreg->arbyte.bits.null_bit = 0;
    }
    if (1 == p_segreg->arbyte.bits.null_bit) {
        return;
    }
    // Assume we run in Ring-0
    BITMAP_CLR(p_segreg->selector, 7); // Clear TI-flag and RPL
    p_segreg->arbyte.as_uint32 &= 0xF0FF;   // clear all reserved
    p_segreg->arbyte.bits.dpl   = 0;        // Assume we run in Ring-0
    p_segreg->arbyte.bits.p_bit = 1;
    // p_segreg->arbyte.bits.db_bit = 1;

    /*
    Set Granularity bit
    If any bit in the limit field in the range 11:0 is 0, G must be 0.
    If any bit in the limit field in the range 31:20 is 1, G must be 1.
    */
    if (0xFFF != (p_segreg->limit & 0xFFF))
        g_must_be_zero = TRUE;
    if (0 != (p_segreg->limit & 0xFFF00000))
        g_must_be_one = TRUE;

    // BEFORE_VMLAUNCH. CRITICAL check that should not fail.
    VMM_ASSERT(FALSE == g_must_be_zero || FALSE == g_must_be_one);

    if (g_must_be_one)
        p_segreg->arbyte.bits.g_bit = 1;
    else
        p_segreg->arbyte.bits.g_bit = 0;

    switch (reg_id) {
    case IA32_SEG_CS:
        p_segreg->arbyte.bits.type = 0xB;   // Execute/Read, accessed
        p_segreg->arbyte.bits.s_bit = 1;
        p_segreg->arbyte.bits.l_bit = 0;    // 32-bit mode
        break;

    case IA32_SEG_SS:
        case IA32_SEG_DS:
    case IA32_SEG_ES:
    case IA32_SEG_FS:
    case IA32_SEG_GS:
        p_segreg->arbyte.bits.type |= 3;     // Read/Write, accessed
        p_segreg->arbyte.bits.s_bit = 1;
        break;

    case IA32_SEG_LDTR:
        BIT_CLR(p_segreg->selector, 2); // TI-flag must be cleared
        p_segreg->arbyte.bits.s_bit = 0;
        p_segreg->arbyte.bits.type  = 2;
    case IA32_SEG_TR:
        BIT_CLR(p_segreg->selector, 2); // TI-flag must be cleared
        p_segreg->arbyte.bits.s_bit = 0;
        p_segreg->arbyte.bits.type  = 11;
        break;

    default:
        break;
    }
}

void make_segreg_hw_real_mode_compliant( GUEST_CPU_HANDLE gcpu , UINT16 selector, 
            UINT64 base, UINT32 limit, UINT32 attr, VMM_IA32_SEGMENT_REGISTERS  reg_id)
{
    seg_reg64_t      segreg;

    segreg.selector = selector;
    segreg.base = base;
    segreg.limit = limit;
    segreg.arbyte.as_uint32 = attr;
    arch_make_segreg_real_mode_compliant(&segreg, reg_id);
    gcpu_set_segment_reg(gcpu, reg_id, segreg.selector,
                         segreg.base, segreg.limit, segreg.arbyte.as_uint32);
}
#pragma warning( pop )
