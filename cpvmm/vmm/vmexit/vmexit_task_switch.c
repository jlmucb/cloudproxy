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

#include "vmm_defs.h"
#include "guest_cpu.h"
#include "isr.h"
#include "vmx_vmcs.h"
#include "guest_cpu_vmenter_event.h"
#include "host_memory_manager_api.h"

/////////////////////////////////////////////////////////////////////////////
// This is 32-bit TSS.

#pragma pack(1)
typedef struct {
    UINT32  prev_tr;            // 0
    UINT32  esp0;               // 4
    UINT32  ss0;                // 8
    UINT32  esp1;               // 12
    UINT32  ss1;                // 16
    UINT32  esp2;               // 20
    UINT32  ss2;                // 24
    UINT32  cr3;                // 28
    UINT32  eip;                // 32
    UINT32  eflags;             // 36
    UINT32  eax;                // 40
    UINT32  ecx;                // 44
    UINT32  edx;                // 48
    UINT32  ebx;                // 52
    UINT32  esp;                // 56
    UINT32  ebp;                // 60
    UINT32  esi;                // 64
    UINT32  edi;                // 68
    UINT32  es;                 // 72
    UINT32  cs;                 // 76
    UINT32  ss;                 // 80
    UINT32  ds;                 // 84
    UINT32  fs;                 // 88
    UINT32  gs;                 // 92
    UINT32  ldtr;               // 96
    UINT32  io_base_addr;       // 100
} tss32_t;
#pragma pack()

/////////////////////////////////////////////////////////////////////////////
// Only three 32-bit registers are used during task switch.  They are not to
// be shared with VMM.  VMM works with 64-bit values.

typedef union {
    UINT32 value;
    struct {
        UINT32 carry:1;
        UINT32 rsvd_1:1;
        UINT32 parity:1;
        UINT32 rsvd_3:1;
        UINT32 adjust:1;
        UINT32 rsvd_5:1;
        UINT32 zero:1;
        UINT32 sign:1;
        UINT32 trap:1;
        UINT32 intr_enable:1;
        UINT32 direction:1;
        UINT32 overflow:1;
        UINT32 iopl:2;
        UINT32 nested_task:1;
        UINT32 rsvd_15:1;
        UINT32 resume:1;
        UINT32 v86_mode:1;
        UINT32 align_chk:1;
        UINT32 v_intr:1;
        UINT32 v_intr_pend:1;
        UINT32 ident:1;
        UINT32 rsvd_31_22:10;
    } bits;
} eflags_t;

typedef union {
    UINT32 value;
    struct {
        UINT32 pe:1;            // bit  0     Protection Enable
        UINT32 mp:1;            // bit  1     Monitor Coprocessor
        UINT32 em:1;            // bit  2     Emulation
        UINT32 ts:1;            // bit  3     Task Switched
        UINT32 et:1;            // bit  4     Extension Type
        UINT32 ne:1;            // bit  5     Numeric Error
        UINT32 rsvd_15_6:10;    // bits 15:6  Reserved
        UINT32 wp:1;            // bit  16    Write Protect
        UINT32 rsvd_17:1;       // bit  17    Reserved
        UINT32 am:1;            // bit  18    Alignment Mask
        UINT32 rsvd_28_19:10;   // bits 28:19 Reserved
        UINT32 nw:1;            // bit  29    Not Write-through
        UINT32 cd:1;            // bit  30    Cache Disable
        UINT32 pg:1;            // bit  31    Paging
    } bits;
} cr0_t;

typedef union {
    UINT32 value;
    struct {
        UINT32 l0:1;            // bit 0  local b.p. enable
        UINT32 g0:1;            // bit 1  global b.p. enable
        UINT32 l1:1;            // bit 2  local b.p. enable
        UINT32 g1:1;            // bit 3  global b.p. enable
        UINT32 l2:1;            // bit 4  local b.p. enable
        UINT32 g2:1;            // bit 5  global b.p. enable
        UINT32 l3:1;            // bit 6  local b.p. enable
        UINT32 g3:1;            // bit 7  global b.p. enable
        UINT32 le:1;            // bit 8  local exact b.p. enable
        UINT32 ge:1;            // bit 9  global exact b.p. enable
        UINT32 rsvd_12_10:3;    // bits 12:10 Reserved
        UINT32 gd:1;            // bit 13 general detect enable
        UINT32 rsvd_15_14:2;    // bits 15:14 Reserved
        UINT32 rw0:2;           // bits 17:16
        UINT32 len0:2;          // bits 19:18
        UINT32 rw1:2;           // bits 21:20
        UINT32 len1:2;          // bits 23:22
        UINT32 rw2:2;           // bits 25:24
        UINT32 len2:2;          // bits 27:26
        UINT32 rw3:2;           // bits 29:28
        UINT32 len3:2;          // bits 31:30
    } bits;
} dr7_t;

/////////////////////////////////////////////////////////////////////////////
// This is 32-bit selector and descriptor.

typedef union {
    UINT32 value;
    struct {
        UINT32 type:4;          // bits 3:0
        UINT32 s_bit:1;         // bit  4
        UINT32 dpl:2;           // bit2 6:5
        UINT32 p_bit:1;         // bit  7
        UINT32 rsvd_11_8:4;     // bits 11:8
        UINT32 avl_bit:1;       // bit  12
        UINT32 l_bit:1;         // bit  13
        UINT32 db_bit:1;        // bit  14
        UINT32 g_bit:1;         // bit  15
        UINT32 null_bit:1;      // bit  16
        UINT32 rsvd_31_17:15;   // bits 31:17
    } bits;
} ar_t;

#pragma warning(push)
#pragma warning(disable: 4820)
// Two-byte padding after selector is ok.
typedef struct {
    UINT16      selector;
    UINT32      base;
    UINT32      limit;
    ar_t        ar;
} seg_reg_t;
#pragma warning(pop)

typedef union {
    UINT64 value;
    struct {
        UINT32 limit_15_00:16;  // bits 15:0
        UINT32 base_15_00:16;   // bits 31:16
        UINT32 base_23_16:8;    // bits 39:32
        UINT32 type:4;          // bits 43:40
        UINT32 s_bit:1;         // bit  44
        UINT32 dpl:2;           // bit2 46:45
        UINT32 p_bit:1;         // bit  47
        UINT32 limit_19_16:4;   // bits 51:48
        UINT32 avl_bit:1;       // bit  52
        UINT32 l_bit:1;         // bit  53
        UINT32 db_bit:1;        // bit  54
        UINT32 g_bit:1;         // bit  55
        UINT32 base_31_24:8;    // bits 63:56
    } bits;
} desc_t;

// Types for (s_bit == 0).
#define Tss32Aval           (0x9)
#define Tss32Busy           (0xb)
#define IsLdt(type)         ((type) == 0x2)
#define IsTss32Aval(type)   ((type) == Tss32Aval)
#define IsTss32Busy(type)   ((type) == Tss32Busy)
#define IsTss32(type)       (IsTss32Aval(type) || IsTss32Busy(type))

// Types for (s_bit == 1).
#define SetAssessed(type)   type |= 0x1
#define IsAssessed(type)    (((type) & 0x1) != 0)
#define IsDataRW(type)      (((type) & 0xa) == 0x2)
#define IsCode(type)        (((type) & 0x8) != 0)
#define IsCodeR(type)       (((type) & 0xa) == 0xa)
#define IsCodeConform(type) (((type) & 0xc) == 0xc)

// Selector fields.
#define SelectorIdx(sel)    ((sel) & 0xfff8)
#define SelectorGdt(sel)    (((sel) & 0x0004) == 0)
#define SelectorRpl(sel)    ((sel) & 0x0003)

/////////////////////////////////////////////////////////////////////////////

int
copy_from_gva(GUEST_CPU_HANDLE gcpu, UINT64 gva, UINT32 size, UINT64 hva)
{
    UINT64 dst_hva = 0;
    UINT64 src_gva = gva;
    UINT8  *local_ptr = (UINT8*)hva;
    UINT32 size_remaining = size;
    UINT32 size_copied = 0;

    while (size_remaining) {
        if (!gcpu_gva_to_hva(gcpu, (GVA)src_gva, (HVA *)&dst_hva)) {
            VMM_LOG(mask_uvmm, level_error,"%s: Invalid Parameter Struct Address %P\n", __FUNCTION__, src_gva);
            return -1;
        }
        /* Copy until end */
        if(src_gva >(UINT64_ALL_ONES-size_remaining))
        {
            VMM_LOG(mask_uvmm,level_error,"Error: Size bounds exceeded\n");
            return -1;
        }
        if ((src_gva + size_remaining) <= (src_gva | PAGE_4KB_MASK)) {
            vmm_memcpy((void*)local_ptr, (void*)dst_hva, size_remaining);
            return 0;
        } else {
            /* Copy until end of page */
            size_copied = (UINT32)
                          (((src_gva + PAGE_4KB_SIZE) & ~PAGE_4KB_MASK) - src_gva);

            vmm_memcpy((void*)local_ptr, (void*)dst_hva, size_copied);

            /* Adjust size and pointers for next copy */
            size_remaining -= size_copied;
            local_ptr += size_copied;
            src_gva += size_copied;
        }
    }

    return 0;
}

/////////////////////////////////////////////////////////////////////////////

static int
copy_to_gva(GUEST_CPU_HANDLE gcpu, UINT64 gva, UINT32 size, UINT64 hva)
{
    UINT64 dst_gva = gva;
    UINT64 src_hva = 0;
    UINT8  *local_ptr = (UINT8*)hva;
    UINT32 size_remaining = size;
    UINT32 size_copied = 0;

    while (size_remaining) {
        if (!gcpu_gva_to_hva(gcpu, dst_gva, &src_hva)) {
            VMM_LOG(mask_uvmm, level_error,"%s: Invalid guest pointer Address %P\n", __FUNCTION__, gva);
            return -1;
        }
        /* Copy until end */
        if(dst_gva >(UINT64_ALL_ONES-size_remaining))
        {
            VMM_LOG(mask_uvmm,level_error,"Error: Size bounds exceeded\n");
            return -1;
        }
        if ((dst_gva + size_remaining) <= (dst_gva | PAGE_4KB_MASK)) {
            vmm_memcpy((void*)src_hva, (void*)local_ptr, size_remaining);
            return 0;
        } else {
            /* Copy until end of page */
            size_copied = (UINT32)
                          (((dst_gva + PAGE_4KB_SIZE) & ~PAGE_4KB_MASK) - dst_gva);

            vmm_memcpy((void*)src_hva, (void*)local_ptr, size_copied);

            /* Adjust size and pointers for next copy */
            size_remaining -= size_copied;
            local_ptr += size_copied;
            dst_gva += size_copied;
        }
    }

    return 0;
}

/////////////////////////////////////////////////////////////////////////////

static void parse_desc(desc_t *dsc, seg_reg_t *seg)
{
    seg->base =
        (dsc->bits.base_15_00) |
        (dsc->bits.base_23_16 << 16) |
        (dsc->bits.base_31_24 << 24);

    seg->limit =
        (dsc->bits.limit_15_00) |
        (dsc->bits.limit_19_16 << 16);

    seg->ar.value = 0;
    seg->ar.bits.type       = dsc->bits.type;
    seg->ar.bits.s_bit      = dsc->bits.s_bit;
    seg->ar.bits.dpl        = dsc->bits.dpl;
    seg->ar.bits.p_bit      = dsc->bits.p_bit;
    seg->ar.bits.avl_bit    = dsc->bits.avl_bit;
    seg->ar.bits.l_bit      = dsc->bits.l_bit;
    seg->ar.bits.db_bit     = dsc->bits.db_bit;
    seg->ar.bits.g_bit      = dsc->bits.g_bit;
}

/////////////////////////////////////////////////////////////////////////////

static void get_task_info(GUEST_CPU_HANDLE gcpu, UINT32 *type, UINT16 *sel, IA32_VMX_VMCS_VM_EXIT_INFO_IDT_VECTORING vect)
{
    VMCS_OBJECT *vmcs = gcpu_get_vmcs(gcpu);
    IA32_VMX_EXIT_QUALIFICATION qual;
    

    qual.Uint64 =  vmcs_read(vmcs, VMCS_EXIT_INFO_QUALIFICATION);

    *type = (UINT32)(qual.TaskSwitch.Source);
    *sel  = (UINT16)(qual.TaskSwitch.TssSelector);

    if ((*type == TASK_SWITCH_TYPE_IDT) && IsSoftwareVector(vect))
        *type = TASK_SWITCH_TYPE_CALL;
}

/////////////////////////////////////////////////////////////////////////////

static void force_ring3_ss(GUEST_CPU_HANDLE gcpu)
{
    seg_reg_t ss;
    cr0_t cr0;
    eflags_t flags;

    cr0.value =
        (UINT32)gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR0);

    flags.value = (UINT32)gcpu_get_gp_reg(gcpu, IA32_REG_RFLAGS);

    if ((cr0.bits.pe == 0) || (flags.bits.v86_mode == 1))
        return;

    gcpu_get_segment_reg(
        gcpu,
        IA32_SEG_TR,
        (UINT16 *)&(ss.selector),
        (UINT64 *)&(ss.base),
        (UINT32 *)&(ss.limit),
        (UINT32 *)&(ss.ar)
        );

    ss.ar.bits.dpl = 3;

    gcpu_set_segment_reg(
        gcpu,
        IA32_SEG_SS,
        ss.selector,
        ss.base,
        ss.limit,
        ss.ar.value
        );
    return;
}

/////////////////////////////////////////////////////////////////////////////
// Set guest LDTR according to new tss.

static int
set_guest_ldtr(GUEST_CPU_HANDLE gcpu, seg_reg_t *gdtr, seg_reg_t *ldtr, tss32_t *tss)
{
    desc_t desc;
    int r;

    vmm_memset(ldtr, 0, sizeof(seg_reg_t));
    ldtr->selector = (UINT16)tss->ldtr;

    if (SelectorIdx(ldtr->selector) == 0)
    {
        ldtr->ar.bits.null_bit = 1;
        return 0;
    }

    if (!SelectorGdt(ldtr->selector)) // must be in gdt
    {
        force_ring3_ss(gcpu);
        gcpu_inject_ts(gcpu, ldtr->selector);
        return -1;
    }

    r = copy_from_gva(gcpu,
        (UINT64)(gdtr->base + SelectorIdx(ldtr->selector)),
        sizeof(desc),
        (UINT64)(&desc)
        );

    if (r != 0)
    {
        force_ring3_ss(gcpu);
        gcpu_inject_ts(gcpu, ldtr->selector);
        return -1;
    }

    parse_desc(&desc, ldtr);

    if ((ldtr->ar.bits.s_bit != 0) ||   // must be sys desc
        !IsLdt(ldtr->ar.bits.type) ||   // must be ldt
        (ldtr->ar.bits.p_bit != 1))     // must be present
    {
        force_ring3_ss(gcpu);
        gcpu_inject_ts(gcpu, ldtr->selector);
        return -1;
    }

    gcpu_set_segment_reg(
        gcpu,
        IA32_SEG_LDTR,
        ldtr->selector,
        ldtr->base,
        ldtr->limit,
        ldtr->ar.value
        );

    return 0;
}

/////////////////////////////////////////////////////////////////////////////
// Set guest SS according to new tss.

static int
set_guest_ss(GUEST_CPU_HANDLE gcpu, seg_reg_t *gdtr, seg_reg_t *ldtr, tss32_t *tss)
{
    desc_t desc;
    seg_reg_t ss;
    seg_reg_t *dtr;
    UINT32 cpl;
    int r;

    vmm_memset(&ss, 0, sizeof(ss));
    ss.selector = (UINT16)tss->ss;
    cpl = SelectorRpl(tss->cs);

    if (SelectorIdx(ss.selector) == 0) // must not be null
    {
        force_ring3_ss(gcpu);
        gcpu_inject_ts(gcpu, ss.selector);
        return -1;
    }

    dtr = SelectorGdt(ss.selector)? gdtr:ldtr;

    r = copy_from_gva(gcpu,
            (UINT64)(dtr->base + SelectorIdx(ss.selector)),
            sizeof(desc),
            (UINT64)(&desc)
            );

    if (r != 0)
    {
        force_ring3_ss(gcpu);
        gcpu_inject_ts(gcpu, ss.selector);
        return -1;
    }

    parse_desc(&desc, &ss);

    if (ss.ar.bits.p_bit == 0) // must be present
    {
        force_ring3_ss(gcpu);
        gcpu_inject_ss(gcpu, ss.selector);
        return -1;
    }

    if ((ss.ar.bits.s_bit == 0) ||      // must be non-sys desc
        IsCode(ss.ar.bits.type) ||      // must not be code
        !IsDataRW(ss.ar.bits.type) ||   // must be data with r/w
        (ss.ar.bits.dpl != cpl) ||
        ((UINT32)SelectorRpl(ss.selector) != cpl))
    {
        force_ring3_ss(gcpu);
        gcpu_inject_ts(gcpu, ss.selector);
        return -1;
    }

    // If g_bit is set, the unit is 4 KB.
    if (ss.ar.bits.g_bit == 1)
        ss.limit = (ss.limit << 12) | 0xfff;

    if (!IsAssessed(ss.ar.bits.type))
    {
        SetAssessed(ss.ar.bits.type);
        SetAssessed(desc.bits.type);

        r = copy_to_gva(gcpu,
            (UINT64)(dtr->base + SelectorIdx(ss.selector)),
            sizeof(desc),
            (UINT64)(&desc)
            );

        if (r != 0)
        {
            force_ring3_ss(gcpu);
            gcpu_inject_ts(gcpu, ss.selector);
            return -1;
        }
    }

    gcpu_set_segment_reg(
        gcpu,
        IA32_SEG_SS,
        ss.selector,
        ss.base,
        ss.limit,
        ss.ar.value
        );

    return 0;
}

/////////////////////////////////////////////////////////////////////////////
// Set guest CS according to new tss.

static int
set_guest_cs(GUEST_CPU_HANDLE gcpu, seg_reg_t *gdtr, seg_reg_t *ldtr, tss32_t *tss)
{
    desc_t desc;
    seg_reg_t cs;
    seg_reg_t *dtr;
    UINT32 cpl;
    int r;

    vmm_memset(&cs, 0, sizeof(cs));
    cs.selector = (UINT16)tss->cs;
    cpl = SelectorRpl(tss->cs);

    if (SelectorIdx(cs.selector) == 0) // must not be null
    {
        gcpu_inject_ts(gcpu, cs.selector);
        return -1;
    }

    dtr = SelectorGdt(cs.selector)? gdtr:ldtr;

    r = copy_from_gva(gcpu,
        (UINT64)(dtr->base + SelectorIdx(cs.selector)),
        sizeof(desc),
        (UINT64)(&desc)
        );

    if (r != 0)
    {
        gcpu_inject_ts(gcpu, cs.selector);
        return -1;
    }

    parse_desc(&desc, &cs);

    if (cs.ar.bits.p_bit != 1) // must be present
    {
        gcpu_inject_np(gcpu, cs.selector);
        return -1;
    }

    if ((cs.ar.bits.s_bit == 0) ||  // must be non-sys desc
        !IsCode(cs.ar.bits.type))   // must be code
    {
        gcpu_inject_ts(gcpu, cs.selector);
        return -1;
    }

    // Priv checks
    if (IsCodeConform(cs.ar.bits.type))
    {
        if (cs.ar.bits.dpl > cpl)
        {
            gcpu_inject_ts(gcpu, cs.selector);
            return -1;
        }
    }
    else
    {
        if (cs.ar.bits.dpl != cpl)
        {
            gcpu_inject_ts(gcpu, cs.selector);
            return -1;
        }
    }

    // If g_bit is set, the unit is 4 KB.
    if (cs.ar.bits.g_bit == 1)
        cs.limit = (cs.limit << 12) | 0xfff;

    if (!IsAssessed(cs.ar.bits.type))
    {
        SetAssessed(cs.ar.bits.type);
        SetAssessed(desc.bits.type);

        r = copy_to_gva(gcpu,
            (UINT64)(dtr->base + (cs.selector & 0xfff8)),
            sizeof(desc),
            (UINT64)(&desc)
            );

        if (r != 0)
        {
            gcpu_inject_ts(gcpu, cs.selector);
            return -1;
        }
    }

    cs.ar.bits.null_bit = 0;

    gcpu_set_segment_reg(
        gcpu,
        IA32_SEG_CS,
        cs.selector,
        cs.base,
        cs.limit,
        cs.ar.value
        );

    if (tss->eip > cs.limit)
    {
        gcpu_inject_ts(gcpu, cs.selector);
        return -1;
    }

    return 0;
}

/////////////////////////////////////////////////////////////////////////////
// Set guest ES, DS, FS, or GS, based on register name and new tss.

static int
set_guest_seg(
    GUEST_CPU_HANDLE gcpu, seg_reg_t *gdtr, seg_reg_t *ldtr, tss32_t *tss,
    VMM_IA32_SEGMENT_REGISTERS name)
{
    desc_t desc;
    seg_reg_t seg;
    seg_reg_t *dtr;
    UINT32 cpl;
    int r;

    vmm_memset(&seg, 0, sizeof(seg));

    if (name == IA32_SEG_ES)
        seg.selector = (UINT16)tss->es;
    else if (name == IA32_SEG_DS)
        seg.selector = (UINT16)tss->ds;
    else if (name == IA32_SEG_FS)
        seg.selector = (UINT16)tss->fs;
    else if (name == IA32_SEG_GS)
        seg.selector = (UINT16)tss->gs;
    else
        return -1;

    cpl = SelectorRpl(tss->cs);

    dtr = SelectorGdt(seg.selector)? gdtr:ldtr;

    if (SelectorIdx(seg.selector) == 0)
    {
        seg.selector = 0;
        seg.ar.bits.null_bit = 1;
        goto set_seg_reg;
    }

    r = copy_from_gva(gcpu,
        (UINT64)(dtr->base + SelectorIdx(seg.selector)),
        sizeof(desc),
        (UINT64)(&desc)
        );

    if (r != 0)
    {
        force_ring3_ss(gcpu);
        gcpu_inject_ts(gcpu, seg.selector);
        return -1;
    }

    parse_desc(&desc, &seg);

    if ((seg.ar.bits.s_bit == 0) || // must be non-sys desc
        (IsCode(seg.ar.bits.type) && !IsCodeR(seg.ar.bits.type)))
    {
        force_ring3_ss(gcpu);
        gcpu_inject_ts(gcpu, seg.selector);
        return -1;
    }

    // Must be present.
    if (seg.ar.bits.p_bit != 1)
    {
        force_ring3_ss(gcpu);
        gcpu_inject_np(gcpu, seg.selector);
        return -1;
    }

    // If g_bit is set, the unit is 4 KB.
    if (seg.ar.bits.g_bit == 1)
        seg.limit = (seg.limit << 12) | 0xfff;

    // Priv checks.
    if (IsCode(seg.ar.bits.type) && !IsCodeConform(seg.ar.bits.type))
    {
        UINT32 rpl = (UINT32)SelectorRpl(seg.selector);

        if ((seg.ar.bits.dpl < cpl) ||
            (seg.ar.bits.dpl < rpl))
        {
            force_ring3_ss(gcpu);
            gcpu_inject_ts(gcpu, seg.selector);
            return -1;
        }
    }

set_seg_reg:

    gcpu_set_segment_reg(
        gcpu,
        name,
        seg.selector,
        seg.base,
        seg.limit,
        seg.ar.value
        );

    return 0;
}

/////////////////////////////////////////////////////////////////////////////
// Copy guest status from VMCS to tss buffer.

static void copy_vmcs_to_tss32(GUEST_CPU_HANDLE gcpu, tss32_t *tss)
{
    VMCS_OBJECT *vmcs = gcpu_get_vmcs(gcpu);

    tss->eip    = (UINT32)gcpu_get_gp_reg(gcpu, IA32_REG_RIP);
    tss->eflags = (UINT32)gcpu_get_gp_reg(gcpu, IA32_REG_RFLAGS);
    tss->eax    = (UINT32)gcpu_get_gp_reg(gcpu, IA32_REG_RAX);
    tss->ecx    = (UINT32)gcpu_get_gp_reg(gcpu, IA32_REG_RCX);
    tss->edx    = (UINT32)gcpu_get_gp_reg(gcpu, IA32_REG_RDX);
    tss->ebx    = (UINT32)gcpu_get_gp_reg(gcpu, IA32_REG_RBX);
    tss->esp    = (UINT32)gcpu_get_gp_reg(gcpu, IA32_REG_RSP);
    tss->ebp    = (UINT32)gcpu_get_gp_reg(gcpu, IA32_REG_RBP);
    tss->esi    = (UINT32)gcpu_get_gp_reg(gcpu, IA32_REG_RSI);
    tss->edi    = (UINT32)gcpu_get_gp_reg(gcpu, IA32_REG_RDI);

    tss->es     = (UINT32)vmcs_read(vmcs, VMCS_GUEST_ES_SELECTOR);
    tss->cs     = (UINT32)vmcs_read(vmcs, VMCS_GUEST_CS_SELECTOR);
    tss->ss     = (UINT32)vmcs_read(vmcs, VMCS_GUEST_SS_SELECTOR);
    tss->ds     = (UINT32)vmcs_read(vmcs, VMCS_GUEST_DS_SELECTOR);
    tss->fs     = (UINT32)vmcs_read(vmcs, VMCS_GUEST_FS_SELECTOR);
    tss->gs     = (UINT32)vmcs_read(vmcs, VMCS_GUEST_GS_SELECTOR);
}

/////////////////////////////////////////////////////////////////////////////
// This function does task switch for 32-bit VMM guest.

int task_switch_for_guest(GUEST_CPU_HANDLE gcpu, IA32_VMX_VMCS_VM_EXIT_INFO_IDT_VECTORING vec_info)
{
    int ret;
    UINT32 inst_type;
    tss32_t tss;

    cr0_t cr0;
    dr7_t dr7;

    seg_reg_t gdtr;
    seg_reg_t old_ldtr;
    seg_reg_t new_ldtr;

    seg_reg_t new_tr;
    seg_reg_t old_tr;
    desc_t new_tss_desc;
    desc_t old_tss_desc;

    gcpu_get_gdt_reg(gcpu, (UINT64 *)&(gdtr.base), (UINT32 *)&(gdtr.limit));
    gdtr.ar.value = 0x000080;

    cr0.value =
        (UINT32) gcpu_get_guest_visible_control_reg(gcpu, IA32_CTRL_CR0);

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Find new tr & tss.

    get_task_info(gcpu, &inst_type, &(new_tr.selector), vec_info);

    ret = copy_from_gva(gcpu,
        (UINT64)(gdtr.base + SelectorIdx(new_tr.selector)),
        sizeof(new_tss_desc),
        (UINT64)(&new_tss_desc)
        );

    if (ret != 0)
    {
        gcpu_inject_ts(gcpu, new_tr.selector);
        return -1;
    }

    parse_desc(&new_tss_desc, &new_tr);

    if (!IsTss32(new_tr.ar.bits.type))
    {
        gcpu_inject_ts(gcpu, new_tr.selector);
        return -1;
    }

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Find old ldtr.

    gcpu_get_segment_reg(
        gcpu,
        IA32_SEG_LDTR,
        (UINT16 *)&(old_ldtr.selector),
        (UINT64 *)&(old_ldtr.base),
        (UINT32 *)&(old_ldtr.limit),
        (UINT32 *)&(old_ldtr.ar)
        );

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Find old tr.

    gcpu_get_segment_reg(
        gcpu,
        IA32_SEG_TR,
        (UINT16 *)&(old_tr.selector),
        (UINT64 *)&(old_tr.base),
        (UINT32 *)&(old_tr.limit),
        (UINT32 *)&(old_tr.ar)
        );

    if (!IsTss32Busy(old_tr.ar.bits.type))
    {
        gcpu_inject_ts(gcpu, old_tr.selector);
        return -1;
    }

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Save guest status to old tss.

    if (inst_type != TASK_SWITCH_TYPE_IDT) // call, jmp or iret
        gcpu_skip_guest_instruction(gcpu);

    vmm_memset(&tss, 0, sizeof(tss));
    copy_vmcs_to_tss32(gcpu, &tss);

    if (inst_type == TASK_SWITCH_TYPE_IRET)
    {
        ((eflags_t *)&(tss.eflags))->bits.nested_task = 0;
    }

    ret = copy_to_gva(gcpu,
        (UINT64)(old_tr.base + 32), // gva of old_tss.eip
        64,                         // from eip to gs: total 64 bytes
        (UINT64)&(tss.eip)          // hva of old_tss.eip
        );

    if (ret != 0)
    {
        gcpu_inject_ts(gcpu, old_tr.selector);
        return -1;
    }

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Read new tss from memory.

    vmm_memset(&tss, 0, sizeof(tss));

    ret = copy_from_gva(gcpu,
        (UINT64)(new_tr.base),
        sizeof(tss),
        (UINT64)&(tss)
        );

    if (ret != 0)
    {
        gcpu_inject_ts(gcpu, new_tr.selector);
        return -1;
    }

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Clear busy bit in old tss descriptor.

    if ((inst_type == TASK_SWITCH_TYPE_JMP) ||
        (inst_type == TASK_SWITCH_TYPE_IRET))
    {
        ret = copy_from_gva(gcpu,
            (UINT64)(gdtr.base + SelectorIdx(old_tr.selector)),
            sizeof(old_tss_desc),
            (UINT64)(&old_tss_desc)
            );

        if (ret != 0)
        {
            gcpu_inject_ts(gcpu, old_tr.selector);
            return -1;
        }

        // Clear the B bit, and write it back.
        old_tss_desc.bits.type = Tss32Aval;

        ret = copy_to_gva(gcpu,
            (UINT64)(gdtr.base + SelectorIdx(old_tr.selector)),
            sizeof(old_tss_desc),
            (UINT64)(&old_tss_desc)
            );

        if (ret != 0)
        {
            gcpu_inject_ts(gcpu, old_tr.selector);
            return -1;
        }
    }

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Set busy bit in new tss descriptor.

    if (inst_type != TASK_SWITCH_TYPE_IRET)
    {
        new_tss_desc.bits.type = Tss32Busy;
        new_tr.ar.bits.type = Tss32Busy;

        ret = copy_to_gva(gcpu,
            (UINT64)(gdtr.base + SelectorIdx(new_tr.selector)),
            sizeof(new_tss_desc),
            (UINT64)(&new_tss_desc)
            );

            if (ret != 0)
            {
                gcpu_inject_ts(gcpu, new_tr.selector);
                return -1;
            }
    }

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Save old tr in new tss.

    if ((inst_type == TASK_SWITCH_TYPE_CALL) ||
        (inst_type == TASK_SWITCH_TYPE_IDT))
    {
        ret = copy_to_gva(gcpu,
            (UINT64)(new_tr.base + 0),      // gva of new_tss.prev_tr
            sizeof(old_tr.selector),        // two bytes
            (UINT64)(&(old_tr.selector))    // hva
            );

        if (ret != 0)
        {
            new_tss_desc.bits.type = Tss32Aval;

            copy_to_gva(gcpu,
                (UINT64)(gdtr.base + SelectorIdx(new_tr.selector)),
                sizeof(new_tss_desc),
                (UINT64)(&new_tss_desc)
                );

            gcpu_inject_ts(gcpu, new_tr.selector);
            return -1;
        }
    }

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Load new tr.

    gcpu_set_segment_reg(
        gcpu,
        IA32_SEG_TR,
        new_tr.selector,
        new_tr.base,
        new_tr.limit,
        new_tr.ar.value
        );

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Load new cr3.

    if (cr0.bits.pg)
    {
        gcpu_set_guest_visible_control_reg(gcpu, IA32_CTRL_CR3, tss.cr3);
        gcpu_set_control_reg(gcpu, IA32_CTRL_CR3, tss.cr3);
    }

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Load new flags.

    if ((inst_type == TASK_SWITCH_TYPE_CALL) ||
        (inst_type == TASK_SWITCH_TYPE_IDT))
    {
        ((eflags_t *)&(tss.eflags))->bits.nested_task = 1;
    }

    ((eflags_t *)&(tss.eflags))->bits.rsvd_1 = 1;

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Load general regs.

    gcpu_set_gp_reg(gcpu, IA32_REG_RIP,     (UINT64)tss.eip);
    gcpu_set_gp_reg(gcpu, IA32_REG_RFLAGS,  (UINT64)tss.eflags);
    gcpu_set_gp_reg(gcpu, IA32_REG_RAX,     (UINT64)tss.eax);
    gcpu_set_gp_reg(gcpu, IA32_REG_RCX,     (UINT64)tss.ecx);
    gcpu_set_gp_reg(gcpu, IA32_REG_RDX,     (UINT64)tss.edx);
    gcpu_set_gp_reg(gcpu, IA32_REG_RBX,     (UINT64)tss.ebx);
    gcpu_set_gp_reg(gcpu, IA32_REG_RBP,     (UINT64)tss.ebp);
    gcpu_set_gp_reg(gcpu, IA32_REG_RSP,     (UINT64)tss.esp);
    gcpu_set_gp_reg(gcpu, IA32_REG_RSI,     (UINT64)tss.esi);
    gcpu_set_gp_reg(gcpu, IA32_REG_RDI,     (UINT64)tss.edi);

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Set the TS bit in CR0.

    cr0.bits.ts = 1;
    gcpu_set_guest_visible_control_reg(gcpu, IA32_CTRL_CR0, cr0.value);
    gcpu_set_control_reg(gcpu, IA32_CTRL_CR0, cr0.value);

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Load new ldtr.

    if (tss.ldtr != old_ldtr.selector)
    {
        if (set_guest_ldtr(gcpu, &gdtr, &new_ldtr, &tss) != 0)
            return -1;
    }

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Load new seg regs.

    if (((eflags_t *)&(tss.eflags))->bits.v86_mode == 1)
    {
        UINT16 es = (UINT16)tss.es;
        UINT16 cs = (UINT16)tss.cs;
        UINT16 ss = (UINT16)tss.ss;
        UINT16 ds = (UINT16)tss.ds;
        UINT16 fs = (UINT16)tss.fs;
        UINT16 gs = (UINT16)tss.gs;

        // Set v86 selector, base, limit, ar, in real-mode style.
        gcpu_set_segment_reg(gcpu, IA32_SEG_ES, es, es << 4, 0xffff, 0xf3);
        gcpu_set_segment_reg(gcpu, IA32_SEG_CS, cs, cs << 4, 0xffff, 0xf3);
        gcpu_set_segment_reg(gcpu, IA32_SEG_SS, ss, ss << 4, 0xffff, 0xf3);
        gcpu_set_segment_reg(gcpu, IA32_SEG_DS, ds, ds << 4, 0xffff, 0xf3);
        gcpu_set_segment_reg(gcpu, IA32_SEG_FS, fs, fs << 4, 0xffff, 0xf3);
        gcpu_set_segment_reg(gcpu, IA32_SEG_GS, gs, gs << 4, 0xffff, 0xf3);

        goto all_done;
    }

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Load new ss.

    if (set_guest_ss(gcpu, &gdtr, &new_ldtr, &tss) != 0)
        return -1;

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Load new es, ds, fs, gs.

    if ((set_guest_seg(gcpu, &gdtr, &new_ldtr, &tss, IA32_SEG_ES) != 0) ||
        (set_guest_seg(gcpu, &gdtr, &new_ldtr, &tss, IA32_SEG_DS) != 0) ||
        (set_guest_seg(gcpu, &gdtr, &new_ldtr, &tss, IA32_SEG_FS) != 0) ||
        (set_guest_seg(gcpu, &gdtr, &new_ldtr, &tss, IA32_SEG_GS) != 0))
    {
        return -1;
    }

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Load new cs.

    if (set_guest_cs(gcpu, &gdtr, &new_ldtr, &tss) != 0)
        return -1;

all_done:

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Clear the LE bits in DR7.

    dr7.value = (UINT32)gcpu_get_debug_reg(gcpu, IA32_REG_DR7);
    dr7.bits.l0 = 0;
    dr7.bits.l1 = 0;
    dr7.bits.l2 = 0;
    dr7.bits.l3 = 0;
    dr7.bits.le = 0;
    gcpu_set_debug_reg(gcpu, IA32_REG_DR7, (UINT64)dr7.value);

    //;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
    // Debug trap in new task?

    if ((tss.io_base_addr & 0x00000001) != 0)
    {
        gcpu_inject_db(gcpu);
        return -1;
    }

    return 0;
}

/////////////////////////////////////////////////////////////////////////////

VMEXIT_HANDLING_STATUS vmexit_task_switch(GUEST_CPU_HANDLE gcpu)
{    
    VMCS_OBJECT*                                vmcs = gcpu_get_vmcs(gcpu);
    IA32_VMX_VMCS_VM_EXIT_INFO_IDT_VECTORING    idt_vectoring_info;    
    IA32_VMX_EXIT_QUALIFICATION                 qualification;
    
    idt_vectoring_info.Uint32 = (UINT32) vmcs_read(vmcs, VMCS_EXIT_INFO_IDT_VECTORING);
    qualification.Uint64      =  vmcs_read(vmcs, VMCS_EXIT_INFO_QUALIFICATION);

#ifdef DEBUG
    {
        #define TS_NMI_VECOTR           0x02
        #define TS_DOUBLE_FAULT_VECTOR  0x08
        #define TS_MC_VECOR             0x12

        char *task_switch_name[]={"NMI", "Double Fault", "Machine Check", "Others"};
        char *task_switch_type[]={"Call", "IRET", "Jmp", "Task Gate"};

        UINT32 name_id = 3; // default Double fault
        UINT32 vector  = (UINT32)-1;
        

        
        if(idt_vectoring_info.Bits.Valid){
            vector = idt_vectoring_info.Bits.Vector;
        }

        if ( qualification.TaskSwitch.Source == TASK_SWITCH_TYPE_IDT) {
            if (qualification.TaskSwitch.TssSelector == 0x50)
                name_id = 1;
            else if (qualification.TaskSwitch.TssSelector == 0x58)
                name_id = 0;
            else if (qualification.TaskSwitch.TssSelector == 0xa0)
                name_id = 2;
            else
                name_id = 3;
        }

        VMM_LOG(mask_anonymous, level_trace,"Task Switch on CPU#%d src:%s type:%s tss:0x%x Qual:0x%x Vec:0x%x \n", 
            guest_vcpu(gcpu)->guest_cpu_id,
            task_switch_name[name_id],
            task_switch_type[qualification.TaskSwitch.Source],
            (qualification.Uint64 & 0xffff),
            qualification.Uint64,
            vector);

    }
#endif //DEBUG

    if(idt_vectoring_info.Bits.Valid && qualification.TaskSwitch.Source == TASK_SWITCH_TYPE_IDT){
        // clear IDT if valid, so that 
        // we can inject the event when needed (see event injections in task_switch_for_guest() below)
        // or 
        // avoid re-inject unwanted exception, e.g NMI.
        vmcs_write(vmcs, VMCS_EXIT_INFO_IDT_VECTORING, 0);
    }

    // pass idt_vectoring_info on to the following function calling since 
    // the value in VMCS_EXIT_INFO_IDT_VECTORING VMCS may be cleared above
    task_switch_for_guest(gcpu, idt_vectoring_info);
    return VMEXIT_HANDLED;
}

// End of file

