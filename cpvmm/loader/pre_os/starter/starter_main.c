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
* Copyright 2013 Intel Corporation All Rights Reserved.
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
#include "msr_defs.h"
#include "ia32_defs.h"
#include "vmm_arch_defs.h"
#include "vmm_startup.h"
#include "evmm_desc.h"

int run_evmmh(EVMM_DESC *td);

/////////////////////////////////////////////////////////////////////////////

UINT16 __readcs(VOID)
{
    __asm mov ax, cs;
}

UINT16 __readds(VOID)
{
    __asm mov ax, ds;
}

UINT16 __reades(VOID)
{
    __asm mov ax, es;
}

UINT16 __readfs(VOID)
{
    __asm mov ax, fs;
}

UINT16 __readgs(VOID)
{
    __asm mov ax, gs;
}

UINT16 __readss(VOID)
{
    __asm mov ax, ss;
}

UINT16 __readtr(VOID)
{
    __asm str ax;
}

VOID __readgdtr(IA32_GDTR *p)
{
    __asm
    {
        mov edx, p
        sgdt [edx]
    }
}

UINT16 __readldtr(VOID)
{
    __asm sldt ax;
}

/////////////////////////////////////////////////////////////////////////////

static int validate_descriptor(IA32_SEGMENT_DESCRIPTOR *d)
{
    if ((d->gen.hi.present == 0) ||
        (d->gen.hi.mbz_21 == 1))
        return -1;

    if (d->gen.hi.s == 0)
    {
        if ((d->tss.hi.mbo_8 == 0) ||
            (d->tss.hi.mbz_10 == 1) ||
            (d->tss.hi.mbo_11 == 0) ||
            (d->tss.hi.mbz_12 == 1) ||
            (d->tss.hi.mbz_21 == 1) ||
            (d->tss.hi.mbz_22 == 1))
            return -1;
    }
    else
    {
        if ((d->gen_attr.attributes & 0x0008) != 0)
        {
            if ((d->cs.hi.mbo_11 == 0) ||
                (d->cs.hi.mbo_12 == 0) ||
                (d->cs.hi.default_size == 0))
                return -1;
        }
        else
        {
            if ((d->ds.hi.mbz_11 == 1) ||
                (d->ds.hi.mbo_12 == 0) ||
                (d->ds.hi.big == 0))
                return -1;
        }
    }

    return 0;
}

/////////////////////////////////////////////////////////////////////////////

static void save_segment_data(UINT16 sel16, VMM_SEGMENT_STRUCT *ss)
{
    IA32_GDTR gdtr;
    IA32_SELECTOR sel;
    IA32_SEGMENT_DESCRIPTOR *desc;
    IA32_SEGMENT_DESCRIPTOR_ATTR attr;
    unsigned max;

    __readgdtr(&gdtr);
    max = gdtr.limit / sizeof(IA32_SEGMENT_DESCRIPTOR);

    sel.sel16 = sel16;

    if ((sel.bits.index == 0) || (sel.bits.index >= max) || (sel.bits.ti))
        return;

    desc = (IA32_SEGMENT_DESCRIPTOR *)
        (gdtr.base + sizeof(IA32_SEGMENT_DESCRIPTOR) * sel.bits.index);

    if (validate_descriptor(desc) != 0)
        return;

    ss->base = (UINT64)(
        (desc->gen.lo.base_address_15_00) |
        (desc->gen.hi.base_address_23_16 << 16) |
        (desc->gen.hi.base_address_31_24 << 24)
        );

    ss->limit = (UINT32)(
        (desc->gen.lo.limit_15_00) | 
        (desc->gen.hi.limit_19_16 << 16)
        );

    if (desc->gen.hi.granularity)
        ss->limit = (ss->limit << 12) | 0x00000fff;

    attr.attr16 = desc->gen_attr.attributes;
    attr.bits.limit_19_16 = 0;

    ss->attributes = (UINT32)attr.attr16;
    ss->selector = sel.sel16;
    return;
}

/////////////////////////////////////////////////////////////////////////////

void save_cpu_state(VMM_GUEST_CPU_STARTUP_STATE *s)
{
    IA32_GDTR gdtr;
    IA32_IDTR idtr;
    IA32_SELECTOR sel;
    IA32_SEGMENT_DESCRIPTOR *desc;

    s->size_of_this_struct = sizeof(VMM_GUEST_CPU_STARTUP_STATE);
    s->version_of_this_struct = VMM_GUEST_CPU_STARTUP_STATE_VERSION;

    __readgdtr(&gdtr);
    __sidt(&idtr);
    s->control.gdtr.base = (UINT64)gdtr.base;
    s->control.gdtr.limit = (UINT32)gdtr.limit;
    s->control.idtr.base = (UINT64)idtr.base;
    s->control.idtr.limit = (UINT32)idtr.limit;
    s->control.cr[IA32_CTRL_CR0] = __readcr0();
    s->control.cr[IA32_CTRL_CR2] = __readcr2();
    s->control.cr[IA32_CTRL_CR3] = __readcr3();
    s->control.cr[IA32_CTRL_CR4] = __readcr4();

    s->msr.msr_sysenter_cs = (UINT32)__readmsr(IA32_MSR_SYSENTER_CS);
    s->msr.msr_sysenter_eip = __readmsr(IA32_MSR_SYSENTER_EIP);
    s->msr.msr_sysenter_esp = __readmsr(IA32_MSR_SYSENTER_ESP);
    s->msr.msr_efer = __readmsr(IA32_MSR_EFER);
    s->msr.msr_pat = __readmsr(IA32_MSR_PAT);
    s->msr.msr_debugctl = __readmsr(IA32_MSR_DEBUGCTL);
    s->msr.pending_exceptions = 0;
    s->msr.interruptibility_state = 0;
    s->msr.activity_state = 0;
    s->msr.smbase = 0;

    sel.sel16 = __readldtr();

    if (sel.bits.index != 0)
        return;

    s->seg.segment[IA32_SEG_LDTR].attributes = 0x00010000;
    s->seg.segment[IA32_SEG_TR].attributes = 0x0000808b;
    s->seg.segment[IA32_SEG_TR].limit = 0xffffffff;
    save_segment_data(__readcs(), &s->seg.segment[IA32_SEG_CS]);
    save_segment_data(__readds(), &s->seg.segment[IA32_SEG_DS]);
    save_segment_data(__reades(), &s->seg.segment[IA32_SEG_ES]);
    save_segment_data(__readfs(), &s->seg.segment[IA32_SEG_FS]);
    save_segment_data(__readgs(), &s->seg.segment[IA32_SEG_GS]);
    save_segment_data(__readss(), &s->seg.segment[IA32_SEG_SS]);
    return;
}

/////////////////////////////////////////////////////////////////////////////

void setup_real_mode(VMM_GUEST_CPU_STARTUP_STATE *s)
{
    s->size_of_this_struct = sizeof(VMM_GUEST_CPU_STARTUP_STATE);
    s->version_of_this_struct = VMM_GUEST_CPU_STARTUP_STATE_VERSION;

    s->msr.msr_sysenter_cs = (UINT32)__readmsr(IA32_MSR_SYSENTER_CS);
    s->msr.msr_sysenter_eip = __readmsr(IA32_MSR_SYSENTER_EIP);
    s->msr.msr_sysenter_esp = __readmsr(IA32_MSR_SYSENTER_ESP);
    s->msr.msr_efer = __readmsr(IA32_MSR_EFER);
    s->msr.msr_pat = __readmsr(IA32_MSR_PAT);
    s->msr.msr_debugctl = __readmsr(IA32_MSR_DEBUGCTL);
    s->msr.pending_exceptions = 0;
    s->msr.interruptibility_state = 0;
    s->msr.activity_state = 0;
    s->msr.smbase = 0;

    s->control.gdtr.base = (UINT64)0;
    s->control.gdtr.limit = (UINT32)0xffff;
    s->control.idtr.base = 0x0;
    s->control.idtr.limit = 0xffff;
    s->control.cr[IA32_CTRL_CR0] = 0;
    s->control.cr[IA32_CTRL_CR2] = 0;
    s->control.cr[IA32_CTRL_CR3] = 0;
    s->control.cr[IA32_CTRL_CR4] = 0;

    s->seg.segment[IA32_SEG_LDTR].attributes = 0x00010000;

    s->seg.segment[IA32_SEG_CS].base = 0;
    s->seg.segment[IA32_SEG_CS].limit = 0xffff;
    s->seg.segment[IA32_SEG_CS].attributes = 0x93;
    s->seg.segment[IA32_SEG_DS].base = 0;
    s->seg.segment[IA32_SEG_DS].limit = 0xffff;
    s->seg.segment[IA32_SEG_DS].attributes = 0x93;
    s->seg.segment[IA32_SEG_ES].base = 0;
    s->seg.segment[IA32_SEG_ES].limit = 0xffff;
    s->seg.segment[IA32_SEG_ES].attributes = 0x93;
    s->seg.segment[IA32_SEG_FS].base = 0;
    s->seg.segment[IA32_SEG_FS].limit = 0xffff;
    s->seg.segment[IA32_SEG_FS].attributes = 0x93;
    s->seg.segment[IA32_SEG_GS].base = 0;
    s->seg.segment[IA32_SEG_GS].limit = 0xffff;
    s->seg.segment[IA32_SEG_GS].attributes = 0x93;
    s->seg.segment[IA32_SEG_SS].base = 0;
    s->seg.segment[IA32_SEG_SS].limit = 0xffff;
    s->seg.segment[IA32_SEG_SS].attributes = 0x93;

    s->gp.reg[IA32_REG_RDX] = 0x0080; // boot from hd0
    s->gp.reg[IA32_REG_RIP] = 0x2000; // grub stage 1.5 buffer
    s->gp.reg[IA32_REG_RSP] = 0x2000; // grub stage 1.5 buffer
    s->gp.reg[IA32_REG_RFLAGS] &= 0xfffffdff;
    return;
}

/////////////////////////////////////////////////////////////////////////////

int check_vmx_support(void)
{
    int info[4];
    UINT64 u;

    // CPUID: input in eax = 1.

    __cpuid(info, 1);

    // CPUID: output in ecx, VT available?

    if ((info[2] & 0x00000020) == 0)
        return -1;

    // Fail if feature is locked and vmx is off.

    u = __readmsr(IA32_MSR_FEATURE_CONTROL);

    if (((u & 0x01) != 0) && ((u & 0x04) == 0))
        return -1;

    return 0;
}

/////////////////////////////////////////////////////////////////////////////

void starter_main(
    UINT32 eflags,
    UINT32 edi, UINT32 esi, UINT32 ebp, UINT32 esp,
    UINT32 ebx, UINT32 edx, UINT32 ecx, UINT32 eax,
    UINT32 eip0
)
{
    UINT32 eip1;
    EVMM_DESC *td;
    VMM_GUEST_CPU_STARTUP_STATE *s;

    eip1 = (UINT32)_ReturnAddress();
    td = (EVMM_DESC *)((eip1 & 0xffffff00) - 0x400);

    vmm_memset(
        STATES0_BASE(td),
        0,
        THUNK_BASE(td) + THUNK_SIZE - STATES0_BASE(td)
        );

    s = (VMM_GUEST_CPU_STARTUP_STATE *)STATES0_BASE(td);
    s->gp.reg[IA32_REG_RIP] = eip0;
    s->gp.reg[IA32_REG_RFLAGS] = eflags;
    s->gp.reg[IA32_REG_RAX] = eax;
    s->gp.reg[IA32_REG_RCX] = ecx;
    s->gp.reg[IA32_REG_RDX] = edx;
    s->gp.reg[IA32_REG_RBX] = ebx;
    s->gp.reg[IA32_REG_RSP] = esp + 4;
    s->gp.reg[IA32_REG_RBP] = ebp;
    s->gp.reg[IA32_REG_RSI] = esi;
    s->gp.reg[IA32_REG_RDI] = edi;

    // move chain loader

    vmm_memcpy((void *)0x2000, (void *)((UINT32)td + 0x200), 512);
    setup_real_mode(s);
//    save_cpu_state(s);

    if (check_vmx_support() != 0)
        goto error;

    run_evmmh(td);

error:

    // clean memory

    vmm_memset(
        (void *)((UINT32)td + td->evmmh_start * 512),
        0,
        THUNK_BASE(td) + THUNK_SIZE - (td->evmmh_start) * 512
        );

    while (1)
        ;
}

// End of file
