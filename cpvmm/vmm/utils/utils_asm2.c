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
#include "vmm_defs.h"
#ifdef JLMDEBUG
#include "jlmdebug.h"
#endif


void vmm_lock_write (UINT64 *mem_loc, UINT64 new_data)
{
#ifdef JLMDEBUG1
    bprint("vmm_lock_write\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tmovq       %[mem_loc], %%rcx\n"
        "\tmovq       %[new_data], %%rdx\n"
        "\tlock; xchgq (%%rcx),%%rdx\n"
    :
    : [mem_loc] "m"(mem_loc), [new_data] "m"(new_data)
    :"%rcx", "%rdx");
}


UINT32 vmm_rdtsc (UINT32 *upper)
{
    UINT32 ret;

#ifdef JLMDEBUG1
    bprint("vmm_rdtsc\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tmovl  %[upper], %%ecx\n"
        "\trdtsc\n"
        "\tmovl    (%%ecx), %%edx\n"
        "\tmovl    %%edx,%[ret]\n"
    : [ret] "=m" (ret)
    : [upper] "m"(upper)
    :"%ecx", "%edx");
    return ret;
}


void vmm_write_xcr(UINT64 xcr)
{
#ifdef JLMDEBUG1
    bprint("vmm_write_xcr\n");
    LOOP_FOREVER
#endif
    asm volatile(
        "\tmovq       %[xcr], %%rax\n"
        "\txsetbv\n"
    : : [xcr] "g"(xcr)
    :"%rax");
}


UINT64 vmm_read_xcr()
{
#ifdef JLMDEBUG1
    bprint("vmm_read_xcr\n");
    LOOP_FOREVER
#endif
    UINT64  result;

    asm volatile(
        "\txgetbv\n"
        "movq   %%rcx, %[result]\n"
    : [result]"=g"(result)
    : :"%rcx", "%rdx");
    return result;
}


//CHECK(JLM)
UINT64 gcpu_read_guestrip(void)
{
    UINT64  result;

#ifdef JLMDEBUG1
    bprint("vmm_read_guest_rip\n");
    LOOP_FOREVER
#endif
    // JLM(FIX): is this right?
    asm volatile(
        "\tvmread    %%rax,%%rax\n"
        "\tmovq     %%rax, %[result]\n"
    : [result]"=g"(result)
    : :"%rax");
    return result;
}


//CHECK(JLM)
UINT64 vmexit_reason()
{
#ifdef JLMDEBUG1
    bprint("vmexit_reason\n");
    LOOP_FOREVER
#endif
    UINT64  result;
    asm volatile(
        "\tmovq   $0x4402, %%rax\n"
        "\tvmread %%rax, %%rax\n"
        "\tmovq   %%rax, %[result]\n"
    : [result]"=g"(result)
    : :"%rax");
    return result;
}


UINT32 vmexit_check_ept_violation(void)
//if it is ept_violation_vmexit, return exit qualification
//  in EAX, otherwise, return 0 in EAX
{
#ifdef JLMDEBUG1
    bprint("vmm_check_ept_violation\n");
    LOOP_FOREVER
#endif
    UINT32  result;
    asm volatile(
        "\tmovq   $0x4402, %%rax\n"
        "\tvmread %%rax, %%rax\n" 
        "\tcmp     $48,%%ax\n" 
        "\tjnz    1f\n" 
        "\tmovq   $0x6400, %%rax\n" 
        "\tvmread %%rax, %%rax\n" 
        "\tmovl   %%eax, %[result]\n"
        "\tjmp    2f\n" 
        "1:\n" 
        "\tmovq   $0x00, %%rax\n" 
        "\tmovl   %%eax, %[result]\n"
        "2:\n" 
    : [result]"=m"(result)
    : :"%rax", "%al");
    return result;
}


typedef struct VMCS_SAVED_REGION {
    UINT64  g_rip;
    UINT64  g_rflags;
    UINT64  g_il;
    UINT64  g_cr0;
    UINT64  g_cr3;
    UINT64  g_cr4;
    UINT64  g_dr7;
    UINT64  g_es;
    UINT64  g_es_base;
    UINT64  g_es_limit;
    UINT64  g_es_access;
    UINT64  g_cs;
    UINT64  g_cs_base;
    UINT64  g_cs_limit;
    UINT64  g_cs_access;
    UINT64  g_ss;
    UINT64  g_ss_base;
    UINT64  g_ss_limit;
    UINT64  g_ss_access;
    UINT64  g_ds;
    UINT64  g_ds_base;
    UINT64  g_ds_limit;
    UINT64  g_ds_access;
    UINT64  g_fs;
    UINT64  g_fs_base;
    UINT64  g_fs_limit;
    UINT64  g_fs_access;
    UINT64  g_gs;
    UINT64  g_gs_base;
    UINT64  g_gs_limit;
    UINT64  g_gs_access;
    UINT64  g_ldtr;
    UINT64  g_ldtr_base;
    UINT64  g_ldtr_limit;
    UINT64  g_ldtr_access;
    UINT64  g_tr;
    UINT64  g_tr_base;
    UINT64  g_tr_limit;
    UINT64  g_tr_access;
    UINT64  g_gdtr1;
    UINT64  g_gdtr2;
    UINT64  g_idtr1;
    UINT64  g_idtr2;
    UINT64  g_rsp;
    UINT64  g_rflg2;
    UINT64  g_dbg_pend;
    UINT64  g_link;
    UINT64  g_IA32_debug;
    UINT64  g_interruptability;
    UINT64  g_activity;
    UINT64  g_smbase;
    UINT64  g_sysenter;
    UINT64  g_sysenter_esp;
    UINT64  g_sysenter_eip;
    UINT64  g_pat;
    UINT64  g_efer;
    UINT64  g_pdpte0;
    UINT64  g_pdpte1;
    UINT64  g_pdpte2;
    UINT64  g_pdpte3;
    UINT64  g_preempt;
    UINT64  g_etpt;
    UINT64  empty[3];
} PACKED VMCS_SAVED_REGION;


void vmm_print_vmcs_region(UINT64* pu)
{
    VMCS_SAVED_REGION* p= (VMCS_SAVED_REGION*) pu;
#ifdef JLMDEBUG
    bprint("Guest values:\n");
    bprint("rip: 0x%016llx, rflags: 0x%016llx g_il: 0xllx \n",
        p->g_rip, p->g_rflags, p->g_il );
    bprint("cr0: 0x%016llx, cr3: 0x%016llx, g_cr4: 0x%016llx\n",
        p->g_cr0, p->g_cr3, p->g_cr4);
    bprint("g_dr7: 0x%016llx\n", p->g_dr7);
    bprint("g_cs: 0x%016llx, g_cs_base: 0x%016llx, g_cs_limit: 0x%llx g_cs_access: 0x%llx\n",
        p->g_cs, p->g_cs_base, p->g_cs_limit, p->g_cs_access);
    bprint("g_ss: 0x%016llx, g_ss_base: 0x%016llx g_ss_limit: 0x%016llx, g_ss_access: 0x%016llx\n",
        p->g_ss, p->g_ss_base, p->g_ss_limit, p->g_ss_access);
    bprint("g_ds: 0x%016llx g_ds_base: 0x%016llx, g_ds_limit: 0x%016llx g_ds_access: 0x%016llx\n",
        p->g_ds, p->g_ds_base, p->g_ds_limit, p->g_ds_access);
#if 0
    bprint("g_fs: 0x%016llx g_fs_base: 0x%016llx g_fs_limit: 0x%016llx g_fs_access: 0x%016llx\n",
        p->g_fs, p->g_fs_base, p->g_fs_limit, p->g_fs_access);
    bprint("g_gs: 0x%016llx g_gs_base: 0x%016llx g_gs_limit: 0x%016llx g_gs_access: 0x%016llx\n",
        p->g_gs, p->g_gs_base, p->g_gs_limit, p->g_gs_access);
#endif
    bprint("g_ldtr: 0x%016llx g_ldtr_base: 0x%016llx g_ldtr_limit: 0x%016llx g_ldtr_access: 0x%016llx\n",
        p->g_ldtr, p->g_ldtr_base, p->g_ldtr_limit, p->g_ldtr_access);
    bprint("g_tr: 0x%016llx g_tr_base: 0x%016llx g_tr_limit: 0x%016llx g_tr_access: 0x%016llx\n",
        p->g_tr, p->g_tr_base, p->g_tr_limit, p->g_tr_access);
    bprint("g_gdtr1: 0x%016llx g_gdtr2: 0x%016llx g_idtr1: 0x%016llx g_idtr2: 0x%016llx\n",
        p->g_gdtr1, p->g_gdtr2, p->g_idtr1, p->g_idtr2);
    bprint("g_etpt: 0x%016llx\n", p->g_etpt);
#if 0
    bprint("g_rsp: 0x%016llx g_rflg2: 0x%016llx\n",
        p->g_rsp, p->g_rflg2);
    bprint("g_dbg_pend: 0x%016llx g_link: 0x%016llx g_IA32_debug: 0x%016llx\n",
        p->g_dbg_pend, p->g_link, p->g_IA32_debug);
    bprint("interrupt: 0x%llx activity: 0x%llx g_smbase: 0x%llx\n",
        p->g_interruptability, p->g_activity, p->g_smbase);
    bprint("sysenter: 0x%016llx esp: 0x%llx eip: 0x%llx\n",
        p->g_sysenter, p->g_sysenter_esp, p->g_sysenter_eip);
    bprint("g_pat: 0x%llx g_efer: 0x%llx\n",
        p->g_pat, p->g_efer);
    bprint("g_pdpte0: 0x%llx g_pdpte1: 0x%llx g_pdpte2: 0x%llx g_pdpte3: 0x%llx\n",
        p->g_pdpte0, p->g_pdpte1, p->g_pdpte2, p->g_pdpte3);
    bprint("g_preempt: 0x%llx\n", p->g_preempt);
#endif
#endif
}



void vmm_vmcs_guest_state_read(UINT64* area)
{
#ifdef JLMDEBUG
    bprint("vmm_vmcs_guest_state_read\n");
#endif
    asm volatile(
        "\tmovq     %[area], %%rcx\n"
        "\tmovq     $0x681e, %%rax\n" // guest rip
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"
        "\tmovq     $0x6820, %%rax\n" // guest rflags
        "\tvmread   %%rax, %%rax\n"
        "\taddq     $8, %%rcx\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x440c, %%rax\n" // instruction length
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6800, %%rax\n"// guest cr0
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6802, %%rax\n" // guest cr3
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6804, %%rax\n" // guest cr4
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x681a, %%rax\n" // guest dr7
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x0800, %%rax\n" // guest es
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6806, %%rax\n" // guest_es_base
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4800, %%rax\n" // guest es limit
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4814, %%rax\n" // guest access rights
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x0802, %%rax\n" // guest cs selector
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6808, %%rax\n" // guest cs base
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4802, %%rax\n" // guest cs limit
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4816, %%rax\n" // guest cs access rights
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x0804, %%rax\n"  // guest ss selector
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x680a, %%rax\n"  // guest ss base
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4804, %%rax\n"  // guest ss limit
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4818, %%rax\n"  // guest ss access rights
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x0806, %%rax\n"  // guest ds
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x680c, %%rax\n"  // guest ds
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4806, %%rax\n"  // guest ds
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x481a, %%rax\n"  // guest ds
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x0808, %%rax\n"  // guest fs
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x680e, %%rax\n"  // guest fs
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4808, %%rax\n"  // guest fs
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x481c, %%rax\n"  // guest fs
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x080a, %%rax\n"  // guest gs
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6810, %%rax\n"  // guest gs
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x480a, %%rax\n"  // guest gs
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x481e, %%rax\n"  // guest gs
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x080c, %%rax\n"   // guest ldtr
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6812, %%rax\n"   // guest ldtr
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x480c, %%rax\n"   // guest ldtr
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4820, %%rax\n"   // guest ldtr
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x080e, %%rax\n"   // guest tr
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6814, %%rax\n"   // guest tr
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x480e, %%rax\n"   // guest tr
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4822, %%rax\n"   // guest tr
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6816, %%rax\n"   // guest gdtr
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4810, %%rax\n"   // guest gdtr
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6818, %%rax\n"  // idtr
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4812, %%rax\n"  // idtr
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x681c, %%rax\n"  // rsp
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x681e, %%rax\n"  // guest rip
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6820, %%rax\n"  // rflags
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6822, %%rax\n" // pending dbg
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x2800, %%rax\n" // link pointer
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x2802, %%rax\n" // IA32 debuf
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4824, %%rax\n"  // guest interruptability
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4826, %%rax\n"  // guest activity
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x4828, %%rax\n"   // smbase
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x482a, %%rax\n"   // sysenter
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6824, %%rax\n"   // sysenter esp
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x6826, %%rax\n"   // sysenter eip
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\tmovl     %%edx, %%eax\n"
        "\tcmp      $0, %%eax\n"
        "jnz        1f\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x2804, %%rax\n"   // pat
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x2806, %%rax\n"   // efer
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x280a, %%rax\n"   // pdpte0
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x280c, %%rax\n"   // pdpte1
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x280e, %%rax\n"   // pdpte2
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x2810, %%rax\n"   // pdpte3
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x482e, %%rax\n"   // preempt timer
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "\taddq     $8, %%rcx\n"
        "\tmovq     $0x201a, %%rax\n"   // etpt
        "\tvmread   %%rax, %%rax\n"
        "\tmovq     %%rax, (%%rcx)\n"
        "\tjmp      2f\n"
        
        "1:\n"
        "\tmovq     $0x00, %%rax\n"
        "\taddq     $8, %%rcx\n"
        "\tmovq     %%rax, (%%rcx)\n"
        "\taddq     $8, %%rcx\n"
        "\tmovq     %%rax, (%%rcx)\n"
        "\taddq     $8, %%rcx\n"
        "\tmovq     %%rax, (%%rcx)\n"
        "\taddq     $8, %%rcx\n"
        "\tmovq     %%rax, (%%rcx)\n"
        "\taddq     $8, %%rcx\n"
        "\tmovq     %%rax, (%%rcx)\n"
        "\taddq     $8, %%rcx\n"
        "\tmovq     %%rax, (%%rcx)\n"
        "\taddq     $8, %%rcx\n"
        "\tmovq     %%rax, (%%rcx)\n"

        "2:\n"
    : : [area] "m" (area)
    :"%rax", "%rcx");
}


