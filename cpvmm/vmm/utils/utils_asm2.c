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
    __asm__ volatile(
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
    __asm__ volatile(
        "\tmovl  %[upper], %%ecx\n"
        "\trdtsc\n"
        "\tmovl    (%%ecx), %%edx\n"
        "\tmovl    %%edx,%[ret]\n"
    : [ret] "=m" (ret)
    : [upper] "m"(upper)
    :"%ecx", "%edx");
    return ret;
}


void vmm_write_xcr(UINT64 xcr, UINT64 high, UINT64 low)
{
#ifdef JLMDEBUG1
    bprint("vmm_write_xcr with value %llx\n", xcr);
    LOOP_FOREVER;
#endif

    __asm__ volatile(
        "\txsetbv\n"
    :: "d" (high), "a" (low), "c" (xcr)
    :);
}


void vmm_read_xcr(UINT32* low, UINT32* high, UINT32 xcr)
{
#ifdef JLMDEBUG1
    bprint("vmm_read_xcr\n");
    LOOP_FOREVER
#endif
    UINT32 highval, lowval;
    __asm__ volatile(
        "\txgetbv\n"
    : "=d" (highval), "=a" (lowval)
    : "c" (xcr) :);

    *high = highval;
    *low = lowval;
    return;
}


UINT64 gcpu_read_guestrip(void)
{
    UINT64  result;

#ifdef JLMDEBUG1
    bprint("vmm_read_guest_rip\n");
    LOOP_FOREVER
#endif
    __asm__ volatile(
        "\tmovq     $0x681e, %%rax\n"
        "\tvmread    %%rax,%%rax\n"
        "\tmovq     %%rax, %[result]\n"
    : [result]"=g"(result)
    : :"%rax");
    return result;
}


UINT64 vmexit_reason()
{
#ifdef JLMDEBUG1
    bprint("vmexit_reason\n");
#endif
    UINT64  result;
    __asm__ volatile(
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
    __asm__ volatile(
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
    UINT64  guest_rip;
    UINT64  guest_rsp;
    UINT64  guest_rflags;
    UINT64  vmexit_il;

    UINT64  guest_cr0;
    UINT64  guest_cr2;
    UINT64  guest_cr3;
    UINT64  guest_cr4;
    UINT64  guest_dr7;
    UINT64  guest_es;
    UINT64  guest_es_base;
    UINT64  guest_es_limit;
    UINT64  guest_es_access;
    UINT64  guest_cs;
    UINT64  guest_cs_base;
    UINT64  guest_cs_limit;
    UINT64  guest_cs_access;
    UINT64  guest_ss;
    UINT64  guest_ss_base;
    UINT64  guest_ss_limit;
    UINT64  guest_ss_access;
    UINT64  guest_ds;
    UINT64  guest_ds_base;
    UINT64  guest_ds_limit;
    UINT64  guest_ds_access;
    UINT64  guest_fs;
    UINT64  guest_fs_base;
    UINT64  guest_fs_limit;
    UINT64  guest_fs_access;
    UINT64  guest_gs;
    UINT64  guest_gs_base;
    UINT64  guest_gs_limit;
    UINT64  guest_gs_access;

    UINT64  guest_gdtr_base;
    UINT64  guest_gdtr_limit;
    UINT64  guest_idtr_base;
    UINT64  guest_idtr_limit;

    UINT64  guest_ldtr;
    UINT64  guest_ldtr_base;
    UINT64  guest_ldtr_limit;
    UINT64  guest_ldtr_access;
    UINT64  guest_tr;
    UINT64  guest_tr_base;
    UINT64  guest_tr_limit;
    UINT64  guest_tr_access;

    UINT64  guest_dbg_pend;
    UINT64  guest_link_full;
    UINT64  guest_link_high;

    UINT64  guest_IA32_debug_full;
    UINT64  guest_IA32_debug_high;

    UINT64  guest_interruptability;
    UINT64  guest_activity;
    UINT64  guest_smbase;
    UINT64  guest_sysenter;
    UINT64  guest_sysenter_esp;
    UINT64  guest_sysenter_eip;
    UINT64  guest_pat;
    UINT64  guest_efer;
    UINT64  guest_pdpte0;
    UINT64  guest_pdpte1;
    UINT64  guest_pdpte2;
    UINT64  guest_pdpte3;
    UINT64  guest_preempt;
    UINT64  guest_etpt;

    UINT64  vmx_pin_controls;
    UINT64  vmx_cpu_controls;
    UINT64  vmx_secondary_controls;
    UINT64  vmx_exception_bitmap;

    UINT64  vmx_exit_controls;
    UINT64  vmx_exit_msr_store_count;
    UINT64  vmx_exit_msr_load_count;

    UINT64  vmx_entry_controls;
    UINT64  vmx_entry_msr_load_count;
    UINT64  vmx_entry_interrupt_info;
    UINT64  vmx_entry_exception_code;
    UINT64  vmx_entry_instruction_length;
    UINT64  vmx_entry_task_priv_thresh;

    UINT64  vmx_control_cr0_mask;
    UINT64  vmx_control_cr4_mask;
    UINT64  vmx_control_cr0_shadow;
    UINT64  vmx_control_cr4_shadow;
    UINT64  vmx_control_cr3_target0;
    UINT64  vmx_control_cr3_target1;
    UINT64  vmx_control_cr3_target2;
    UINT64  vmx_control_cr3_target3;

    UINT64  vmx_control_io_bitmapa_full;
    UINT64  vmx_control_io_bitmapa_high;
    UINT64  vmx_control_io_bitmapb_full;
    UINT64  vmx_control_io_bitmapb_high;

    UINT64  vmexit_msr_store_address_full;
    UINT64  vmexit_msr_store_address_high;
    UINT64  vmexit_msr_load_address_full;
    UINT64  vmexit_msr_load_address_high;
    UINT64  vmentry_msr_load_address_full;
    UINT64  vmentry_msr_load_address_high;
    
    UINT64  vmx_instruction_error;
    UINT64  vmexit_reason;
    UINT64  vmexit_interrupt_info;
    UINT64  vmexit_interrupt_error;
    UINT64  idt_vectoring_info;
    UINT64  idt_vectoring_error_code;
    UINT64  vmexit_instruction_length;
    UINT64  vmexit_instruction_info;

    UINT64  host_sysenter_cs;
    UINT64  host_sysenter_eip;
    UINT64  host_sysenter_esp;
    UINT64  host_rip;
    UINT64  host_rsp;

    UINT64  host_cr0;
    UINT64  host_cr3;
    UINT64  host_cr4;
    UINT64  host_es;
    UINT64  host_cs;
    UINT64  host_ss;
    UINT64  host_ds;
    UINT64  host_fs;
    UINT64  host_gs;
    UINT64  host_tr;
    UINT64  host_fs_base;
    UINT64  host_gs_base;
    UINT64  host_tr_base;
    UINT64  host_gdtr_base;
    UINT64  host_idtr_base;

    // msr index is 0x38d(?)
    UINT64  guest_perf_ctrl;    // 0x2808
    UINT64  guest_perf_high;    // 0x2809
    UINT64  host_perf_ctrl;	// 0x2c04
    UINT64  host_perf_high;	// 0x2c06

} PACKED VMCS_SAVED_REGION;


#ifdef JLMDEBUG
void vmm_print_vmcs_region(UINT64* pu)
{
    VMCS_SAVED_REGION* p= (VMCS_SAVED_REGION*) pu;
    bprint("Guest values:\n");
    bprint("rip: %016llx, rflags: %016llx, rsp: %016llx\n",
        p->guest_rip, p->guest_rflags, p->guest_rsp);
    bprint("cr0: %08llx, cr2: %08llx, cr3: %08llx, cr4: %08llx\n",
        p->guest_cr0, p->guest_cr2, p->guest_cr3, p->guest_cr4);
    bprint("dr7: %08llx\n", p->guest_dr7);
    bprint("cs: %08llx, base: %08llx, limit: %08llx, access: %04llx\n",
        p->guest_cs, p->guest_cs_base, p->guest_cs_limit, p->guest_cs_access);
    bprint("ss: %08llx, base: %08llx, limit: %08llx, access: %04llx\n",
        p->guest_ss, p->guest_ss_base, p->guest_ss_limit, p->guest_ss_access);
    bprint("ds: %08llx, base: %08llx, limit: %08llx, access: %04llx\n",
        p->guest_ds, p->guest_ds_base, p->guest_ds_limit, p->guest_ds_access);
#if 0  // unused prints
    bprint("fs: %08llx, base: %08llx, limit: %08llx, access: %04llx\n",
        p->guest_fs, p->guest_fs_base, p->guest_fs_limit, p->guest_fs_access);
    bprint("gs: %08llx, base: %08llx, limit: %08llx, access: %04llx\n",
        p->guest_gs, p->guest_gs_base, p->guest_gs_limit, p->guest_gs_access);
    bprint("ldtr: %08llx, base: %08llx, limit: %08llx, access: %04llx\n",
       p->guest_ldtr, p->guest_ldtr_base, p->guest_ldtr_limit, p->guest_ldtr_access);
#endif
    bprint("gdtr base: %08llx, limit: %08llx\n", p->guest_gdtr_base, 
           p->guest_gdtr_limit);
    bprint("idtr base: %08llx, limit: %08llx\n", p->guest_idtr_base, 
           p->guest_idtr_limit);
    bprint("tr: %08llx, base: %08llx, limit: %08llx, access: %04llx\n",
        p->guest_tr, p->guest_tr_base, p->guest_tr_limit, p->guest_tr_access);
    bprint("secondary controls: %08llx, etpt: %08llx\n", 
           p->vmx_secondary_controls, p->guest_etpt);
    bprint("pin controls: %08llx, cpu controls: %08llx\n", p->vmx_pin_controls,
           p->vmx_cpu_controls);
    bprint("entry controls: %08llx, exit controls: %08llx\n", 
           p->vmx_entry_controls, p->vmx_exit_controls);
    bprint("pdpte0: %llx, pdpte1: %llx, pdpte2: %llx, pdpte3: %llx\n",
        p->guest_pdpte0, p->guest_pdpte1, p->guest_pdpte2, p->guest_pdpte3);
}
#endif


void vmm_vmcs_guest_state_read(UINT64* area)
{
    VMCS_SAVED_REGION* p= (VMCS_SAVED_REGION*) area;
    extern int vmx_vmread(UINT64, UINT64*);

    vmx_vmread(0x681e, &p->guest_rip);
    vmx_vmread(0x681c, &p->guest_rsp);
    vmx_vmread(0x6820, &p->guest_rflags);
    vmx_vmread(0x440c, &p->vmexit_il);

    vmx_vmread(0x6800, &p->guest_cr0);
    vmx_vmread(0x6802, &p->guest_cr3);
    vmx_vmread(0x6804, &p->guest_cr4);
    vmx_vmread(0x681a, &p->guest_dr7);
    vmx_vmread(0x0800, &p->guest_es);
    vmx_vmread(0x6806, &p->guest_es_base);
    vmx_vmread(0x4800, &p->guest_es_limit);
    vmx_vmread(0x4814, &p->guest_es_access);
    vmx_vmread(0x0802, &p->guest_cs);
    vmx_vmread(0x6808, &p->guest_cs_base);
    vmx_vmread(0x4802, &p->guest_cs_limit);
    vmx_vmread(0x4816, &p->guest_cs_access);
    vmx_vmread(0x0804, &p->guest_ss);
    vmx_vmread(0x680a, &p->guest_ss_base);

    vmx_vmread(0x4804, &p->guest_ss_limit);
    vmx_vmread(0x4818, &p->guest_ss_access);
    vmx_vmread(0x0806, &p->guest_ds);
    vmx_vmread(0x680c, &p->guest_ds_base);
    vmx_vmread(0x4806, &p->guest_ds_limit);
    vmx_vmread(0x481a, &p->guest_ds_access);
    vmx_vmread(0x0808, &p->guest_fs);
    vmx_vmread(0x680e, &p->guest_fs_base);

    vmx_vmread(0x4808, &p->guest_fs_limit);
    vmx_vmread(0x481c, &p->guest_fs_access);
    vmx_vmread(0x080a, &p->guest_gs);
    vmx_vmread(0x6810, &p->guest_gs_base);
    vmx_vmread(0x480a, &p->guest_gs_limit);
    vmx_vmread(0x481e, &p->guest_gs_access);

    vmx_vmread(0x6816, &p->guest_gdtr_base);
    vmx_vmread(0x4810, &p->guest_gdtr_limit);
    vmx_vmread(0x6818, &p->guest_idtr_base);
    vmx_vmread(0x4812, &p->guest_idtr_limit);

    vmx_vmread(0x080e, &p->guest_tr);
    vmx_vmread(0x6814, &p->guest_tr_base);
    vmx_vmread(0x480e, &p->guest_tr_limit);
    vmx_vmread(0x4822, &p->guest_tr_access);
    vmx_vmread(0x080c, &p->guest_ldtr);
    vmx_vmread(0x6812, &p->guest_ldtr_base);
    vmx_vmread(0x480c, &p->guest_ldtr_limit);
    vmx_vmread(0x4820, &p->guest_ldtr_access);

    vmx_vmread(0x6822, &p->guest_dbg_pend);
    vmx_vmread(0x2800, &p->guest_link_full);
    vmx_vmread(0x2801, &p->guest_link_high);
    vmx_vmread(0x2802, &p->guest_IA32_debug_full);
    vmx_vmread(0x2803, &p->guest_IA32_debug_high);
    vmx_vmread(0x4824, &p->guest_interruptability);
    vmx_vmread(0x4826, &p->guest_activity);
    vmx_vmread(0x4828, &p->guest_smbase);
    vmx_vmread(0x482a, &p->guest_sysenter);
    vmx_vmread(0x6824, &p->guest_sysenter_esp);
    vmx_vmread(0x6826, &p->guest_sysenter_eip);
    vmx_vmread(0x2804, &p->guest_pat);
    vmx_vmread(0x2806, &p->guest_efer);
    vmx_vmread(0x280a, &p->guest_pdpte0);
    vmx_vmread(0x280c, &p->guest_pdpte1);
    vmx_vmread(0x280e, &p->guest_pdpte2);
    vmx_vmread(0x2810, &p->guest_pdpte3);
    vmx_vmread(0x482e, &p->guest_preempt);
    vmx_vmread(0x201a, &p->guest_etpt);

    vmx_vmread(0x4000, &p->vmx_pin_controls);
    vmx_vmread(0x4002, &p->vmx_cpu_controls);
    vmx_vmread(0x401e, &p->vmx_secondary_controls);
    vmx_vmread(0x4004, &p->vmx_exception_bitmap);
    vmx_vmread(0x400C, &p->vmx_exit_controls);
    vmx_vmread(0x400E, &p->vmx_exit_msr_store_count);
    vmx_vmread(0x4010, &p->vmx_exit_msr_load_count);

    vmx_vmread(0x4012, &p->vmx_entry_controls);
    vmx_vmread(0x4014, &p->vmx_entry_msr_load_count);
    vmx_vmread(0x4016, &p->vmx_entry_interrupt_info);
    vmx_vmread(0x4018, &p->vmx_entry_exception_code);
    vmx_vmread(0x401a, &p->vmx_entry_instruction_length);
    vmx_vmread(0x401c, &p->vmx_entry_task_priv_thresh);

    vmx_vmread(0x6000, &p->vmx_control_cr0_mask);
    vmx_vmread(0x6002, &p->vmx_control_cr4_mask);
    vmx_vmread(0x6004, &p->vmx_control_cr0_shadow);
    vmx_vmread(0x6006, &p->vmx_control_cr4_shadow);
    vmx_vmread(0x6008, &p->vmx_control_cr3_target0);
    vmx_vmread(0x600a, &p->vmx_control_cr3_target1);
    vmx_vmread(0x600c, &p->vmx_control_cr3_target2);
    vmx_vmread(0x600e, &p->vmx_control_cr3_target3);

    vmx_vmread(0x2000, &p->vmx_control_io_bitmapa_full);
    vmx_vmread(0x2001, &p->vmx_control_io_bitmapa_high);
    vmx_vmread(0x2002, &p->vmx_control_io_bitmapb_full);
    vmx_vmread(0x2003, &p->vmx_control_io_bitmapb_high);

    vmx_vmread(0x2006, &p->vmexit_msr_store_address_full);
    vmx_vmread(0x2007, &p->vmexit_msr_store_address_high);
    vmx_vmread(0x2008, &p->vmexit_msr_load_address_full);
    vmx_vmread(0x2009, &p->vmexit_msr_load_address_high);
    vmx_vmread(0x200a, &p->vmentry_msr_load_address_full);
    vmx_vmread(0x200c, &p->vmentry_msr_load_address_high);
    
    vmx_vmread(0x4400, &p->vmx_instruction_error);
    vmx_vmread(0x4402, &p->vmexit_reason);
    vmx_vmread(0x4404, &p->vmexit_interrupt_info);
    vmx_vmread(0x4406, &p->vmexit_interrupt_error);
    vmx_vmread(0x4408, &p->idt_vectoring_info);
    vmx_vmread(0x440a, &p->idt_vectoring_error_code);
    vmx_vmread(0x440c, &p->vmexit_instruction_length);
    vmx_vmread(0x440e, &p->vmexit_instruction_info);

    vmx_vmread(0x4c00, &p->host_sysenter_cs);
    vmx_vmread(0x6c14, &p->host_sysenter_eip);
    vmx_vmread(0x6c12, &p->host_sysenter_esp);
    vmx_vmread(0x6c16, &p->host_rip);
    vmx_vmread(0x6c14, &p->host_rsp);

    vmx_vmread(0x6c00, &p->host_cr0);
    vmx_vmread(0x6c02, &p->host_cr3);
    vmx_vmread(0x6c04, &p->host_cr4);
    vmx_vmread(0x0c00, &p->host_es);
    vmx_vmread(0x0c02, &p->host_cs);
    vmx_vmread(0x0c04, &p->host_ss);
    vmx_vmread(0x0c06, &p->host_ds);
    vmx_vmread(0x0c08, &p->host_fs);
    vmx_vmread(0x0c08, &p->host_gs);
    vmx_vmread(0x0c0a, &p->host_tr);
    vmx_vmread(0x6c06, &p->host_fs_base);
    vmx_vmread(0x6c08, &p->host_gs_base);
    vmx_vmread(0x680a, &p->host_tr_base);
    vmx_vmread(0x6c0c, &p->host_gdtr_base);
    vmx_vmread(0x6c0e, &p->host_idtr_base);
}




