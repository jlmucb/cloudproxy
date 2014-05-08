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
#define VMM_NATIVE_VMCALL_SIGNATURE 0x024694D40
#ifdef JLMDEBUG
#include "bootstrap_print.h"
#include "jlmdebug.h"

extern void** g_guest_regs_save_area;
UINT64   t_vmcs_save_area[512];  // never bigger than 4KB
extern void vmm_print_vmcs_region(UINT64* pu);
extern void vmm_vmcs_guest_state_read(UINT64* area);
#endif

extern void vmm_vmcs_guest_state_read(UINT64* area);
extern int vmx_vmread(UINT64 index, UINT64 *value);
extern int vmx_vmwrite(UINT64 index, UINT64 value);

extern UINT64 getphysical(UINT64 cr3, UINT64 virt);


#ifdef JLMDEBUG
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef long long unsigned uint64_t;

typedef int                 bool;
typedef unsigned char       u8;
typedef unsigned short      u16;
typedef unsigned int        u32;
typedef long long unsigned  u64;

#include "../../../bootstrap/linux_defns.h"

void check_boot_parameters()
{
    UINT64* regs = *g_guest_regs_save_area;
    UINT64 rdi_reg= regs[4];
    UINT64 rsi_reg= regs[5];
    UINT64  ept;
    UINT64  real;
    UINT64  virt;
    UINT64  value;

    bprint("rdi on entry: %p, rsi: %p\n", rdi_reg, rsi_reg);
    boot_params_t* boot_params= (boot_params_t*) rdi_reg;
    HexDump((UINT8*)rdi_reg, (UINT8*)rdi_reg+32);
    bprint("cmd line ptr: %p\n", boot_params->hdr.cmd_line_ptr);
    bprint("code32_start: %p\n", boot_params->hdr.code32_start);
    bprint("loadflags: %02x\n", boot_params->hdr.loadflags);

    vmx_vmread(0x201a, &ept);
    virt= rdi_reg;
    real= getphysical(ept, virt);
    bprint("virt: %016llx, real: %016llx\n", virt, real);
    virt= (UINT64) &(boot_params->hdr.loadflags);
    real= getphysical(ept, virt);
    bprint("virt: %016llx, real: %016llx\n", virt, real);

    vmx_vmread(0x681e, &value);  // guest_rip
    virt =value;
    real= getphysical(ept, virt);
    bprint("virt: %016llx, real: %016llx\n", virt, real);
    virt =value+10;
    real= getphysical(ept, virt);
    bprint("virt: %016llx, real: %016llx\n", virt, real);
}
#endif



// fixup control registers and make guest loop forever

asm(
".text\n"
".globl loop_forever\n"
".type loop_forever, @function\n"
"loop_forever:\n"
    "\tjmp   .\n"
    "\tret\n"
);


void fixupvmcs()
{
    UINT64  value;
    void loop_forever();
    UINT16* loop= (UINT16*)loop_forever;

    bprint("fixupvmcs %04x\n\n", *loop);
    vmx_vmread(0x681e, &value);  // guest_rip
    // bprint("Code at %p\n", value);
    // HexDump((UINT8*)value, (UINT8*)value+32);
    check_boot_parameters();
     *((UINT16*) value+0x8)= *loop;  // feeb

    // vmx_vmread(0x4000, &value);  // vmx_pin_controls
    // vmx_vmwrite(0x4000, value);  // vmx_pin_controls

    // vmx_vmread(0x4002, &value);  // vmx_cpu_controls
    // vmx_vmwrite(0x4002, value);  // vmx_cpu_controls

    // vmx_vmread(0x401e, &value);  // vmx_secondary_controls
    // vmx_vmwrite(0x401e, value);  // vmx_secondary_controls

    // vmx_vmread(0x4012, &value);  // vmx_entry_controls
    // vmx_vmwrite(0x4012, value);  // vmx_entry_controls

    // vmx_vmread(0x4002, &value);  // vmx_exit_controls
    // vmx_vmwrite(0x4002, value);  // vmx_exit_controls

    vmm_vmcs_guest_state_read((UINT64*) t_vmcs_save_area);
    vmm_print_vmcs_region((UINT64*) t_vmcs_save_area);
}


