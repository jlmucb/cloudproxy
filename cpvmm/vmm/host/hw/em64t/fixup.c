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

UINT64   t_vmcs_save_area[512];  // never bigger than 4KB
extern void vmm_print_vmcs_region(UINT64* pu);
extern void vmm_vmcs_guest_state_read(UINT64* area);
#endif

extern void vmm_vmcs_guest_state_read(UINT64* area);
extern int vmx_vmread(UINT64 index, UINT64 *value);
extern int vmx_vmwrite(UINT64 index, UINT64 value);


// fixup control registers and make guest loop forever

static int count= 0;

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

#ifdef JLMDEBUG
    bprint("fixupvmcs %04x\n", *loop);
#endif
    if(count++>0)
        LOOP_FOREVER
    vmx_vmread(0x681e, &value);  // guest_rip
    *((UINT16*) value)= *loop;    // feeb

    // was 3e, cruse has 16
    vmx_vmread(0x4000, &value);  // vmx_pin_controls
    // value= 0x16;
    // vmx_vmwrite(0x4000, value);  // vmx_pin_controls

    // was 96006172, cruse has 401e172
    vmx_vmread(0x4002, &value);  // vmx_cpu_controls
    //value= 0x80016172;         // can't figure out anything to change here
    //value= 0x96006172;         // can't figure out anything to change here
    //vmx_vmwrite(0x4002, value);  // vmx_cpu_controls

    vmx_vmread(0x401e, &value);  // vmx_secondary_controls
    value= 0x8a;                 // no vpid
    vmx_vmwrite(0x401e, value);  // vmx_secondary_controls

    // was d1ff, cruse has 11ff 
    vmx_vmread(0x4012, &value);  // vmx_entry_controls
    // vmx_vmwrite(0x4012, value);  // vmx_entry_controls

    // was 3f7fff, cruse has 36fff
    vmx_vmread(0x4002, &value);  // vmx_exit_controls
    // vmx_vmwrite(0x4002, value);  // vmx_exit_controls

    vmm_vmcs_guest_state_read((UINT64*) t_vmcs_save_area);
    vmm_print_vmcs_region((UINT64*) t_vmcs_save_area);
}


