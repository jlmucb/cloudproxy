/*
 * Copyright (c) 2013 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "vmm_defs.h"
#include "common_libc.h"
#include "heap.h"
#include "hw_utils.h"
#include "em64t_defs.h"
#include "ia32_defs.h"
#include "gdt.h"
#include "vmm_dbg.h"
#include "file_codes.h"

#define VMM_DEADLOOP()          VMM_DEADLOOP_LOG(EM64T_GDT_C)
#define VMM_ASSERT(__condition) VMM_ASSERT_LOG(EM64T_GDT_C, __condition)


static UINT8 *gdt = NULL;
static EM64T_TASK_STATE_SEGMENT *p_tss = NULL;
static UINT16 gdt_size;
static CPU_ID gdt_number_of_cpus = 0;

typedef struct {
    UINT32 lo;
    UINT32 hi;
} UINT64_EMULATED;


static void setup_data32_segment_descriptor(
    void)
{
    IA32_DATA_SEGMENT_DESCRIPTOR *p_data32 = (IA32_DATA_SEGMENT_DESCRIPTOR *) &gdt[DATA32_GDT_ENTRY_OFFSET];


    p_data32->lo.limit_15_00           = 0xFFFF;
    p_data32->lo.base_address_15_00    = 0;

    p_data32->hi.base_address_23_16    = 0;
    p_data32->hi.accessed              = 0;
    p_data32->hi.writable              = 1;
    p_data32->hi.expansion_direction   = 0;    // up
    p_data32->hi.mbz_11                = 0;
    p_data32->hi.mbo_12                = 1;
    p_data32->hi.dpl                   = 0;    // privileged
    p_data32->hi.present               = 1;
    p_data32->hi.limit_19_16           = 0xF;
    p_data32->hi.avl                   = 0;    // available to SW
    p_data32->hi.mbz_21                = 0;
    p_data32->hi.big                   = 1;    // 32-bit access
    p_data32->hi.granularity           = 1;    // segment limit measured in 4K units
    p_data32->hi.base_address_31_24    = 0;
}


static void setup_code32_segment_descriptor(
    void)
{
    IA32_CODE_SEGMENT_DESCRIPTOR *p_code32 = (IA32_CODE_SEGMENT_DESCRIPTOR *) &gdt[CODE32_GDT_ENTRY_OFFSET];
    p_code32->lo.limit_15_00           = 0xFFFF;
    p_code32->lo.base_address_15_00    = 0;

    p_code32->hi.base_address_23_16    = 0;
    p_code32->hi.accessed              = 0;
    p_code32->hi.readable              = 1;
    p_code32->hi.conforming            = 0;    // strict privilege checkings
    p_code32->hi.mbo_11                = 1;
    p_code32->hi.mbo_12                = 1;
    p_code32->hi.dpl                   = 0;    // privileged
    p_code32->hi.present               = 1;
    p_code32->hi.limit_19_16           = 0xF;
    p_code32->hi.avl                   = 0;    // available to SW
    p_code32->hi.mbz_21                = 0;
    p_code32->hi.default_size          = 1;    // 32-bit access
    p_code32->hi.granularity           = 1;    // segment limit measured in 4K units
    p_code32->hi.base_address_31_24    = 0;
}


static void setup_code64_segment_descriptor(
    void)
{
    EM64T_CODE_SEGMENT_DESCRIPTOR *p_code64 = (EM64T_CODE_SEGMENT_DESCRIPTOR *) &gdt[CODE64_GDT_ENTRY_OFFSET];

    // low 32-bit word is reserved, configure only high word
    p_code64->hi.accessed       = 0;
    p_code64->hi.readable       = 1;
    p_code64->hi.conforming     = 1; /// ??? 0;
    p_code64->hi.mbo_11         = 1;
    p_code64->hi.mbo_12         = 1;
    p_code64->hi.dpl            = 0;
    p_code64->hi.present        = 1;
    p_code64->hi.long_mode      = 1;    // important !!!
    p_code64->hi.default_size   = 0;    // important !!!
    p_code64->hi.granularity    = 0;
}

static void setup_tss_with_descriptor(
    CPU_ID cpu_id)
{
    EM64T_TSS_SEGMENT_DESCRIPTOR *p_tss_dx = (EM64T_TSS_SEGMENT_DESCRIPTOR *) &gdt[TSS_ENTRY_OFFSET(cpu_id)];
    UINT64  base_address    = (UINT64) &p_tss[cpu_id];
    UINT32  segment_limit   = OFFSET_OF(EM64T_TASK_STATE_SEGMENT, io_bitmap_last_byte);

    p_tss_dx->q0.segment_limit_00_15    = segment_limit & 0xFFFF;
    p_tss_dx->q0.base_address_00_15     = (UINT32) (base_address & 0xFFFF);

    p_tss_dx->q1.base_address_23_16     = ((UINT32) (base_address >> 16)) & 0xFF;
    p_tss_dx->q1.type                   = 9;    // means TSS descriptor
    p_tss_dx->q1.mbz_12                 = 0;
    p_tss_dx->q1.dpl                    = 0;
    p_tss_dx->q1.present                = 1;
    p_tss_dx->q1.segment_limit_16_19    = (segment_limit >> 16) & 0xF;
    p_tss_dx->q1.avl                    = 0;
    p_tss_dx->q1.mbz_21_22              = 0;
    p_tss_dx->q1.granularity            = 0;
    p_tss_dx->q1.base_address_31_24     = ((UINT32) (base_address >> 24)) & 0xFF;

    p_tss_dx->q2.base_address_32_63     = (UINT32) (base_address >> 32);

    p_tss_dx->q3 = 0;

    // that means no IO ports are blocked
    p_tss[cpu_id].io_bitmap_address = OFFSET_OF(EM64T_TASK_STATE_SEGMENT, io_bitmap_last_byte);
    p_tss[cpu_id].io_bitmap_last_byte = 0xFF;
}


/*-------------------------------------------------------*
*  FUNCTION     : hw_gdt_setup()
*  PURPOSE      : Setup GDT for all CPUs. Including entries for:
*               : 64-bit code segment
*               : 32-bit code segment (for compatibility mode)
*               : 32-bit data segment (in compatibility mode, for both data and stack)
*               : one 64-bit for FS, which limit is used like index CPU ID
*  ARGUMENTS    : IN CPU_ID number_of_cpus - number of CPUs in the system
*  RETURNS      : void
*-------------------------------------------------------*/
void hw_gdt_setup(IN CPU_ID number_of_cpus)
{
    CPU_ID cpu_id;

    if (NULL == gdt)
    {
        // Offset of next after last entry will give us the size
        gdt_size = TSS_ENTRY_OFFSET(number_of_cpus);
        gdt = vmm_memory_alloc(gdt_size);
        // BEFORE_VMLAUNCH. We must ASSERT if condition is false.
        VMM_ASSERT(NULL != gdt);

        p_tss = vmm_memory_alloc(sizeof(EM64T_TASK_STATE_SEGMENT) * number_of_cpus);
        // BEFORE_VMLAUNCH. We must ASSERT if condition is false.
        VMM_ASSERT(NULL != p_tss);
    }

    gdt_number_of_cpus = number_of_cpus;

    setup_data32_segment_descriptor();
    setup_code32_segment_descriptor();
    setup_code64_segment_descriptor();


    for (cpu_id = 0; cpu_id < number_of_cpus; ++cpu_id)
    {
        setup_tss_with_descriptor(cpu_id);
    }

}
#ifdef DEBUG
void gdt_show(void)
{
    EM64T_GDTR gdtr;
    UINT64_EMULATED *p_base;
    unsigned i;


    hw_sgdt(&gdtr);

    p_base = (UINT64_EMULATED *) gdtr.base;

    VMM_LOG(mask_anonymous, level_trace,"Limit = %04X\n", gdtr.limit);

    for (i = 0; i < (gdtr.limit + 1) / sizeof(UINT64_EMULATED); ++i)
    {
        VMM_LOG(mask_anonymous, level_trace,"%02X %08X %08X\n", i, p_base[i].lo, p_base[i].hi);
    }
}
#endif

/*-------------------------------------------------------*
*  FUNCTION     : hw_gdt_load()
*  PURPOSE      : Load GDT on given CPU
*  ARGUMENTS    : IN CPU_ID cpu_id
*  RETURNS      : void
*-------------------------------------------------------*/
void hw_gdt_load(IN CPU_ID cpu_id)
{
    EM64T_GDTR gdtr;

    // BEFORE_VMLAUNCH. We must ASSERT if condition is false.
    VMM_ASSERT(NULL != gdt);
    // BEFORE_VMLAUNCH. We must ASSERT if condition is false.
    VMM_ASSERT(cpu_id < gdt_number_of_cpus);

    gdtr.limit = gdt_size - 1;
    gdtr.base  = (UINT64) gdt;

//    VMM_LOG(mask_anonymous, level_trace,"GDT BEFORE\n");
//    gdt_show();
    hw_lgdt(&gdtr);
//    VMM_LOG(mask_anonymous, level_trace,"GDT AFTER\n");
//    gdt_show();

    hw_write_ds(DATA32_GDT_ENTRY_OFFSET);
    hw_write_ss(DATA32_GDT_ENTRY_OFFSET);
    hw_write_cs(CODE64_GDT_ENTRY_OFFSET);

    setup_tss_with_descriptor(cpu_id); // do it again here, in case we called after S3
    hw_write_tr(TSS_ENTRY_OFFSET(cpu_id));

    hw_write_ldtr(0);

    hw_write_es(0);
    hw_write_fs(0);
    hw_write_gs(0);

}

/*-------------------------------------------------------*
*  FUNCTION     : hw_gdt_set_ist_pointer()
*  PURPOSE      : Assign address to specified IST
*  ARGUMENTS    : CPU_ID cpu_id
*               : UINT8 ist_no - in range [0..7]
*               : ADDRESS address - of specified Interrupt Stack
*  RETURNS      : void
*-------------------------------------------------------*/
void hw_gdt_set_ist_pointer(CPU_ID cpu_id, UINT8 ist_no, ADDRESS address)
{
    // BEFORE_VMLAUNCH
    VMM_ASSERT(ist_no <= 7);
    // BEFORE_VMLAUNCH
    VMM_ASSERT(cpu_id < gdt_number_of_cpus);
    // BEFORE_VMLAUNCH
    VMM_ASSERT(NULL != p_tss);
    p_tss[cpu_id].ist[ist_no] = address;
}

VMM_STATUS hw_gdt_parse_entry(
    IN UINT8    *p_gdt,
    IN UINT16   selector,
    OUT ADDRESS *p_base,
    OUT UINT32  *p_limit,
    OUT UINT32  *p_attributes)
{
    UINT32 *p_entry = (UINT32 *) &p_gdt[selector];
    VMM_STATUS status = VMM_OK;

    switch (selector)
    {
    case NULL_GDT_ENTRY_OFFSET:
        *p_base       = 0;
        *p_limit      = 0;
        *p_attributes = EM64T_SEGMENT_IS_UNUSABLE_ATTRUBUTE_VALUE; // set "unusable" bit to 1
        break;

    case CODE64_GDT_ENTRY_OFFSET:
        *p_base       = 0;
        *p_limit      = 0;
        *p_attributes = (p_entry[1] >> 8) & 0xF0FF;
        break;

    case DATA32_GDT_ENTRY_OFFSET:
    case CODE32_GDT_ENTRY_OFFSET:
        *p_base =  (p_entry[1]        & 0xFF000000) |
                   ((p_entry[1] << 16) & 0x00FF0000) |
                   ((p_entry[0] >> 16) & 0x0000FFFF);
        *p_limit      = (p_entry[0] & 0xFFFF) | (p_entry[1] & 0x000F0000);
        *p_attributes = (p_entry[1] >> 8) & 0xF0FF;
        break;

    default:    // Task Switch Segment
        if (selector > TSS_ENTRY_OFFSET(gdt_number_of_cpus-1) ||    // exceeds limit or
            0 != (selector & 0xF)) {                                // not aligned on 16 bytes
            status = VMM_ERROR;
        }
        else {
            *p_base = p_entry[2];
            *p_base <<= 32;
            *p_base |=  (p_entry[1] & 0xFF000000) | ((p_entry[1] << 16) & 0x00FF0000) |
                        ((p_entry[0] >> 16) & 0x0000FFFF);
            *p_limit = (p_entry[0] & 0xFFFF) | (p_entry[1] & 0x000F0000);
            *p_attributes = (p_entry[1] >> 8) & 0xF0FF;
        }
        break;
    }

    return status;
}

