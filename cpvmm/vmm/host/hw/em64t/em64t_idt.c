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

////////////////////////////////////////////////////////////////////
//
//  This code is assumed to be running in 32-bit mode,
//  but configure IDT for 64-bit mode.
//
////////////////////////////////////////////////////////////////////


#include "vmm_defs.h"
#include "common_libc.h"
#include "heap.h"
#include "em64t_defs.h"
#include "hw_utils.h"
#include "isr_generated.h"
#include "idt.h"

extern void dump_memory(const void * mem_location,UINT32 count,UINT32 size);

#define IDT_VECTOR_COUNT 256

#define IA32E_IDT_GATE_TYPE_INTERRUPT_GATE  0xE
#define IA32E_IDT_GATE_TYPE_TRAP_GATE       0xF


static EM64T_IDT_TABLE idt;  // pointer to IDTs for all CPUs
static UINT8 ist_used[32] = {
    0,
    0,
    1,  // NMI
    0,
    0,
    0,
    2,  // UNDEFINED_OPCODE
    0,
    3,  // DOUBLE_FAULT
    0,
    0,
    0,
    4,  // STACK_SEGMENT_FAULT
    5,  // GENERAL_PROTECTION_FAULT
    6,  // PAGE_FAULT
};

static ADDRESS isr_handler_table[256] =
{
    (ADDRESS) isr_entry_00,
    (ADDRESS) isr_entry_01,
    (ADDRESS) isr_entry_02,
    (ADDRESS) isr_entry_03,
    (ADDRESS) isr_entry_04,
    (ADDRESS) isr_entry_05,
    (ADDRESS) isr_entry_06,
    (ADDRESS) isr_entry_07,
    (ADDRESS) isr_entry_08,
    (ADDRESS) isr_entry_09,
    (ADDRESS) isr_entry_0a,
    (ADDRESS) isr_entry_0b,
    (ADDRESS) isr_entry_0c,
    (ADDRESS) isr_entry_0d,
    (ADDRESS) isr_entry_0e,
    (ADDRESS) isr_entry_0f,
    (ADDRESS) isr_entry_10,
    (ADDRESS) isr_entry_11,
    (ADDRESS) isr_entry_12,
    (ADDRESS) isr_entry_13,
    (ADDRESS) isr_entry_14,
    (ADDRESS) isr_entry_15,
    (ADDRESS) isr_entry_16,
    (ADDRESS) isr_entry_17,
    (ADDRESS) isr_entry_18,
    (ADDRESS) isr_entry_19,
    (ADDRESS) isr_entry_1a,
    (ADDRESS) isr_entry_1b,
    (ADDRESS) isr_entry_1c,
    (ADDRESS) isr_entry_1d,
    (ADDRESS) isr_entry_1e,
    (ADDRESS) isr_entry_1f,
    (ADDRESS) isr_entry_20,
    (ADDRESS) isr_entry_21,
    (ADDRESS) isr_entry_22,
    (ADDRESS) isr_entry_23,
    (ADDRESS) isr_entry_24,
    (ADDRESS) isr_entry_25,
    (ADDRESS) isr_entry_26,
    (ADDRESS) isr_entry_27,
    (ADDRESS) isr_entry_28,
    (ADDRESS) isr_entry_29,
    (ADDRESS) isr_entry_2a,
    (ADDRESS) isr_entry_2b,
    (ADDRESS) isr_entry_2c,
    (ADDRESS) isr_entry_2d,
    (ADDRESS) isr_entry_2e,
    (ADDRESS) isr_entry_2f,
    (ADDRESS) isr_entry_30,
    (ADDRESS) isr_entry_31,
    (ADDRESS) isr_entry_32,
    (ADDRESS) isr_entry_33,
    (ADDRESS) isr_entry_34,
    (ADDRESS) isr_entry_35,
    (ADDRESS) isr_entry_36,
    (ADDRESS) isr_entry_37,
    (ADDRESS) isr_entry_38,
    (ADDRESS) isr_entry_39,
    (ADDRESS) isr_entry_3a,
    (ADDRESS) isr_entry_3b,
    (ADDRESS) isr_entry_3c,
    (ADDRESS) isr_entry_3d,
    (ADDRESS) isr_entry_3e,
    (ADDRESS) isr_entry_3f,
    (ADDRESS) isr_entry_40,
    (ADDRESS) isr_entry_41,
    (ADDRESS) isr_entry_42,
    (ADDRESS) isr_entry_43,
    (ADDRESS) isr_entry_44,
    (ADDRESS) isr_entry_45,
    (ADDRESS) isr_entry_46,
    (ADDRESS) isr_entry_47,
    (ADDRESS) isr_entry_48,
    (ADDRESS) isr_entry_49,
    (ADDRESS) isr_entry_4a,
    (ADDRESS) isr_entry_4b,
    (ADDRESS) isr_entry_4c,
    (ADDRESS) isr_entry_4d,
    (ADDRESS) isr_entry_4e,
    (ADDRESS) isr_entry_4f,
    (ADDRESS) isr_entry_50,
    (ADDRESS) isr_entry_51,
    (ADDRESS) isr_entry_52,
    (ADDRESS) isr_entry_53,
    (ADDRESS) isr_entry_54,
    (ADDRESS) isr_entry_55,
    (ADDRESS) isr_entry_56,
    (ADDRESS) isr_entry_57,
    (ADDRESS) isr_entry_58,
    (ADDRESS) isr_entry_59,
    (ADDRESS) isr_entry_5a,
    (ADDRESS) isr_entry_5b,
    (ADDRESS) isr_entry_5c,
    (ADDRESS) isr_entry_5d,
    (ADDRESS) isr_entry_5e,
    (ADDRESS) isr_entry_5f,
    (ADDRESS) isr_entry_60,
    (ADDRESS) isr_entry_61,
    (ADDRESS) isr_entry_62,
    (ADDRESS) isr_entry_63,
    (ADDRESS) isr_entry_64,
    (ADDRESS) isr_entry_65,
    (ADDRESS) isr_entry_66,
    (ADDRESS) isr_entry_67,
    (ADDRESS) isr_entry_68,
    (ADDRESS) isr_entry_69,
    (ADDRESS) isr_entry_6a,
    (ADDRESS) isr_entry_6b,
    (ADDRESS) isr_entry_6c,
    (ADDRESS) isr_entry_6d,
    (ADDRESS) isr_entry_6e,
    (ADDRESS) isr_entry_6f,
    (ADDRESS) isr_entry_70,
    (ADDRESS) isr_entry_71,
    (ADDRESS) isr_entry_72,
    (ADDRESS) isr_entry_73,
    (ADDRESS) isr_entry_74,
    (ADDRESS) isr_entry_75,
    (ADDRESS) isr_entry_76,
    (ADDRESS) isr_entry_77,
    (ADDRESS) isr_entry_78,
    (ADDRESS) isr_entry_79,
    (ADDRESS) isr_entry_7a,
    (ADDRESS) isr_entry_7b,
    (ADDRESS) isr_entry_7c,
    (ADDRESS) isr_entry_7d,
    (ADDRESS) isr_entry_7e,
    (ADDRESS) isr_entry_7f,
    (ADDRESS) isr_entry_80,
    (ADDRESS) isr_entry_81,
    (ADDRESS) isr_entry_82,
    (ADDRESS) isr_entry_83,
    (ADDRESS) isr_entry_84,
    (ADDRESS) isr_entry_85,
    (ADDRESS) isr_entry_86,
    (ADDRESS) isr_entry_87,
    (ADDRESS) isr_entry_88,
    (ADDRESS) isr_entry_89,
    (ADDRESS) isr_entry_8a,
    (ADDRESS) isr_entry_8b,
    (ADDRESS) isr_entry_8c,
    (ADDRESS) isr_entry_8d,
    (ADDRESS) isr_entry_8e,
    (ADDRESS) isr_entry_8f,
    (ADDRESS) isr_entry_90,
    (ADDRESS) isr_entry_91,
    (ADDRESS) isr_entry_92,
    (ADDRESS) isr_entry_93,
    (ADDRESS) isr_entry_94,
    (ADDRESS) isr_entry_95,
    (ADDRESS) isr_entry_96,
    (ADDRESS) isr_entry_97,
    (ADDRESS) isr_entry_98,
    (ADDRESS) isr_entry_99,
    (ADDRESS) isr_entry_9a,
    (ADDRESS) isr_entry_9b,
    (ADDRESS) isr_entry_9c,
    (ADDRESS) isr_entry_9d,
    (ADDRESS) isr_entry_9e,
    (ADDRESS) isr_entry_9f,
    (ADDRESS) isr_entry_a0,
    (ADDRESS) isr_entry_a1,
    (ADDRESS) isr_entry_a2,
    (ADDRESS) isr_entry_a3,
    (ADDRESS) isr_entry_a4,
    (ADDRESS) isr_entry_a5,
    (ADDRESS) isr_entry_a6,
    (ADDRESS) isr_entry_a7,
    (ADDRESS) isr_entry_a8,
    (ADDRESS) isr_entry_a9,
    (ADDRESS) isr_entry_aa,
    (ADDRESS) isr_entry_ab,
    (ADDRESS) isr_entry_ac,
    (ADDRESS) isr_entry_ad,
    (ADDRESS) isr_entry_ae,
    (ADDRESS) isr_entry_af,
    (ADDRESS) isr_entry_b0,
    (ADDRESS) isr_entry_b1,
    (ADDRESS) isr_entry_b2,
    (ADDRESS) isr_entry_b3,
    (ADDRESS) isr_entry_b4,
    (ADDRESS) isr_entry_b5,
    (ADDRESS) isr_entry_b6,
    (ADDRESS) isr_entry_b7,
    (ADDRESS) isr_entry_b8,
    (ADDRESS) isr_entry_b9,
    (ADDRESS) isr_entry_ba,
    (ADDRESS) isr_entry_bb,
    (ADDRESS) isr_entry_bc,
    (ADDRESS) isr_entry_bd,
    (ADDRESS) isr_entry_be,
    (ADDRESS) isr_entry_bf,
    (ADDRESS) isr_entry_c0,
    (ADDRESS) isr_entry_c1,
    (ADDRESS) isr_entry_c2,
    (ADDRESS) isr_entry_c3,
    (ADDRESS) isr_entry_c4,
    (ADDRESS) isr_entry_c5,
    (ADDRESS) isr_entry_c6,
    (ADDRESS) isr_entry_c7,
    (ADDRESS) isr_entry_c8,
    (ADDRESS) isr_entry_c9,
    (ADDRESS) isr_entry_ca,
    (ADDRESS) isr_entry_cb,
    (ADDRESS) isr_entry_cc,
    (ADDRESS) isr_entry_cd,
    (ADDRESS) isr_entry_ce,
    (ADDRESS) isr_entry_cf,
    (ADDRESS) isr_entry_d0,
    (ADDRESS) isr_entry_d1,
    (ADDRESS) isr_entry_d2,
    (ADDRESS) isr_entry_d3,
    (ADDRESS) isr_entry_d4,
    (ADDRESS) isr_entry_d5,
    (ADDRESS) isr_entry_d6,
    (ADDRESS) isr_entry_d7,
    (ADDRESS) isr_entry_d8,
    (ADDRESS) isr_entry_d9,
    (ADDRESS) isr_entry_da,
    (ADDRESS) isr_entry_db,
    (ADDRESS) isr_entry_dc,
    (ADDRESS) isr_entry_dd,
    (ADDRESS) isr_entry_de,
    (ADDRESS) isr_entry_df,
    (ADDRESS) isr_entry_e0,
    (ADDRESS) isr_entry_e1,
    (ADDRESS) isr_entry_e2,
    (ADDRESS) isr_entry_e3,
    (ADDRESS) isr_entry_e4,
    (ADDRESS) isr_entry_e5,
    (ADDRESS) isr_entry_e6,
    (ADDRESS) isr_entry_e7,
    (ADDRESS) isr_entry_e8,
    (ADDRESS) isr_entry_e9,
    (ADDRESS) isr_entry_ea,
    (ADDRESS) isr_entry_eb,
    (ADDRESS) isr_entry_ec,
    (ADDRESS) isr_entry_ed,
    (ADDRESS) isr_entry_ee,
    (ADDRESS) isr_entry_ef,
    (ADDRESS) isr_entry_f0,
    (ADDRESS) isr_entry_f1,
    (ADDRESS) isr_entry_f2,
    (ADDRESS) isr_entry_f3,
    (ADDRESS) isr_entry_f4,
    (ADDRESS) isr_entry_f5,
    (ADDRESS) isr_entry_f6,
    (ADDRESS) isr_entry_f7,
    (ADDRESS) isr_entry_f8,
    (ADDRESS) isr_entry_f9,
    (ADDRESS) isr_entry_fa,
    (ADDRESS) isr_entry_fb,
    (ADDRESS) isr_entry_fc,
    (ADDRESS) isr_entry_fd,
    (ADDRESS) isr_entry_fe,
    (ADDRESS) isr_entry_ff
};

/*-------------------------------------------------------*
*  FUNCTION     : hw_idt_register_handler()
*  PURPOSE      : Register interrupt handler at spec. vector
*  ARGUMENTS    : UINT8 vector_id
*               : ADDRESS isr_handler_address - address of function
*  RETURNS      : void
*-------------------------------------------------------*/
void hw_idt_register_handler(
    VECTOR_ID   vector_id,
    ADDRESS     isr_handler_address)
{
    // fill IDT entries with it
    idt[vector_id].offset_0_15    = (UINT32) GET_2BYTE(isr_handler_address, 0);
    idt[vector_id].offset_15_31   = (UINT32) GET_2BYTE(isr_handler_address, 1);
    idt[vector_id].offset_32_63   = (UINT32) GET_4BYTE(isr_handler_address, 1);
    idt[vector_id].ist            = vector_id < NELEMENTS(ist_used) ? ist_used[vector_id] : 0;
    idt[vector_id].gate_type      = IA32E_IDT_GATE_TYPE_INTERRUPT_GATE;
    idt[vector_id].dpl            = 0;
    idt[vector_id].present        = 1;
    idt[vector_id].css            = CODE64_GDT_ENTRY_OFFSET;
}


/*-------------------------------------------------------*
*  FUNCTION     : hw_idt_setup()
*  PURPOSE      : Build and populate IDT table, used by all CPUs
*  ARGUMENTS    : void
*  RETURNS      : void
*-------------------------------------------------------*/
void hw_idt_setup(void)
{
    unsigned vector_id;

    for (vector_id = 0; vector_id < IDT_VECTOR_COUNT; ++vector_id)
    {
        hw_idt_register_handler((VECTOR_ID) vector_id, isr_handler_table[vector_id]);
    }
}

/*-------------------------------------------------------*
*  FUNCTION     : hw_idt_load()
*  PURPOSE      : Load IDT descriptor into IDTR of CPU, currently excuted
*  ARGUMENTS    : void
*  RETURNS      : void
*-------------------------------------------------------*/
void hw_idt_load(void)
{
    EM64T_IDT_DESCRIPTOR idt_desc;

    idt_desc.base = (ADDRESS) idt;
    idt_desc.limit = sizeof(idt) - 1;
    hw_lidt((void*)&idt_desc);
}

/*----------------------------------------------------*
*  FUNCTION     : idt_get_extra_stacks_required()
*  PURPOSE      : Returns the number of extra stacks required by ISRs
*  ARGUMENTS    : void
*  RETURNS      : number between 0..7
*  NOTES        : per CPU
*-------------------------------------------------------*/
UINT8 idt_get_extra_stacks_required(
    void
    )
{
    return 6;   // the number of no-zero elements in array <ist_used>
}

