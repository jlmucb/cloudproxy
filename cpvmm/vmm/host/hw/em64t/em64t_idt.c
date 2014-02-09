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

extern void isr_entry_00(void);
extern void isr_entry_01(void);
static ADDRESS isr_handler_table[256];

static void init_isr_handler_table() {

		isr_handler_table[0] = (isr_entry_00);
		isr_handler_table[1] = (isr_entry_01);
		isr_handler_table[2] = (isr_entry_02);
		isr_handler_table[3] = (isr_entry_03);
		isr_handler_table[4] = (isr_entry_04);
		isr_handler_table[5] = (isr_entry_05);
		isr_handler_table[6] = (isr_entry_06);
		isr_handler_table[7] = (isr_entry_07);
		isr_handler_table[8] = (isr_entry_08);
		isr_handler_table[9] = (isr_entry_09);
		isr_handler_table[10] = (isr_entry_0a);
		isr_handler_table[11] = (isr_entry_0b);
		isr_handler_table[12] = (isr_entry_0c);
		isr_handler_table[13] = (isr_entry_0d);
		isr_handler_table[14] = (isr_entry_0e);
		isr_handler_table[15] = (isr_entry_0f);
		isr_handler_table[16] = (isr_entry_10);
		isr_handler_table[17] = (isr_entry_11);
		isr_handler_table[18] = (isr_entry_12);
		isr_handler_table[19] = (isr_entry_13);
		isr_handler_table[20] = (isr_entry_14);
		isr_handler_table[21] = (isr_entry_15);
		isr_handler_table[22] = (isr_entry_16);
		isr_handler_table[23] = (isr_entry_17);
		isr_handler_table[24] = (isr_entry_18);
		isr_handler_table[25] = (isr_entry_19);
		isr_handler_table[26] = (isr_entry_1a);
		isr_handler_table[27] = (isr_entry_1b);
		isr_handler_table[28] = (isr_entry_1c);
		isr_handler_table[29] = (isr_entry_1d);
		isr_handler_table[30] = (isr_entry_1e);
		isr_handler_table[31] = (isr_entry_1f);
		isr_handler_table[32] = (isr_entry_20);
		isr_handler_table[33] = (isr_entry_21);
		isr_handler_table[34] = (isr_entry_22);
		isr_handler_table[35] = (isr_entry_23);
		isr_handler_table[36] = (isr_entry_24);
		isr_handler_table[37] = (isr_entry_25);
		isr_handler_table[38] = (isr_entry_26);
		isr_handler_table[39] = (isr_entry_27);
		isr_handler_table[40] = (isr_entry_28);
		isr_handler_table[41] = (isr_entry_29);
		isr_handler_table[42] = (isr_entry_2a);
		isr_handler_table[43] = (isr_entry_2b);
		isr_handler_table[44] = (isr_entry_2c);
		isr_handler_table[45] = (isr_entry_2d);
		isr_handler_table[46] = (isr_entry_2e);
		isr_handler_table[47] = (isr_entry_2f);
		isr_handler_table[48] = (isr_entry_30);
		isr_handler_table[49] = (isr_entry_31);
		isr_handler_table[50] = (isr_entry_32);
		isr_handler_table[51] = (isr_entry_33);
		isr_handler_table[52] = (isr_entry_34);
		isr_handler_table[53] = (isr_entry_35);
		isr_handler_table[54] = (isr_entry_36);
		isr_handler_table[55] = (isr_entry_37);
		isr_handler_table[56] = (isr_entry_38);
		isr_handler_table[57] = (isr_entry_39);
		isr_handler_table[58] = (isr_entry_3a);
		isr_handler_table[59] = (isr_entry_3b);
		isr_handler_table[60] = (isr_entry_3c);
		isr_handler_table[61] = (isr_entry_3d);
		isr_handler_table[62] = (isr_entry_3e);
		isr_handler_table[63] = (isr_entry_3f);
		isr_handler_table[64] = (isr_entry_40);
		isr_handler_table[65] = (isr_entry_41);
		isr_handler_table[66] = (isr_entry_42);
		isr_handler_table[67] = (isr_entry_43);
		isr_handler_table[68] = (isr_entry_44);
		isr_handler_table[69] = (isr_entry_45);
		isr_handler_table[70] = (isr_entry_46);
		isr_handler_table[71] = (isr_entry_47);
		isr_handler_table[72] = (isr_entry_48);
		isr_handler_table[73] = (isr_entry_49);
		isr_handler_table[74] = (isr_entry_4a);
		isr_handler_table[75] = (isr_entry_4b);
		isr_handler_table[76] = (isr_entry_4c);
		isr_handler_table[77] = (isr_entry_4d);
		isr_handler_table[78] = (isr_entry_4e);
		isr_handler_table[79] = (isr_entry_4f);
		isr_handler_table[80] = (isr_entry_50);
		isr_handler_table[81] = (isr_entry_51);
		isr_handler_table[82] = (isr_entry_52);
		isr_handler_table[83] = (isr_entry_53);
		isr_handler_table[84] = (isr_entry_54);
		isr_handler_table[85] = (isr_entry_55);
		isr_handler_table[86] = (isr_entry_56);
		isr_handler_table[87] = (isr_entry_57);
		isr_handler_table[88] = (isr_entry_58);
		isr_handler_table[89] = (isr_entry_59);
		isr_handler_table[90] = (isr_entry_5a);
		isr_handler_table[91] = (isr_entry_5b);
		isr_handler_table[92] = (isr_entry_5c);
		isr_handler_table[93] = (isr_entry_5d);
		isr_handler_table[94] = (isr_entry_5e);
		isr_handler_table[95] = (isr_entry_5f);
		isr_handler_table[96] = (isr_entry_60);
		isr_handler_table[97] = (isr_entry_61);
		isr_handler_table[98] = (isr_entry_62);
		isr_handler_table[99] = (isr_entry_63);
		isr_handler_table[100] = (isr_entry_64);
		isr_handler_table[101] = (isr_entry_65);
		isr_handler_table[102] = (isr_entry_66);
		isr_handler_table[103] = (isr_entry_67);
		isr_handler_table[104] = (isr_entry_68);
		isr_handler_table[105] = (isr_entry_69);
		isr_handler_table[106] = (isr_entry_6a);
		isr_handler_table[107] = (isr_entry_6b);
		isr_handler_table[108] = (isr_entry_6c);
		isr_handler_table[109] = (isr_entry_6d);
		isr_handler_table[110] = (isr_entry_6e);
		isr_handler_table[111] = (isr_entry_6f);
		isr_handler_table[112] = (isr_entry_70);
		isr_handler_table[113] = (isr_entry_71);
		isr_handler_table[114] = (isr_entry_72);
		isr_handler_table[115] = (isr_entry_73);
		isr_handler_table[116] = (isr_entry_74);
		isr_handler_table[117] = (isr_entry_75);
		isr_handler_table[118] = (isr_entry_76);
		isr_handler_table[119] = (isr_entry_77);
		isr_handler_table[120] = (isr_entry_78);
		isr_handler_table[121] = (isr_entry_79);
		isr_handler_table[122] = (isr_entry_7a);
		isr_handler_table[123] = (isr_entry_7b);
		isr_handler_table[124] = (isr_entry_7c);
		isr_handler_table[125] = (isr_entry_7d);
		isr_handler_table[126] = (isr_entry_7e);
		isr_handler_table[127] = (isr_entry_7f);
		isr_handler_table[128] = (isr_entry_80);
		isr_handler_table[129] = (isr_entry_81);
		isr_handler_table[130] = (isr_entry_82);
		isr_handler_table[131] = (isr_entry_83);
		isr_handler_table[132] = (isr_entry_84);
		isr_handler_table[133] = (isr_entry_85);
		isr_handler_table[134] = (isr_entry_86);
		isr_handler_table[135] = (isr_entry_87);
		isr_handler_table[136] = (isr_entry_88);
		isr_handler_table[137] = (isr_entry_89);
		isr_handler_table[138] = (isr_entry_8a);
		isr_handler_table[139] = (isr_entry_8b);
		isr_handler_table[140] = (isr_entry_8c);
		isr_handler_table[141] = (isr_entry_8d);
		isr_handler_table[142] = (isr_entry_8e);
		isr_handler_table[143] = (isr_entry_8f);
		isr_handler_table[144] = (isr_entry_90);
		isr_handler_table[145] = (isr_entry_91);
		isr_handler_table[146] = (isr_entry_92);
		isr_handler_table[147] = (isr_entry_93);
		isr_handler_table[148] = (isr_entry_94);
		isr_handler_table[149] = (isr_entry_95);
		isr_handler_table[150] = (isr_entry_96);
		isr_handler_table[151] = (isr_entry_97);
		isr_handler_table[152] = (isr_entry_98);
		isr_handler_table[153] = (isr_entry_99);
		isr_handler_table[154] = (isr_entry_9a);
		isr_handler_table[155] = (isr_entry_9b);
		isr_handler_table[156] = (isr_entry_9c);
		isr_handler_table[157] = (isr_entry_9d);
		isr_handler_table[158] = (isr_entry_9e);
		isr_handler_table[159] = (isr_entry_9f);
		isr_handler_table[160] = (isr_entry_a0);
		isr_handler_table[161] = (isr_entry_a1);
		isr_handler_table[162] = (isr_entry_a2);
		isr_handler_table[163] = (isr_entry_a3);
		isr_handler_table[164] = (isr_entry_a4);
		isr_handler_table[165] = (isr_entry_a5);
		isr_handler_table[166] = (isr_entry_a6);
		isr_handler_table[167] = (isr_entry_a7);
		isr_handler_table[168] = (isr_entry_a8);
		isr_handler_table[169] = (isr_entry_a9);
		isr_handler_table[170] = (isr_entry_aa);
		isr_handler_table[171] = (isr_entry_ab);
		isr_handler_table[172] = (isr_entry_ac);
		isr_handler_table[173] = (isr_entry_ad);
		isr_handler_table[174] = (isr_entry_ae);
		isr_handler_table[175] = (isr_entry_af);
		isr_handler_table[176] = (isr_entry_b0);
		isr_handler_table[177] = (isr_entry_b1);
		isr_handler_table[178] = (isr_entry_b2);
		isr_handler_table[179] = (isr_entry_b3);
		isr_handler_table[180] = (isr_entry_b4);
		isr_handler_table[181] = (isr_entry_b5);
		isr_handler_table[182] = (isr_entry_b6);
		isr_handler_table[183] = (isr_entry_b7);
		isr_handler_table[184] = (isr_entry_b8);
		isr_handler_table[185] = (isr_entry_b9);
		isr_handler_table[186] = (isr_entry_ba);
		isr_handler_table[187] = (isr_entry_bb);
		isr_handler_table[188] = (isr_entry_bc);
		isr_handler_table[189] = (isr_entry_bd);
		isr_handler_table[190] = (isr_entry_be);
		isr_handler_table[191] = (isr_entry_bf);
		isr_handler_table[192] = (isr_entry_c0);
		isr_handler_table[193] = (isr_entry_c1);
		isr_handler_table[194] = (isr_entry_c2);
		isr_handler_table[195] = (isr_entry_c3);
		isr_handler_table[196] = (isr_entry_c4);
		isr_handler_table[197] = (isr_entry_c5);
		isr_handler_table[198] = (isr_entry_c6);
		isr_handler_table[199] = (isr_entry_c7);
		isr_handler_table[200] = (isr_entry_c8);
		isr_handler_table[201] = (isr_entry_c9);
		isr_handler_table[202] = (isr_entry_ca);
		isr_handler_table[203] = (isr_entry_cb);
		isr_handler_table[204] = (isr_entry_cc);
		isr_handler_table[205] = (isr_entry_cd);
		isr_handler_table[206] = (isr_entry_ce);
		isr_handler_table[207] = (isr_entry_cf);
		isr_handler_table[208] = (isr_entry_d0);
		isr_handler_table[209] = (isr_entry_d1);
		isr_handler_table[210] = (isr_entry_d2);
		isr_handler_table[211] = (isr_entry_d3);
		isr_handler_table[212] = (isr_entry_d4);
		isr_handler_table[213] = (isr_entry_d5);
		isr_handler_table[214] = (isr_entry_d6);
		isr_handler_table[215] = (isr_entry_d7);
		isr_handler_table[216] = (isr_entry_d8);
		isr_handler_table[217] = (isr_entry_d9);
		isr_handler_table[218] = (isr_entry_da);
		isr_handler_table[219] = (isr_entry_db);
		isr_handler_table[220] = (isr_entry_dc);
		isr_handler_table[221] = (isr_entry_dd);
		isr_handler_table[222] = (isr_entry_de);
		isr_handler_table[223] = (isr_entry_df);
		isr_handler_table[224] = (isr_entry_e0);
		isr_handler_table[225] = (isr_entry_e1);
		isr_handler_table[226] = (isr_entry_e2);
		isr_handler_table[227] = (isr_entry_e3);
		isr_handler_table[228] = (isr_entry_e4);
		isr_handler_table[229] = (isr_entry_e5);
		isr_handler_table[230] = (isr_entry_e6);
		isr_handler_table[231] = (isr_entry_e7);
		isr_handler_table[232] = (isr_entry_e8);
		isr_handler_table[233] = (isr_entry_e9);
		isr_handler_table[234] = (isr_entry_ea);
		isr_handler_table[235] = (isr_entry_eb);
		isr_handler_table[236] = (isr_entry_ec);
		isr_handler_table[237] = (isr_entry_ed);
		isr_handler_table[238] = (isr_entry_ee);
		isr_handler_table[239] = (isr_entry_ef);
		isr_handler_table[240] = (isr_entry_f0);
		isr_handler_table[241] = (isr_entry_f1);
		isr_handler_table[242] = (isr_entry_f2);
		isr_handler_table[243] = (isr_entry_f3);
		isr_handler_table[244] = (isr_entry_f4);
		isr_handler_table[245] = (isr_entry_f5);
		isr_handler_table[246] = (isr_entry_f6);
		isr_handler_table[247] = (isr_entry_f7);
		isr_handler_table[248] = (isr_entry_f8);
		isr_handler_table[249] = (isr_entry_f9);
		isr_handler_table[250] = (isr_entry_fa);
		isr_handler_table[251] = (isr_entry_fb);
		isr_handler_table[252] = (isr_entry_fc);
		isr_handler_table[253] = (isr_entry_fd);
		isr_handler_table[254] = (isr_entry_fe);
		isr_handler_table[255] = (isr_entry_ff);
}

//{
//    (ADDRESS) isr_entry_fa,
//    (ADDRESS) isr_entry_fb,
//    (ADDRESS) isr_entry_fc,
//    (ADDRESS) isr_entry_fd,
//    (ADDRESS) isr_entry_fe,
//    (ADDRESS) isr_entry_ff
//};
//
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

