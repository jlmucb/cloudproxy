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



//  This code is assumed to be running in 32-bit mode,
//  but configure IDT for 64-bit mode.
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

#if 0 // not used
static void init_isr_handler_table() {
    isr_handler_table[0] = (ADDRESS)(isr_entry_00);
    isr_handler_table[1] = (ADDRESS)(isr_entry_01);
    isr_handler_table[2] = (ADDRESS)(isr_entry_02);
    isr_handler_table[3] = (ADDRESS)(isr_entry_03);
    isr_handler_table[4] = (ADDRESS)(isr_entry_04);
    isr_handler_table[5] = (ADDRESS)(isr_entry_05);
    isr_handler_table[6] = (ADDRESS)(isr_entry_06);
    isr_handler_table[7] = (ADDRESS)(isr_entry_07);
    isr_handler_table[8] = (ADDRESS)(isr_entry_08);
    isr_handler_table[9] = (ADDRESS)(isr_entry_09);
    isr_handler_table[10] = (ADDRESS)(isr_entry_0a);
    isr_handler_table[11] = (ADDRESS)(isr_entry_0b);
    isr_handler_table[12] = (ADDRESS)(isr_entry_0c);
    isr_handler_table[13] = (ADDRESS)(isr_entry_0d);
    isr_handler_table[14] = (ADDRESS)(isr_entry_0e);
    isr_handler_table[15] = (ADDRESS)(isr_entry_0f);
    isr_handler_table[16] = (ADDRESS)(isr_entry_10);
    isr_handler_table[17] = (ADDRESS)(isr_entry_11);
    isr_handler_table[18] = (ADDRESS)(isr_entry_12);
    isr_handler_table[19] = (ADDRESS)(isr_entry_13);
    isr_handler_table[20] = (ADDRESS)(isr_entry_14);
    isr_handler_table[21] = (ADDRESS)(isr_entry_15);
    isr_handler_table[22] = (ADDRESS)(isr_entry_16);
    isr_handler_table[23] = (ADDRESS)(isr_entry_17);
    isr_handler_table[24] = (ADDRESS)(isr_entry_18);
    isr_handler_table[25] = (ADDRESS)(isr_entry_19);
    isr_handler_table[26] = (ADDRESS)(isr_entry_1a);
    isr_handler_table[27] = (ADDRESS)(isr_entry_1b);
    isr_handler_table[28] = (ADDRESS)(isr_entry_1c);
    isr_handler_table[29] = (ADDRESS)(isr_entry_1d);
    isr_handler_table[30] = (ADDRESS)(isr_entry_1e);
    isr_handler_table[31] = (ADDRESS)(isr_entry_1f);
    isr_handler_table[32] = (ADDRESS)(isr_entry_20);
    isr_handler_table[33] = (ADDRESS)(isr_entry_21);
    isr_handler_table[34] = (ADDRESS)(isr_entry_22);
    isr_handler_table[35] = (ADDRESS)(isr_entry_23);
    isr_handler_table[36] = (ADDRESS)(isr_entry_24);
    isr_handler_table[37] = (ADDRESS)(isr_entry_25);
    isr_handler_table[38] = (ADDRESS)(isr_entry_26);
    isr_handler_table[39] = (ADDRESS)(isr_entry_27);
    isr_handler_table[40] = (ADDRESS)(isr_entry_28);
    isr_handler_table[41] = (ADDRESS)(isr_entry_29);
    isr_handler_table[42] = (ADDRESS)(isr_entry_2a);
    isr_handler_table[43] = (ADDRESS)(isr_entry_2b);
    isr_handler_table[44] = (ADDRESS)(isr_entry_2c);
    isr_handler_table[45] = (ADDRESS)(isr_entry_2d);
    isr_handler_table[46] = (ADDRESS)(isr_entry_2e);
    isr_handler_table[47] = (ADDRESS)(isr_entry_2f);
    isr_handler_table[48] = (ADDRESS)(isr_entry_30);
    isr_handler_table[49] = (ADDRESS)(isr_entry_31);
    isr_handler_table[50] = (ADDRESS)(isr_entry_32);
    isr_handler_table[51] = (ADDRESS)(isr_entry_33);
    isr_handler_table[52] = (ADDRESS)(isr_entry_34);
    isr_handler_table[53] = (ADDRESS)(isr_entry_35);
    isr_handler_table[54] = (ADDRESS)(isr_entry_36);
    isr_handler_table[55] = (ADDRESS)(isr_entry_37);
    isr_handler_table[56] = (ADDRESS)(isr_entry_38);
    isr_handler_table[57] = (ADDRESS)(isr_entry_39);
    isr_handler_table[58] = (ADDRESS)(isr_entry_3a);
    isr_handler_table[59] = (ADDRESS)(isr_entry_3b);
    isr_handler_table[60] = (ADDRESS)(isr_entry_3c);
    isr_handler_table[61] = (ADDRESS)(isr_entry_3d);
    isr_handler_table[62] = (ADDRESS)(isr_entry_3e);
    isr_handler_table[63] = (ADDRESS)(isr_entry_3f);
    isr_handler_table[64] = (ADDRESS)(isr_entry_40);
    isr_handler_table[65] = (ADDRESS)(isr_entry_41);
    isr_handler_table[66] = (ADDRESS)(isr_entry_42);
    isr_handler_table[67] = (ADDRESS)(isr_entry_43);
    isr_handler_table[68] = (ADDRESS)(isr_entry_44);
    isr_handler_table[69] = (ADDRESS)(isr_entry_45);
    isr_handler_table[70] = (ADDRESS)(isr_entry_46);
    isr_handler_table[71] = (ADDRESS)(isr_entry_47);
    isr_handler_table[72] = (ADDRESS)(isr_entry_48);
    isr_handler_table[73] = (ADDRESS)(isr_entry_49);
    isr_handler_table[74] = (ADDRESS)(isr_entry_4a);
    isr_handler_table[75] = (ADDRESS)(isr_entry_4b);
    isr_handler_table[76] = (ADDRESS)(isr_entry_4c);
    isr_handler_table[77] = (ADDRESS)(isr_entry_4d);
    isr_handler_table[78] = (ADDRESS)(isr_entry_4e);
    isr_handler_table[79] = (ADDRESS)(isr_entry_4f);
    isr_handler_table[80] = (ADDRESS)(isr_entry_50);
    isr_handler_table[81] = (ADDRESS)(isr_entry_51);
    isr_handler_table[82] = (ADDRESS)(isr_entry_52);
    isr_handler_table[83] = (ADDRESS)(isr_entry_53);
    isr_handler_table[84] = (ADDRESS)(isr_entry_54);
    isr_handler_table[85] = (ADDRESS)(isr_entry_55);
    isr_handler_table[86] = (ADDRESS)(isr_entry_56);
    isr_handler_table[87] = (ADDRESS)(isr_entry_57);
    isr_handler_table[88] = (ADDRESS)(isr_entry_58);
    isr_handler_table[89] = (ADDRESS)(isr_entry_59);
    isr_handler_table[90] = (ADDRESS)(isr_entry_5a);
    isr_handler_table[91] = (ADDRESS)(isr_entry_5b);
    isr_handler_table[92] = (ADDRESS)(isr_entry_5c);
    isr_handler_table[93] = (ADDRESS)(isr_entry_5d);
    isr_handler_table[94] = (ADDRESS)(isr_entry_5e);
    isr_handler_table[95] = (ADDRESS)(isr_entry_5f);
    isr_handler_table[96] = (ADDRESS)(isr_entry_60);
    isr_handler_table[97] = (ADDRESS)(isr_entry_61);
    isr_handler_table[98] = (ADDRESS)(isr_entry_62);
    isr_handler_table[99] = (ADDRESS)(isr_entry_63);
    isr_handler_table[100] = (ADDRESS)(isr_entry_64);
    isr_handler_table[101] = (ADDRESS)(isr_entry_65);
    isr_handler_table[102] = (ADDRESS)(isr_entry_66);
    isr_handler_table[103] = (ADDRESS)(isr_entry_67);
    isr_handler_table[104] = (ADDRESS)(isr_entry_68);
    isr_handler_table[105] = (ADDRESS)(isr_entry_69);
    isr_handler_table[106] = (ADDRESS)(isr_entry_6a);
    isr_handler_table[107] = (ADDRESS)(isr_entry_6b);
    isr_handler_table[108] = (ADDRESS)(isr_entry_6c);
    isr_handler_table[109] = (ADDRESS)(isr_entry_6d);
    isr_handler_table[110] = (ADDRESS)(isr_entry_6e);
    isr_handler_table[111] = (ADDRESS)(isr_entry_6f);
    isr_handler_table[112] = (ADDRESS)(isr_entry_70);
    isr_handler_table[113] = (ADDRESS)(isr_entry_71);
    isr_handler_table[114] = (ADDRESS)(isr_entry_72);
    isr_handler_table[115] = (ADDRESS)(isr_entry_73);
    isr_handler_table[116] = (ADDRESS)(isr_entry_74);
    isr_handler_table[117] = (ADDRESS)(isr_entry_75);
    isr_handler_table[118] = (ADDRESS)(isr_entry_76);
    isr_handler_table[119] = (ADDRESS)(isr_entry_77);
    isr_handler_table[120] = (ADDRESS)(isr_entry_78);
    isr_handler_table[121] = (ADDRESS)(isr_entry_79);
    isr_handler_table[122] = (ADDRESS)(isr_entry_7a);
    isr_handler_table[123] = (ADDRESS)(isr_entry_7b);
    isr_handler_table[124] = (ADDRESS)(isr_entry_7c);
    isr_handler_table[125] = (ADDRESS)(isr_entry_7d);
    isr_handler_table[126] = (ADDRESS)(isr_entry_7e);
    isr_handler_table[127] = (ADDRESS)(isr_entry_7f);
    isr_handler_table[128] = (ADDRESS)(isr_entry_80);
    isr_handler_table[129] = (ADDRESS)(isr_entry_81);
    isr_handler_table[130] = (ADDRESS)(isr_entry_82);
    isr_handler_table[131] = (ADDRESS)(isr_entry_83);
    isr_handler_table[132] = (ADDRESS)(isr_entry_84);
    isr_handler_table[133] = (ADDRESS)(isr_entry_85);
    isr_handler_table[134] = (ADDRESS)(isr_entry_86);
    isr_handler_table[135] = (ADDRESS)(isr_entry_87);
    isr_handler_table[136] = (ADDRESS)(isr_entry_88);
    isr_handler_table[137] = (ADDRESS)(isr_entry_89);
    isr_handler_table[138] = (ADDRESS)(isr_entry_8a);
    isr_handler_table[139] = (ADDRESS)(isr_entry_8b);
    isr_handler_table[140] = (ADDRESS)(isr_entry_8c);
    isr_handler_table[141] = (ADDRESS)(isr_entry_8d);
    isr_handler_table[142] = (ADDRESS)(isr_entry_8e);
    isr_handler_table[143] = (ADDRESS)(isr_entry_8f);
    isr_handler_table[144] = (ADDRESS)(isr_entry_90);
    isr_handler_table[145] = (ADDRESS)(isr_entry_91);
    isr_handler_table[146] = (ADDRESS)(isr_entry_92);
    isr_handler_table[147] = (ADDRESS)(isr_entry_93);
    isr_handler_table[148] = (ADDRESS)(isr_entry_94);
    isr_handler_table[149] = (ADDRESS)(isr_entry_95);
    isr_handler_table[150] = (ADDRESS)(isr_entry_96);
    isr_handler_table[151] = (ADDRESS)(isr_entry_97);
    isr_handler_table[152] = (ADDRESS)(isr_entry_98);
    isr_handler_table[153] = (ADDRESS)(isr_entry_99);
    isr_handler_table[154] = (ADDRESS)(isr_entry_9a);
    isr_handler_table[155] = (ADDRESS)(isr_entry_9b);
    isr_handler_table[156] = (ADDRESS)(isr_entry_9c);
    isr_handler_table[157] = (ADDRESS)(isr_entry_9d);
    isr_handler_table[158] = (ADDRESS)(isr_entry_9e);
    isr_handler_table[159] = (ADDRESS)(isr_entry_9f);
    isr_handler_table[160] = (ADDRESS)(isr_entry_a0);
    isr_handler_table[161] = (ADDRESS)(isr_entry_a1);
    isr_handler_table[162] = (ADDRESS)(isr_entry_a2);
    isr_handler_table[163] = (ADDRESS)(isr_entry_a3);
    isr_handler_table[164] = (ADDRESS)(isr_entry_a4);
    isr_handler_table[165] = (ADDRESS)(isr_entry_a5);
    isr_handler_table[166] = (ADDRESS)(isr_entry_a6);
    isr_handler_table[167] = (ADDRESS)(isr_entry_a7);
    isr_handler_table[168] = (ADDRESS)(isr_entry_a8);
    isr_handler_table[169] = (ADDRESS)(isr_entry_a9);
    isr_handler_table[170] = (ADDRESS)(isr_entry_aa);
    isr_handler_table[171] = (ADDRESS)(isr_entry_ab);
    isr_handler_table[172] = (ADDRESS)(isr_entry_ac);
    isr_handler_table[173] = (ADDRESS)(isr_entry_ad);
    isr_handler_table[174] = (ADDRESS)(isr_entry_ae);
    isr_handler_table[175] = (ADDRESS)(isr_entry_af);
    isr_handler_table[176] = (ADDRESS)(isr_entry_b0);
    isr_handler_table[177] = (ADDRESS)(isr_entry_b1);
    isr_handler_table[178] = (ADDRESS)(isr_entry_b2);
    isr_handler_table[179] = (ADDRESS)(isr_entry_b3);
    isr_handler_table[180] = (ADDRESS)(isr_entry_b4);
    isr_handler_table[181] = (ADDRESS)(isr_entry_b5);
    isr_handler_table[182] = (ADDRESS)(isr_entry_b6);
    isr_handler_table[183] = (ADDRESS)(isr_entry_b7);
    isr_handler_table[184] = (ADDRESS)(isr_entry_b8);
    isr_handler_table[185] = (ADDRESS)(isr_entry_b9);
    isr_handler_table[186] = (ADDRESS)(isr_entry_ba);
    isr_handler_table[187] = (ADDRESS)(isr_entry_bb);
    isr_handler_table[188] = (ADDRESS)(isr_entry_bc);
    isr_handler_table[189] = (ADDRESS)(isr_entry_bd);
    isr_handler_table[190] = (ADDRESS)(isr_entry_be);
    isr_handler_table[191] = (ADDRESS)(isr_entry_bf);
    isr_handler_table[192] = (ADDRESS)(isr_entry_c0);
    isr_handler_table[193] = (ADDRESS)(isr_entry_c1);
    isr_handler_table[194] = (ADDRESS)(isr_entry_c2);
    isr_handler_table[195] = (ADDRESS)(isr_entry_c3);
    isr_handler_table[196] = (ADDRESS)(isr_entry_c4);
    isr_handler_table[197] = (ADDRESS)(isr_entry_c5);
    isr_handler_table[198] = (ADDRESS)(isr_entry_c6);
    isr_handler_table[199] = (ADDRESS)(isr_entry_c7);
    isr_handler_table[200] = (ADDRESS)(isr_entry_c8);
    isr_handler_table[201] = (ADDRESS)(isr_entry_c9);
    isr_handler_table[202] = (ADDRESS)(isr_entry_ca);
    isr_handler_table[203] = (ADDRESS)(isr_entry_cb);
    isr_handler_table[204] = (ADDRESS)(isr_entry_cc);
    isr_handler_table[205] = (ADDRESS)(isr_entry_cd);
    isr_handler_table[206] = (ADDRESS)(isr_entry_ce);
    isr_handler_table[207] = (ADDRESS)(isr_entry_cf);
    isr_handler_table[208] = (ADDRESS)(isr_entry_d0);
    isr_handler_table[209] = (ADDRESS)(isr_entry_d1);
    isr_handler_table[210] = (ADDRESS)(isr_entry_d2);
    isr_handler_table[211] = (ADDRESS)(isr_entry_d3);
    isr_handler_table[212] = (ADDRESS)(isr_entry_d4);
    isr_handler_table[213] = (ADDRESS)(isr_entry_d5);
    isr_handler_table[214] = (ADDRESS)(isr_entry_d6);
    isr_handler_table[215] = (ADDRESS)(isr_entry_d7);
    isr_handler_table[216] = (ADDRESS)(isr_entry_d8);
    isr_handler_table[217] = (ADDRESS)(isr_entry_d9);
    isr_handler_table[218] = (ADDRESS)(isr_entry_da);
    isr_handler_table[219] = (ADDRESS)(isr_entry_db);
    isr_handler_table[220] = (ADDRESS)(isr_entry_dc);
    isr_handler_table[221] = (ADDRESS)(isr_entry_dd);
    isr_handler_table[222] = (ADDRESS)(isr_entry_de);
    isr_handler_table[223] = (ADDRESS)(isr_entry_df);
    isr_handler_table[224] = (ADDRESS)(isr_entry_e0);
    isr_handler_table[225] = (ADDRESS)(isr_entry_e1);
    isr_handler_table[226] = (ADDRESS)(isr_entry_e2);
    isr_handler_table[227] = (ADDRESS)(isr_entry_e3);
    isr_handler_table[228] = (ADDRESS)(isr_entry_e4);
    isr_handler_table[229] = (ADDRESS)(isr_entry_e5);
    isr_handler_table[230] = (ADDRESS)(isr_entry_e6);
    isr_handler_table[231] = (ADDRESS)(isr_entry_e7);
    isr_handler_table[232] = (ADDRESS)(isr_entry_e8);
    isr_handler_table[233] = (ADDRESS)(isr_entry_e9);
    isr_handler_table[234] = (ADDRESS)(isr_entry_ea);
    isr_handler_table[235] = (ADDRESS)(isr_entry_eb);
    isr_handler_table[236] = (ADDRESS)(isr_entry_ec);
    isr_handler_table[237] = (ADDRESS)(isr_entry_ed);
    isr_handler_table[238] = (ADDRESS)(isr_entry_ee);
    isr_handler_table[239] = (ADDRESS)(isr_entry_ef);
    isr_handler_table[240] = (ADDRESS)(isr_entry_f0);
    isr_handler_table[241] = (ADDRESS)(isr_entry_f1);
    isr_handler_table[242] = (ADDRESS)(isr_entry_f2);
    isr_handler_table[243] = (ADDRESS)(isr_entry_f3);
    isr_handler_table[244] = (ADDRESS)(isr_entry_f4);
    isr_handler_table[245] = (ADDRESS)(isr_entry_f5);
    isr_handler_table[246] = (ADDRESS)(isr_entry_f6);
    isr_handler_table[247] = (ADDRESS)(isr_entry_f7);
    isr_handler_table[248] = (ADDRESS)(isr_entry_f8);
    isr_handler_table[249] = (ADDRESS)(isr_entry_f9);
    isr_handler_table[250] = (ADDRESS)(isr_entry_fa);
    isr_handler_table[251] = (ADDRESS)(isr_entry_fb);
    isr_handler_table[252] = (ADDRESS)(isr_entry_fc);
    isr_handler_table[253] = (ADDRESS)(isr_entry_fd);
    isr_handler_table[254] = (ADDRESS)(isr_entry_fe);
    isr_handler_table[255] = (ADDRESS)(isr_entry_ff);
}
#endif
//    (ADDRESS) isr_entry_fa,
//    (ADDRESS) isr_entry_fb,
//    (ADDRESS) isr_entry_fc,
//    (ADDRESS) isr_entry_fd,
//    (ADDRESS) isr_entry_fe,
//    (ADDRESS) isr_entry_ff


// FUNCTION     : hw_idt_register_handler()
// PURPOSE      : Register interrupt handler at spec. vector
// ARGUMENTS    : UINT8 vector_id
//              : ADDRESS isr_handler_address - address of function
void hw_idt_register_handler( VECTOR_ID vector_id, ADDRESS isr_handler_address)
{
    // fill IDT entries 
    idt[vector_id].offset_0_15    = (UINT32) GET_2BYTE(isr_handler_address, 0);
    idt[vector_id].offset_15_31   = (UINT32) GET_2BYTE(isr_handler_address, 1);
    idt[vector_id].offset_32_63   = (UINT32) GET_4BYTE(isr_handler_address, 1);
    idt[vector_id].ist            = vector_id < NELEMENTS(ist_used) ? ist_used[vector_id] : 0;
    idt[vector_id].gate_type      = IA32E_IDT_GATE_TYPE_INTERRUPT_GATE;
    idt[vector_id].dpl            = 0;
    idt[vector_id].present        = 1;
    idt[vector_id].css            = CODE64_GDT_ENTRY_OFFSET;
}


// FUNCTION     : hw_idt_setup()
// PURPOSE      : Build and populate IDT table, used by all CPUs
void hw_idt_setup(void)
{
    unsigned vector_id;

    for (vector_id = 0; vector_id < IDT_VECTOR_COUNT; ++vector_id) {
        hw_idt_register_handler((VECTOR_ID) vector_id, isr_handler_table[vector_id]);
    }
}


// FUNCTION     : hw_idt_load()
// PURPOSE      : Load IDT descriptor into IDTR of CPU, currently excuted
void hw_idt_load(void)
{
    EM64T_IDT_DESCRIPTOR idt_desc;

    idt_desc.base = (ADDRESS) idt;
    idt_desc.limit = sizeof(idt) - 1;
    hw_lidt((void*)&idt_desc);
}


// FUNCTION     : idt_get_extra_stacks_required()
// PURPOSE      : Returns the number of extra stacks required by ISRs
// RETURNS      : number between 0..7
// NOTES        : per CPU
UINT8 idt_get_extra_stacks_required(void)
{
    return 6;   // the number of no-zero elements in array <ist_used>
}

