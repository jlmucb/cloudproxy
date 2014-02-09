/*
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
 */

#include "vmm_defs.h"

/*
UINT8 hw_isr (void)
// ISR handler. Pushes hardcoded CPU ID onto stack and jumps to vector routine
// Stack offsets on entry:
// eax register will contain result         Bits 7-0: #Physical Address Bits
//                               Bits 15-8: #Virtual Address Bits
{
    UINT8   result;
    asm volatile(
.macro isr_entry_macro vector
        push vector
        jmp  hw_isr_c_wrapper
.endm
    : 
    : [addr] "m" (addr), [extension] "m" (extension), [hint] "m" (hint)
    :"%rax", "%rcx", "%rdx", "%r8");
}
*/
#define FAULT_CLASS 2
extern UINT16 exception_class;
void hw_isr_c_wrapper(unsigned long int index)
{
	asm volatile(
		"push %%rax \n\t" //     # offset 08
		"push %%rbx \n\t" //    # offset 00
//        # If an exception fault is detected, save the GPRs
//        # for the assertion debug buffer
		"movq %0, %%rbx \n\t" // qword ptr [%rsp+$0x10h]    # vector number
//        # all exception faults have vector number up to 19
		"cmpq $19, %%rbx \n\t"
		"jg 1f \n\t"
// # check the exception type
		"lea exception_class, %%rax \n\t" 
//RNB: the addl/subl instructions are to derefernce the (%rbx + %rax),
// and then restore the %ebx to original location
		"addq %%rax, %%rbx \n\t"
		"movzbl (%%rbx),  %%ebx \n\t"
		"subq %%rax, %%rbx \n\t"
		"cmpl %%ebx, 2 \n\t"
		"jne 1f\n\t"
//        # Save GPRs
		"movq 0x08(%%rsp), %%rax \n\t" //this is rax
		"movq g_exception_gpr, %%rbx \n\t"
		"movq %%rax, (%%rbx) \n\t"
		"movq (%%rsp), %%rax \n\t"  //          # this is rbx
		"movq %%rax, 8(%%rbx) \n\t"
//	now save all other GP registers except RIP,RSP,RFLAGS
		"movq %%rcx, 16(%%rbx) \n\t"
		"movq %%rdx, 24(%%rbx) \n\t"
		"movq %%rdi, 32(%%rbx) \n\t"
		"movq %%rsi, 40(%%rbx) \n\t"
		"movq %%rbp, 48(%%rbx) \n\t"
		"movq %%r8, 64(%%rbx) \n\t"
		"movq %%r9, 72(%%rbx) \n\t"
		"movq %%r10, 80(%%rbx) \n\t"
		"movq %%r11, 88(%%rbx) \n\t"
		"movq %%r12, 96(%%rbx) \n\t"
		"movq %%r13, 104(%%rbx) \n\t"
		"movq %%r14, 112(%%rbx) \n\t"
		"movq %%r15, 120(%%rbx) \n\t"
		"1: \n\t"
		"pop %%rbx \n\t"
		"pop %%rax \n\t"
/*
        #; save context and prepare stack for C-function
        #; at this point stack contains
        #;..................................
        #; [       SS         ]
        #; [       RSP        ]
        #; [      RFLAGS      ]
        #; [       CS         ]
        #; [       RIP        ] <= here RSP should point prior iret
        #; [[   errcode      ]]    optionally
        #; [    vector ID     ] <= RSP
*/
		"push %%rcx \n\t"	//save RCX which used for argument passing
		"movq %%rsp, %%rcx \n\t"
		"add $8, %%rcx \n\t" //now RCX points to the location of vector ID
		"push %%rdx \n\t"
		"push %%rax \n\t"
		"push %%r8 \n\t"
		"push %%r9 \n\t"
		"push %%r10 \n\t"
		"push %%r11 \n\t"
		"push %%r15 \n\t"  //used for saving unaligned stack
		"movq %%rsp, %%r15 \n\t" //# save RSP prior alignment
		"and $0x0FFFFFFFFFFFFFFF0, %%rsp \n\t" //# align on 16 bytes boundary
		"sub $0x020, %%rsp \n\t" //      # prepare space for C-function
		"call isr_c_handler \n\t"
		"movq %%r15, %%rsp \n\t" //# restore unaligned RSP
		"pop %%r15 \n\t"
		"pop %%r11 \n\t"
		"pop %%r10 \n\t"
		"pop %%r9 \n\t"
		"pop %%r8 \n\t"
		"pop %%rax \n\t"
		"pop %%rdx \n\t"
		"pop %%rcx \n\t"
		"pop %%rsp \n\t"	//isr_c_handler replaces vector ID with pointer to the
//                                # RIP. Just pop the pointer to the RIP into RSP.
		"iretq"
		:[index] "+r" (index)
		://[index] "r" (index)
		:
	);
}


//the functions below instantiate isr_entry_macro for 256 vectors (IDT entries)

void isr_entry_00() {
	//isr_entry_macro $0x000
	int arg = 0x000;
	hw_isr_c_wrapper(arg);
}

void isr_entry_01() {
	int arg = 0x001;
	hw_isr_c_wrapper(arg);
}

void isr_entry_02() {
	int arg = 0x002;
	hw_isr_c_wrapper(arg);
}

void isr_entry_03() {
	int arg = 0x003;
	hw_isr_c_wrapper(arg);
}

void isr_entry_04() {
	int arg = 0x004;
	hw_isr_c_wrapper(arg);
}

void isr_entry_05() {
	int arg = 0x005;
	hw_isr_c_wrapper(arg);
}

void isr_entry_06() {
	int arg = 0x006;
	hw_isr_c_wrapper(arg);
}

void isr_entry_07() {
	int arg = 0x007;
	hw_isr_c_wrapper(arg);
}

void isr_entry_08() {
	int arg = 0x008;
	hw_isr_c_wrapper(arg);
}

void isr_entry_09() {
	int arg = 0x009;
	hw_isr_c_wrapper(arg);
}

void isr_entry_0a() {
	int arg = 0x00a;
	hw_isr_c_wrapper(arg);
}

void isr_entry_0b() {
	int arg = 0x00b;
	hw_isr_c_wrapper(arg);
}

void isr_entry_0c() {
	int arg = 0x00c;
	hw_isr_c_wrapper(arg);
}

void isr_entry_0d() {
	int arg = 0x00d;
	hw_isr_c_wrapper(arg);
}

void isr_entry_0e() {
	int arg = 0x00e;
	hw_isr_c_wrapper(arg);
}

void isr_entry_0f() {
	int arg = 0x00f;
	hw_isr_c_wrapper(arg);
}

void isr_entry_10() {
	int arg = 0x010;
	hw_isr_c_wrapper(arg);
}

void isr_entry_11() {
	int arg = 0x011;
	hw_isr_c_wrapper(arg);
}

void isr_entry_12() {
	int arg = 0x012;
	hw_isr_c_wrapper(arg);
}

void isr_entry_13() {
	int arg = 0x013;
	hw_isr_c_wrapper(arg);
}

void isr_entry_14() {
	int arg = 0x014;
	hw_isr_c_wrapper(arg);
}

void isr_entry_15() {
	int arg = 0x015;
	hw_isr_c_wrapper(arg);
}

void isr_entry_16() {
	int arg = 0x016;
	hw_isr_c_wrapper(arg);
}

void isr_entry_17() {
	int arg = 0x017;
	hw_isr_c_wrapper(arg);
}

void isr_entry_18() {
	int arg = 0x018;
	hw_isr_c_wrapper(arg);
}

void isr_entry_19() {
	int arg = 0x019;
	hw_isr_c_wrapper(arg);
}

void isr_entry_1a() {
	int arg = 0x01a;
	hw_isr_c_wrapper(arg);
}

void isr_entry_1b() {
	int arg = 0x01b;
	hw_isr_c_wrapper(arg);
}

void isr_entry_1c() {
	int arg = 0x01c;
	hw_isr_c_wrapper(arg);
}

void isr_entry_1d() {
	int arg = 0x01d;
	hw_isr_c_wrapper(arg);
}

void isr_entry_1e() {
	int arg = 0x01e;
	hw_isr_c_wrapper(arg);
}

void isr_entry_1f() {
	int arg = 0x01f;
	hw_isr_c_wrapper(arg);
}

void isr_entry_20() {
	int arg = 0x020;
	hw_isr_c_wrapper(arg);
}

void isr_entry_21() {
	int arg = 0x021;
	hw_isr_c_wrapper(arg);
}

void isr_entry_22() {
	int arg = 0x022;
	hw_isr_c_wrapper(arg);
}

void isr_entry_23() {
	int arg = 0x023;
	hw_isr_c_wrapper(arg);
}

void isr_entry_24() {
	int arg = 0x024;
	hw_isr_c_wrapper(arg);
}

void isr_entry_25() {
	int arg = 0x025;
	hw_isr_c_wrapper(arg);
}

void isr_entry_26() {
	int arg = 0x026;
	hw_isr_c_wrapper(arg);
}

void isr_entry_27() {
	int arg = 0x027;
	hw_isr_c_wrapper(arg);
}

void isr_entry_28() {
	int arg = 0x028;
	hw_isr_c_wrapper(arg);
}

void isr_entry_29() {
	int arg = 0x029;
	hw_isr_c_wrapper(arg);
}

void isr_entry_2a() {
	int arg = 0x02a;
	hw_isr_c_wrapper(arg);
}

void isr_entry_2b() {
	int arg = 0x02b;
	hw_isr_c_wrapper(arg);
}

void isr_entry_2c() {
	int arg = 0x02c;
	hw_isr_c_wrapper(arg);
}

void isr_entry_2d() {
	int arg = 0x02d;
	hw_isr_c_wrapper(arg);
}

void isr_entry_2e() {
	int arg = 0x02e;
	hw_isr_c_wrapper(arg);
}

void isr_entry_2f() {
	int arg = 0x02f;
	hw_isr_c_wrapper(arg);
}

void isr_entry_30() {
	int arg = 0x030;
	hw_isr_c_wrapper(arg);
}

void isr_entry_31() {
	int arg = 0x031;
	hw_isr_c_wrapper(arg);
}

void isr_entry_32() {
	int arg = 0x032;
	hw_isr_c_wrapper(arg);
}

void isr_entry_33() {
	int arg = 0x033;
	hw_isr_c_wrapper(arg);
}

void isr_entry_34() {
	int arg = 0x034;
	hw_isr_c_wrapper(arg);
}

void isr_entry_35() {
	int arg = 0x035;
	hw_isr_c_wrapper(arg);
}

void isr_entry_36() {
	int arg = 0x036;
	hw_isr_c_wrapper(arg);
}

void isr_entry_37() {
	int arg = 0x037;
	hw_isr_c_wrapper(arg);
}

void isr_entry_38() {
	int arg = 0x038;
	hw_isr_c_wrapper(arg);
}

void isr_entry_39() {
	int arg = 0x039;
	hw_isr_c_wrapper(arg);
}

void isr_entry_3a() {
	int arg = 0x03a;
	hw_isr_c_wrapper(arg);
}

void isr_entry_3b() {
	int arg = 0x03b;
	hw_isr_c_wrapper(arg);
}

void isr_entry_3c() {
	int arg = 0x03c;
	hw_isr_c_wrapper(arg);
}

void isr_entry_3d() {
	int arg = 0x03d;
	hw_isr_c_wrapper(arg);
}

void isr_entry_3e() {
	int arg = 0x03e;
	hw_isr_c_wrapper(arg);
}

void isr_entry_3f() {
	int arg = 0x03f;
	hw_isr_c_wrapper(arg);
}

void isr_entry_40() {
	int arg = 0x040;
	hw_isr_c_wrapper(arg);
}

void isr_entry_41() {
	int arg = 0x041;
	hw_isr_c_wrapper(arg);
}

void isr_entry_42() {
	int arg = 0x042;
	hw_isr_c_wrapper(arg);
}

void isr_entry_43() {
	int arg = 0x043;
	hw_isr_c_wrapper(arg);
}

void isr_entry_44() {
	int arg = 0x044;
	hw_isr_c_wrapper(arg);
}

void isr_entry_45() {
	int arg = 0x045;
	hw_isr_c_wrapper(arg);
}

void isr_entry_46() {
	int arg = 0x046;
	hw_isr_c_wrapper(arg);
}

void isr_entry_47() {
	int arg = 0x047;
	hw_isr_c_wrapper(arg);
}

void isr_entry_48() {
	int arg = 0x048;
	hw_isr_c_wrapper(arg);
}

void isr_entry_49() {
	int arg = 0x049;
	hw_isr_c_wrapper(arg);
}

void isr_entry_4a() {
	int arg = 0x04a;
	hw_isr_c_wrapper(arg);
}

void isr_entry_4b() {
	int arg = 0x04b;
	hw_isr_c_wrapper(arg);
}

void isr_entry_4c() {
	int arg = 0x04c;
	hw_isr_c_wrapper(arg);
}

void isr_entry_4d() {
	int arg = 0x04d;
	hw_isr_c_wrapper(arg);
}

void isr_entry_4e() {
	int arg = 0x04e;
	hw_isr_c_wrapper(arg);
}

void isr_entry_4f() {
	int arg = 0x04f;
	hw_isr_c_wrapper(arg);
}

void isr_entry_50() {
	int arg = 0x050;
	hw_isr_c_wrapper(arg);
}

void isr_entry_51() {
	int arg = 0x051;
	hw_isr_c_wrapper(arg);
}

void isr_entry_52() {
	int arg = 0x052;
	hw_isr_c_wrapper(arg);
}

void isr_entry_53() {
	int arg = 0x053;
	hw_isr_c_wrapper(arg);
}

void isr_entry_54() {
	int arg = 0x054;
	hw_isr_c_wrapper(arg);
}

void isr_entry_55() {
	int arg = 0x055;
	hw_isr_c_wrapper(arg);
}

void isr_entry_56() {
	int arg = 0x056;
	hw_isr_c_wrapper(arg);
}

void isr_entry_57() {
	int arg = 0x057;
	hw_isr_c_wrapper(arg);
}

void isr_entry_58() {
	int arg = 0x058;
	hw_isr_c_wrapper(arg);
}

void isr_entry_59() {
	int arg = 0x059;
	hw_isr_c_wrapper(arg);
}

void isr_entry_5a() {
	int arg = 0x05a;
	hw_isr_c_wrapper(arg);
}

void isr_entry_5b() {
	int arg = 0x05b;
	hw_isr_c_wrapper(arg);
}

void isr_entry_5c() {
	int arg = 0x05c;
	hw_isr_c_wrapper(arg);
}

void isr_entry_5d() {
	int arg = 0x05d;
	hw_isr_c_wrapper(arg);
}

void isr_entry_5e() {
	int arg = 0x05e;
	hw_isr_c_wrapper(arg);
}

void isr_entry_5f() {
	int arg = 0x05f;
	hw_isr_c_wrapper(arg);
}

void isr_entry_60() {
	int arg = 0x060;
	hw_isr_c_wrapper(arg);
}

void isr_entry_61()  {
	int arg = 0x061;
	hw_isr_c_wrapper(arg);
}

void isr_entry_62()  {
	int arg = 0x062;
	hw_isr_c_wrapper(arg);
}

void isr_entry_63()  {
	int arg = 0x063;
	hw_isr_c_wrapper(arg);
}

void isr_entry_64()  {
	int arg = 0x064;
	hw_isr_c_wrapper(arg);
}

void isr_entry_65()  {
	int arg = 0x065;
	hw_isr_c_wrapper(arg);
}

void isr_entry_66()  {
	int arg = 0x066;
	hw_isr_c_wrapper(arg);
}

void isr_entry_67()  {
	int arg = 0x067;
	hw_isr_c_wrapper(arg);
}

void isr_entry_68()  {
	int arg = 0x068;
	hw_isr_c_wrapper(arg);
}

void isr_entry_69()  {
	int arg = 0x069;
	hw_isr_c_wrapper(arg);
}

void isr_entry_6a() {
	int arg = 0x06a;
	hw_isr_c_wrapper(arg);
}

void isr_entry_6b() {
	int arg = 0x06b;
	hw_isr_c_wrapper(arg);
}

void isr_entry_6c() {
	int arg = 0x06c;
	hw_isr_c_wrapper(arg);
}

void isr_entry_6d() {
	int arg = 0x06d;
	hw_isr_c_wrapper(arg);
}

void isr_entry_6e() {
	int arg = 0x06e;
	hw_isr_c_wrapper(arg);
}

void isr_entry_6f() {
	int arg = 0x06f;
	hw_isr_c_wrapper(arg);
}

void isr_entry_70()  {
	int arg = 0x070;
	hw_isr_c_wrapper(arg);
}

void isr_entry_71()  {
	int arg = 0x071;
	hw_isr_c_wrapper(arg);
}

void isr_entry_72()  {
	int arg = 0x072;
	hw_isr_c_wrapper(arg);
}

void isr_entry_73()  {
	int arg = 0x073;
	hw_isr_c_wrapper(arg);
}

void isr_entry_74()  {
	int arg = 0x074;
	hw_isr_c_wrapper(arg);
}

void isr_entry_75()  {
	int arg = 0x075;
	hw_isr_c_wrapper(arg);
}

void isr_entry_76()  {
	int arg = 0x076;
	hw_isr_c_wrapper(arg);
}

void isr_entry_77()  {
	int arg = 0x077;
	hw_isr_c_wrapper(arg);
}

void isr_entry_78()  {
	int arg = 0x078;
	hw_isr_c_wrapper(arg);
}

void isr_entry_79()  {
	int arg = 0x079;
	hw_isr_c_wrapper(arg);
}

void isr_entry_7a() {
	int arg = 0x07a;
	hw_isr_c_wrapper(arg);
}

void isr_entry_7b() {
	int arg = 0x07b;
	hw_isr_c_wrapper(arg);
}

void isr_entry_7c() {
	int arg = 0x07c;
	hw_isr_c_wrapper(arg);
}

void isr_entry_7d() {
	int arg = 0x07d;
	hw_isr_c_wrapper(arg);
}

void isr_entry_7e() {
	int arg = 0x07e;
	hw_isr_c_wrapper(arg);
}

void isr_entry_7f() {
	int arg = 0x07f;
	hw_isr_c_wrapper(arg);
}

void isr_entry_80()  {
	int arg = 0x080;
	hw_isr_c_wrapper(arg);
}

void isr_entry_81()  {
	int arg = 0x081;
	hw_isr_c_wrapper(arg);
}

void isr_entry_82()  {
	int arg = 0x082;
	hw_isr_c_wrapper(arg);
}

void isr_entry_83()  {
	int arg = 0x083;
	hw_isr_c_wrapper(arg);
}

void isr_entry_84()  {
	int arg = 0x084;
	hw_isr_c_wrapper(arg);
}

void isr_entry_85()  {
	int arg = 0x085;
	hw_isr_c_wrapper(arg);
}

void isr_entry_86()  {
	int arg = 0x086;
	hw_isr_c_wrapper(arg);
}

void isr_entry_87()  {
	int arg = 0x087;
	hw_isr_c_wrapper(arg);
}

void isr_entry_88()  {
	int arg = 0x088;
	hw_isr_c_wrapper(arg);
}

void isr_entry_89()  {
	int arg = 0x089;
	hw_isr_c_wrapper(arg);
}

void isr_entry_8a() {
	int arg = 0x08a;
	hw_isr_c_wrapper(arg);
}

void isr_entry_8b() {
	int arg = 0x08b;
	hw_isr_c_wrapper(arg);
}

void isr_entry_8c() {
	int arg = 0x08c;
	hw_isr_c_wrapper(arg);
}

void isr_entry_8d() {
	int arg = 0x08d;
	hw_isr_c_wrapper(arg);
}

void isr_entry_8e() {
	int arg = 0x08e;
	hw_isr_c_wrapper(arg);
}

void isr_entry_8f() {
	int arg = 0x08f;
	hw_isr_c_wrapper(arg);
}

void isr_entry_90()  {
	int arg = 0x090;
	hw_isr_c_wrapper(arg);
}

void isr_entry_91()  {
	int arg = 0x091;
	hw_isr_c_wrapper(arg);
}

void isr_entry_92()  {
	int arg = 0x092;
	hw_isr_c_wrapper(arg);
}

void isr_entry_93()  {
	int arg = 0x093;
	hw_isr_c_wrapper(arg);
}

void isr_entry_94()  {
	int arg = 0x094;
	hw_isr_c_wrapper(arg);
}

void isr_entry_95()  {
	int arg = 0x095;
	hw_isr_c_wrapper(arg);
}

void isr_entry_96()  {
	int arg = 0x096;
	hw_isr_c_wrapper(arg);
}

void isr_entry_97()  {
	int arg = 0x097;
	hw_isr_c_wrapper(arg);
}

void isr_entry_98()  {
	int arg = 0x098;
	hw_isr_c_wrapper(arg);
}

void isr_entry_99()  {
	int arg = 0x099;
	hw_isr_c_wrapper(arg);
}

void isr_entry_9a() {
	int arg = 0x09a;
	hw_isr_c_wrapper(arg);
}

void isr_entry_9b() {
	int arg = 0x09b;
	hw_isr_c_wrapper(arg);
}

void isr_entry_9c() {
	int arg = 0x09c;
	hw_isr_c_wrapper(arg);
}

void isr_entry_9d() {
	int arg = 0x09d;
	hw_isr_c_wrapper(arg);
}

void isr_entry_9e() {
	int arg = 0x09e;
	hw_isr_c_wrapper(arg);
}

void isr_entry_9f() {
	int arg = 0x09f;
	hw_isr_c_wrapper(arg);
}

void isr_entry_a0() {
	int arg = 0x0a0;
	hw_isr_c_wrapper(arg);
}

void isr_entry_a1() {
	int arg = 0x0a1;
	hw_isr_c_wrapper(arg);
}

void isr_entry_a2() {
	int arg = 0x0a2;
	hw_isr_c_wrapper(arg);
}

void isr_entry_a3() {
	int arg = 0x0a3;
	hw_isr_c_wrapper(arg);
}

void isr_entry_a4() {
	int arg = 0x0a4;
	hw_isr_c_wrapper(arg);
}

void isr_entry_a5() {
	int arg = 0x0a5;
	hw_isr_c_wrapper(arg);
}

void isr_entry_a6() {
	int arg = 0x0a6;
	hw_isr_c_wrapper(arg);
}

void isr_entry_a7() {
	int arg = 0x0a7;
	hw_isr_c_wrapper(arg);
}

void isr_entry_a8() {
	int arg = 0x0a8;
	hw_isr_c_wrapper(arg);
}

void isr_entry_a9() {
	int arg = 0x0a9;
	hw_isr_c_wrapper(arg);
}

void isr_entry_aa() {
	int arg = 0x0aa;
	hw_isr_c_wrapper(arg);
}

void isr_entry_ab() {
	int arg = 0x0ab;
	hw_isr_c_wrapper(arg);
}

void isr_entry_ac() {
	int arg = 0x0ac;
	hw_isr_c_wrapper(arg);
}

void isr_entry_ad() {
	int arg = 0x0ad;
	hw_isr_c_wrapper(arg);
}

void isr_entry_ae() {
	int arg = 0x0ae;
	hw_isr_c_wrapper(arg);
}

void isr_entry_af() {
	int arg = 0x0af;
	hw_isr_c_wrapper(arg);
}

void isr_entry_b0() {
	int arg = 0x0b0;
	hw_isr_c_wrapper(arg);
}

void isr_entry_b1() {
	int arg = 0x0b1;
	hw_isr_c_wrapper(arg);
}

void isr_entry_b2() {
	int arg = 0x0b2;
	hw_isr_c_wrapper(arg);
}

void isr_entry_b3() {
	int arg = 0x0b3;
	hw_isr_c_wrapper(arg);
}

void isr_entry_b4() {
	int arg = 0x0b4;
	hw_isr_c_wrapper(arg);
}

void isr_entry_b5() {
	int arg = 0x0b5;
	hw_isr_c_wrapper(arg);
}

void isr_entry_b6() {
	int arg = 0x0b6;
	hw_isr_c_wrapper(arg);
}

void isr_entry_b7() {
	int arg = 0x0b7;
	hw_isr_c_wrapper(arg);
}

void isr_entry_b8() {
	int arg = 0x0b8;
	hw_isr_c_wrapper(arg);
}

void isr_entry_b9() {
	int arg = 0x0b9;
	hw_isr_c_wrapper(arg);
}

void isr_entry_ba() {
	int arg = 0x0ba;
	hw_isr_c_wrapper(arg);
}

void isr_entry_bb() {
	int arg = 0x0bb;
	hw_isr_c_wrapper(arg);
}

void isr_entry_bc() {
	int arg = 0x0bc;
	hw_isr_c_wrapper(arg);
}

void isr_entry_bd() {
	int arg = 0x0bd;
	hw_isr_c_wrapper(arg);
}

void isr_entry_be() {
	int arg = 0x0be;
	hw_isr_c_wrapper(arg);
}

void isr_entry_bf() {
	int arg = 0x0bf;
	hw_isr_c_wrapper(arg);
}

void isr_entry_c0() {
	int arg = 0x0c0;
	hw_isr_c_wrapper(arg);
}

void isr_entry_c1() {
	int arg = 0x0c1;
	hw_isr_c_wrapper(arg);
}

void isr_entry_c2() {
	int arg = 0x0c2;
	hw_isr_c_wrapper(arg);
}

void isr_entry_c3()  {
	int arg = 0x0c3;
	hw_isr_c_wrapper(arg);
}

void isr_entry_c4() {
	int arg = 0x0c4;
	hw_isr_c_wrapper(arg);
}

void isr_entry_c5() {
	int arg = 0x0c5;
	hw_isr_c_wrapper(arg);
}

void isr_entry_c6() {
	int arg = 0x0c6;
	hw_isr_c_wrapper(arg);
}

void isr_entry_c7() {
	int arg = 0x0c7;
	hw_isr_c_wrapper(arg);
}

void isr_entry_c8() {
	int arg = 0x0c8;
	hw_isr_c_wrapper(arg);
}

void isr_entry_c9() {
	int arg = 0x0c9;
	hw_isr_c_wrapper(arg);
}

void isr_entry_ca() {
	int arg = 0x0ca;
	hw_isr_c_wrapper(arg);
}

void isr_entry_cb() {
	int arg = 0x0cb;
	hw_isr_c_wrapper(arg);
}

void isr_entry_cc() {
	int arg = 0x0cc;
	hw_isr_c_wrapper(arg);
}

void isr_entry_cd() {
	int arg = 0x0cd;
	hw_isr_c_wrapper(arg);
}

void isr_entry_ce() {
	int arg = 0x0ce;
	hw_isr_c_wrapper(arg);
}

void isr_entry_cf() {
	int arg = 0x0cf;
	hw_isr_c_wrapper(arg);
}

void isr_entry_d0() {
	int arg = 0x0d0;
	hw_isr_c_wrapper(arg);
}

void isr_entry_d1() {
	int arg = 0x0d1;
	hw_isr_c_wrapper(arg);
}

void isr_entry_d2() {
	int arg = 0x0d2;
	hw_isr_c_wrapper(arg);
}

void isr_entry_d3() {
	int arg = 0x0d3;
	hw_isr_c_wrapper(arg);
}

void isr_entry_d4() {
	int arg = 0x0d4;
	hw_isr_c_wrapper(arg);
}

void isr_entry_d5() {
	int arg = 0x0d5;
	hw_isr_c_wrapper(arg);
}

void isr_entry_d6() {
	int arg = 0x0d6;
	hw_isr_c_wrapper(arg);
}

void isr_entry_d7() {
	int arg = 0x0d7;
	hw_isr_c_wrapper(arg);
}

void isr_entry_d8() {
	int arg = 0x0d8;
	hw_isr_c_wrapper(arg);
}

void isr_entry_d9() {
	int arg = 0x0d9;
	hw_isr_c_wrapper(arg);
}

void isr_entry_da() {
	int arg = 0x0da;
	hw_isr_c_wrapper(arg);
}

void isr_entry_db() {
	int arg = 0x0db;
	hw_isr_c_wrapper(arg);
}

void isr_entry_dc() {
	int arg = 0x0dc;
	hw_isr_c_wrapper(arg);
}

void isr_entry_dd() {
	int arg = 0x0dd;
	hw_isr_c_wrapper(arg);
}

void isr_entry_de() {
	int arg = 0x0de;
	hw_isr_c_wrapper(arg);
}

void isr_entry_df() {
	int arg = 0x0df;
	hw_isr_c_wrapper(arg);
}

void isr_entry_e0() {
	int arg = 0x0e0;
	hw_isr_c_wrapper(arg);
}

void isr_entry_e1() {
	int arg = 0x0e1;
	hw_isr_c_wrapper(arg);
}

void isr_entry_e2() {
	int arg = 0x0e2;
	hw_isr_c_wrapper(arg);
}

void isr_entry_e3() {
	int arg = 0x0e3;
	hw_isr_c_wrapper(arg);
}

void isr_entry_e4() {
	int arg = 0x0e4;
	hw_isr_c_wrapper(arg);
}

void isr_entry_e5() {
	int arg = 0x0e5;
	hw_isr_c_wrapper(arg);
}

void isr_entry_e6() {
	int arg = 0x0e6;
	hw_isr_c_wrapper(arg);
}

void isr_entry_e7() {
	int arg = 0x0e7;
	hw_isr_c_wrapper(arg);
}

void isr_entry_e8() {
	int arg = 0x0e8;
	hw_isr_c_wrapper(arg);
}

void isr_entry_e9() {
	int arg = 0x0e9;
	hw_isr_c_wrapper(arg);
}

void isr_entry_ea() {
	int arg = 0x0ea;
	hw_isr_c_wrapper(arg);
}

void isr_entry_eb() {
	int arg = 0x0eb;
	hw_isr_c_wrapper(arg);
}

void isr_entry_ec() {
	int arg = 0x0ec;
	hw_isr_c_wrapper(arg);
}

void isr_entry_ed() {
	int arg = 0x0ed;
	hw_isr_c_wrapper(arg);
}

void isr_entry_ee() {
	int arg = 0x0ee;
	hw_isr_c_wrapper(arg);
}

void isr_entry_ef() {
	int arg = 0x0ef;
	hw_isr_c_wrapper(arg);
}

void isr_entry_f0() {
	int arg = 0x0f0;
	hw_isr_c_wrapper(arg);
}

void isr_entry_f1() {
	int arg = 0x0f1;
	hw_isr_c_wrapper(arg);
}

void isr_entry_f2() {
	int arg = 0x0f2;
	hw_isr_c_wrapper(arg);
}

void isr_entry_f3() {
	int arg = 0x0f3;
	hw_isr_c_wrapper(arg);
}

void isr_entry_f4() {
	int arg = 0x0f4;
	hw_isr_c_wrapper(arg);
}

void isr_entry_f5() {
	int arg = 0x0f5;
	hw_isr_c_wrapper(arg);
}

void isr_entry_f6() {
	int arg = 0x0f6;
	hw_isr_c_wrapper(arg);
}

void isr_entry_f7() {
	int arg = 0x0f7;
	hw_isr_c_wrapper(arg);
}

void isr_entry_f8() {
	int arg = 0x0f8;
	hw_isr_c_wrapper(arg);
}

void isr_entry_f9() {
	int arg = 0x0f9;
	hw_isr_c_wrapper(arg);
}

void isr_entry_fa() {
	int arg = 0x0fa;
	hw_isr_c_wrapper(arg);
}

void isr_entry_fb() {
	int arg = 0x0fb;
	hw_isr_c_wrapper(arg);
}

void isr_entry_fc() {
	int arg = 0x0fc;
	hw_isr_c_wrapper(arg);
}

void isr_entry_fd() {
	int arg = 0x0fd;
	hw_isr_c_wrapper(arg);
}

void isr_entry_fe() {
	int arg = 0x0fe;
	hw_isr_c_wrapper(arg);
}

void isr_entry_ff() {
	int arg = 0x0ff;
	hw_isr_c_wrapper(arg);
}
