//
//  File: aesni.cpp
//
//  This module contains the low-level AES encryption routines
//      using aesni.
//
//  Copyright (c) 2011, John Manferdelli.  All rights reserved.
//      Some portions derived (c) 2010, Intel Corporation
//
// Use, duplication and disclosure of this file and derived works of
// this file are subject to and licensed under the Apache License dated
// January, 2004, (the "License").  This License is contained in the
// top level directory originally provided with the CloudProxy Project.
// Your right to use or distribute this file, or derived works thereof,
// is subject to your being bound by those terms and your use indicates
// consent to those terms.
//
// If you distribute this file (or portions derived therefrom), you must
// include License in or with the file and, in the event you do not include
// the entire License in the file, the file must contain a reference
// to the location of the License.


#include "aesni.h"
#include "jlmTypes.h"


// ------------------------------------------------------------------------


#define  AESFEATUREOFFSET   25


void callcpuid(u32 arg, u32 out[4])
{
    u32     a1, a2, a3, a4;

    asm volatile(
        "\tmovl    %[arg], %%eax\n" \
        "\tcpuid   \n" \
        "\tmovl    %%eax, %[a1]\n" \
        "\tmovl    %%ebx, %[a2]\n" \
        "\tmovl    %%ecx, %[a3]\n" \
        "\tmovl    %%edx, %[a4]\n" \
        : [a1] "=m"(a1), [a2] "=m"(a2), [a3] "=m"(a3), [a4] "=m"(a4)
        : [arg] "m" (arg)
        : "%eax", "%ebx", "%ecx", "%edx");

        out[0]= a1;
        out[1]= a2;
        out[2]= a3;
        out[3]= a4;
}


void inline genAES128EncRoundKeys(byte* pKey, byte* pExpandedKey)
{
    //  rdi --- pKey
    //  rsi --- pExpandedKey
    asm volatile(
        "\tjmp                  2f\n"\
    
        "1: \n"\
        "\tpshufd              $255, %%xmm2, %%xmm2\n"\
        "\tmovdqa              %%xmm1, %%xmm3 \n"\
        "\tpslldq              $4, %%xmm3 \n"\
        "\tpxor                %%xmm3, %%xmm1 \n"\
        "\tpslldq              $4, %%xmm3 \n"\
        "\tpxor                %%xmm3, %%xmm1 \n"\
        "\tpslldq              $4, %%xmm3\n"\
        "\tpxor                %%xmm3, %%xmm1\n"\
        "\tpxor                %%xmm2, %%xmm1\n"\
        "\tret\n"\

        "2:\n"\
        "\tmovq                %[pKey], %%rdi\n"\
        "\tmovq                %[pExpandedKey], %%rsi\n"\
        "\tmovdqu              (%%rdi), %%xmm1 \n"\
        "\tmovdqu              %%xmm1, (%%rsi)\n"\
    
        "\taeskeygenassist     $1, %%xmm1, %%xmm2\n"\
        "\tcall                1b\n"\
        "\tmovdqu              %%xmm1, 16(%%rsi) \n"\
        "\taeskeygenassist     $2, %%xmm1, %%xmm2 \n"\
        "\tcall                1b\n"\
        "\tmovdqu              %%xmm1, 32(%%rsi) \n"\
        "\taeskeygenassist     $4, %%xmm1, %%xmm2 \n"\
        "\tcall                1b\n"\
        "\tmovdqu              %%xmm1, 48(%%rsi) \n"\
        "\taeskeygenassist     $8, %%xmm1, %%xmm2 \n"\
        "\tcall                1b\n"\
        "\tmovdqu              %%xmm1, 64(%%rsi) \n"\
        "\taeskeygenassist     $16, %%xmm1, %%xmm2 \n"\
        "\tcall                1b\n"\
        "\tmovdqu              %%xmm1, 80(%%rsi) \n"\
        "\taeskeygenassist     $32, %%xmm1, %%xmm2 \n"\
        "\tcall                1b\n"\
        "\tmovdqu              %%xmm1, 96(%%rsi) \n"\
        "\taeskeygenassist     $64, %%xmm1, %%xmm2 \n"\
        "\tcall                1b\n"\
        "\tmovdqu              %%xmm1, 112(%%rsi) \n"\
        "\taeskeygenassist     $0x80, %%xmm1, %%xmm2 \n"\
        "\tcall                1b\n"\
        "\tmovdqu              %%xmm1, 128(%%rsi) \n"\
        "\taeskeygenassist     $0x1b, %%xmm1, %%xmm2 \n"\
        "\tcall                1b\n"\
        "\tmovdqu              %%xmm1, 144(%%rsi) \n"\
        "\taeskeygenassist     $0x36, %%xmm1, %%xmm2 \n"\
        "\tcall                1b\n"\
        "\tmovdqu              %%xmm1, 160(%%rsi)\n"\
        :
        : [pKey] "m"(pKey), [pExpandedKey] "m"(pExpandedKey)
        : "%rdi", "%rsi", "%xmm1", "%xmm2", "%xmm3");
}


void inline fixAES128DecRoundKeys(byte* ks)
{
    asm volatile (
        "\tmovq          %[ks], %%rdi\n"\
        "\tmovdqu        (%%rdi), %%xmm1\n"\
        "\taesimc        %%xmm1, %%xmm1\n"\
        "\tmovdqu        %%xmm1, (%%rdi)\n"\
        :
        : [ks] "m" (ks)
        : "%rdi", "%xmm1", "%xmm0");
}


bool    supportsni()
{
    u32     out[4];

    callcpuid(0x1, out);
    return(((out[2]>>AESFEATUREOFFSET)&1)!=0);
}


void aesni::CleanKeys()
{
    for(int i=0; i<4*(MAXNR+1); i++)
        m_rk[i]= 0;
}


int aesni::KeySetupEnc(const byte* pbKey, int iNumKeyBits) 
{
    if(iNumKeyBits!=128)
        return 0;
    m_Nr= 10;
    genAES128EncRoundKeys((byte*)pbKey,  (byte*)m_rk);
    return m_Nr;
}


int aesni::KeySetupDec(const byte* pbKey, int iNumKeyBits) 
{
    int     i;
    if(iNumKeyBits!=128)
        return 0;
     genAES128EncRoundKeys((byte*)pbKey,  (byte*)m_rk);
     for(i=1; i<10;i++) 
         fixAES128DecRoundKeys((byte*) &m_rk[4*i]);
    m_Nr= 10;
    return m_Nr;
}


void aesni::Encrypt(const byte pt[16], byte ct[16]) 
{
    byte*    ks= (byte*)m_rk;
    asm volatile (
        "\tmovq         %[ks], %%r8\n"\
        "\tmovq         %[pt], %%rdi\n"\
        "\tmovq         %[ct], %%rsi\n"\
        "\tmovdqu       (%%rdi), %%xmm1\n"\

        "\tmovdqu       (%%r8), %%xmm0\n"\
        "\tpxor         %%xmm0, %%xmm1\n"\

        "\tmovdqu       16(%%r8),%%xmm0\n"\
        "\taesenc       %%xmm0,%%xmm1\n"\

        "\tmovdqu       32(%%r8),%%xmm0\n"\
        "\taesenc       %%xmm0,%%xmm1\n"\
        "\tmovdqu       48(%%r8),%%xmm0\n"\
        "\taesenc       %%xmm0,%%xmm1\n"\
        "\tmovdqu       64(%%r8),%%xmm0\n"\
        "\taesenc       %%xmm0,%%xmm1\n"\
        "\tmovdqu       80(%%r8),%%xmm0\n"\
        "\taesenc       %%xmm0,%%xmm1\n"\
        "\tmovdqu       96(%%r8),%%xmm0\n"\
        "\taesenc       %%xmm0,%%xmm1\n"\
        "\tmovdqu       112(%%r8),%%xmm0\n"\
        "\taesenc       %%xmm0,%%xmm1\n"\
        "\tmovdqu       128(%%r8),%%xmm0\n"\
        "\taesenc       %%xmm0,%%xmm1\n"\
        "\tmovdqu       144(%%r8),%%xmm0\n"\
        "\taesenc       %%xmm0,%%xmm1\n"\
        "\tmovdqu       160(%%r8),%%xmm0\n"\
        "\taesenclast   %%xmm0,%%xmm1\n"\
        "\tmovdqu       %%xmm1,(%%rsi)\n" \
        :
        : [pt] "m" (pt), [ct] "m" (ct), [ks] "m" (ks)
        : "%rdi", "%rsi", "%xmm1", "%r8", "%xmm0");
}


void aesni::Decrypt(const byte ct[16], byte pt[16]) 
{
    byte*    ks= (byte*)m_rk;
    asm volatile (
        "\tmovq         %[ks], %%r8\n"\
        "\tmovq         %[pt], %%rdi\n"\
        "\tmovq         %[ct], %%rsi\n"\
        "\tmovdqu       (%%rsi), %%xmm1\n"\
        "\tmovdqu       160(%%r8), %%xmm0\n"\
        "\tpxor         %%xmm0, %%xmm1\n"\
        "\tmovdqu       144(%%r8), %%xmm0\n"\
        "\taesdec       %%xmm0,%%xmm1\n"\

        "\tmovdqu       128(%%r8),%%xmm0\n"\
        "\taesdec       %%xmm0,%%xmm1\n"\
        "\tmovdqu       112(%%r8),%%xmm0\n"\
        "\taesdec       %%xmm0,%%xmm1\n"\
        "\tmovdqu       96(%%r8),%%xmm0\n"\
        "\taesdec       %%xmm0,%%xmm1\n"\
        "\tmovdqu       80(%%r8),%%xmm0\n"\
        "\taesdec       %%xmm0,%%xmm1\n"\
        "\tmovdqu       64(%%r8),%%xmm0\n"\
        "\taesdec       %%xmm0,%%xmm1\n"\
        "\tmovdqu       48(%%r8),%%xmm0\n"\
        "\taesdec       %%xmm0,%%xmm1\n"\
        "\tmovdqu       32(%%r8),%%xmm0\n"\
        "\taesdec       %%xmm0,%%xmm1\n"\
        "\tmovdqu       16(%%r8),%%xmm0\n"\
        "\taesdec       %%xmm0,%%xmm1\n"\
        "\tmovdqu       (%%r8),%%xmm0\n"\
        "\taesdeclast   %%xmm0,%%xmm1\n"\
        "\tmovdqu       %%xmm1,(%%rdi)\n" \
        :
        : [pt] "m" (pt), [ct] "m" (ct), [ks] "m" (ks)
        : "%rdi", "%rsi", "%xmm1", "%r8", "%xmm0");
}


// ------------------------------------------------------------------------


