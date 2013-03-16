//
//  File: bignum.h:
//     Multiprecision arithmetic data structures
//
//  Copyright (c) 2011, John Manferdelli.  All rights reserved.
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


// ----------------------------------------------------------------------------


#ifndef _BIGNUM_H
#define _BIGNUM_H

typedef unsigned char           u8;
typedef char                    i8;
typedef short unsigned          u16;
typedef short int               i16;
typedef unsigned                u32;
typedef int                     i32;
typedef long long unsigned      u64;
typedef long long int           i64;
typedef long unsigned int       up64;

#ifndef byte
typedef unsigned char           byte;
#endif


#ifndef __MPGLOBALDEFINES_
#define __MPGLOBALDEFINES_

const i32       s_iIsGreaterThan= 1;
const i32       s_iIsEqualTo= 0;
const i32       s_iIsLessThan= -1;

const u32       s_SignBit=  0x80000000;
const u32       s_SizeMask= 0x7fffffff;
#endif


//      Number Format (bNum): 
//              Array of 32 bit values: sLen32 digit1 digit1 ... digitn
//              Top bit of sLen is sign (1 means negative) remaining 64 bits are
//              the number of 32 bit words constituting the number low order words first.
//              Remaining 32 bit words are 32 bit unsigned quantities representing the
//              absolute value of the number, least significant word is first, most
//              significant is last.
class bnum {
public:
    u32     m_uSignandSize;
    u64*    m_pValue;

    bnum(int iSize);
    ~bnum();

    inline bool     mpSign();
    inline u32      mpSize();
    inline void     mpNegate();
    inline void     mpDumpSign();
    inline u32      mpBitSize();
    inline bool     mpIsZero();
    bool            mpCopyNum(bnum& bnC);
};


inline bool bnum::mpSign()    
{
    return (m_uSignandSize&s_SignBit)!=0;
}


inline u32  bnum::mpSize()    
{
    return m_uSignandSize&(~s_SignBit);
}


inline void bnum::mpNegate()  
{
    if(mpSize()>0) 
        m_uSignandSize^= s_SignBit;
}


inline void bnum::mpDumpSign()  
{
    if(mpSize()>0) 
        m_uSignandSize&= ~s_SignBit;
}


inline u32 bnum::mpBitSize()  
{
    return mpSize()*64;
}


inline bool bnum::mpIsZero()
{
    int iSize= mpSize();

    if(iSize<=0)
        return(true);
    u64* puN= m_pValue;
    while(iSize-->0)  {
        if(*(puN++)!=0)
            return(false);
    }
    return(true);
}


#define NUMBITSINU64  64


#ifndef NULL
#define NULL 0
#endif


#endif    // _BIGNUM_H


// ----------------------------------------------------------------------------

