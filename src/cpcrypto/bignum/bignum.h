//
//  File: bignum.h:
//  Description: Multiprecision arithmetic data structures
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

#include "common.h"

#ifndef __MPGLOBALDEFINES_
#define __MPGLOBALDEFINES_

const i32 s_isGreaterThan = 1;
const i32 s_isEqualTo = 0;
const i32 s_isLessThan = -1;

const u32 s_signBit = 0x80000000;
const u32 s_signMask = 0x7fffffff;
#endif

//  Number Format (bNum):
//      m_signandSize contains sign and number of 64 bit digits allocated.
//      If the top bit of m_signandSize, 1 the number is negative.
//      Remaining 31 bits is the number of 64 bit digits allocated.
//      Array of 64 bit unsigned values in m_pValue are 64 bit
//      digits: digit1 digit2 ... digitn.  The 64-bit word with lowest
//      address (digit1) is the least significant.  The 64 bit word with
//      highest address is most significant.
//      In earlier versions, a number with no digits was treated as 0.
//      That is now an error.  Every number must have at least one digit.

class bnum {
 public:
  u32 m_signandSize;
  u64* m_pValue;  //  __attribute__((aligned(64)));?

  bnum(int size);
  ~bnum();

  inline bool mpSign();
  inline int mpSize();
  inline void mpNegate();
  inline void mpDumpSign();
  inline int mpBitSize();
  inline bool mpIsZero();
  bool mpCopyNum(bnum&);
};

inline bool bnum::mpSign() { return (m_signandSize & s_signBit) != 0; }

inline int bnum::mpSize() { return (int)(m_signandSize & (~s_signBit)); }

inline void bnum::mpNegate() {
  if (mpSize() > 0) m_signandSize ^= s_signBit;
}

inline void bnum::mpDumpSign() {
  if (mpSize() > 0) m_signandSize &= ~s_signBit;
}

inline int bnum::mpBitSize() { return mpSize() * 64; }

inline bool bnum::mpIsZero() {
  int iSize = mpSize();

  if (iSize <= 0) return (true);
  u64* puN = m_pValue;
  while (iSize-- > 0) {
    if (*(puN++) != 0) return (false);
  }
  return (true);
}

#define NUMBITSINU64 64
#define NUMBITSINU64MINUS1 63

extern bnum g_bnZero;
extern bnum g_bnOne;
extern bnum g_bnTwo;
extern bnum g_bnThree;

#endif  // _BIGNUM_H

// ----------------------------------------------------------------------------
