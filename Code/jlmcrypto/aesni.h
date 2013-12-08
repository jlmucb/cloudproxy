//
//  File: aesni.h
//  Descriptin: aesni defines
//
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


// ------------------------------------------------------------------------


#ifndef __AESNI_H
#define __AESNI_H

#include "jlmTypes.h"
#include "string.h"

#define  MAXKC  (256/32)
#define  MAXKB  (256/8)
#define  MAXNR  14


class aesni {
private:
    int     m_Nr;                   // number of rounds (10 only for now)
    u32     m_rk[4*(MAXNR+1)+1];    // round keys
public:
    aesni();
    ~aesni();

    int     KeySetupEnc(const byte key[16], int nbits);
    int     KeySetupDec(const byte key[16], int nbits);
    void    Encrypt(const byte pt[16], byte ct[16]);
    void    Decrypt(const byte ct[16], byte pt[16]);
    void    CleanKeys();
};

bool	supportsni();

#endif


// ------------------------------------------------------------------------

