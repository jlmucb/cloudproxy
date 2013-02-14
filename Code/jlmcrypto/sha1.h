//
//  Copyright (c) 2012 John Manferdelli.  All rights reserved.
//    Some contributions (c) 2012, Intel Corporation
//
//      Description: sha-1
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


#ifndef __SHA1_H__
#define __SHA1_H__

#define IV1 0x67452301
#define IV2 0xefcdab89
#define IV3 0x98badcfe
#define IV4 0x10325476
#define IV5 0xc3d2e1f0

#define K1  0x5A827999 
#define K2  0x6ED9EBA1
#define K3  0x8F1BBCDC
#define K4  0xCA62C1D6


#include "jlmTypes.h"

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN
#endif


class Sha1 {
    public:
    enum            {DIGESTSIZE= 20, BLOCKSIZE= 64};

    u32             m_rgState[DIGESTSIZE/sizeof(u32)];
    u64             m_uLen;
    int             m_iBLen;
    byte            m_rgB[BLOCKSIZE];
#ifdef  LITTLE_ENDIAN
    void            littleEndian(byte* buf, int size);
#endif
    void            Init();
    bool            Transform(u32*);
    void            Update(const byte*, const u32 long);
    void            Final();
    void            getDigest(byte* rgOut);
};

#endif
