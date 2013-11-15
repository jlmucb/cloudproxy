//
//  File: jlmcrypto.h
//  Description: common crypto definitions and helpers
//
//
//  Copyright (c) 2011, Intel Corporation. Some contributions 
//    (c) John Manferdelli.  All rights reserved.
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


// --------------------------------------------------------------------------


#ifndef _JLMCRYPTO__H
#define _JLMCRYPTO__H

#include "jlmTypes.h"
#include "keys.h"
#include "aesni.h"
#include "sha256.h"
#include "modesandpadding.h"


#define NBITSINBYTE 8


extern int  iRandDev;

bool        getCryptoRandom(int iNumBits, byte* buf);
bool        initCryptoRand();
bool        closeCryptoRand();
bool        toBase64(int iInLen, const unsigned char* puIn, int* piOutLen, char* rgszOut, 
                     bool fDirFwd=true);
bool        fromBase64(int iInLen, const char* pszIn, int* piOutLen, unsigned char* puOut, 
                       bool fDirFwd=true);
bool        getBase64Rand(int iBytes, byte* puR, int* pOutSize, char* szOut);
bool        initAllCrypto();
bool        closeallCrypto();

bool        prf_SHA256(int iKeyLen, byte* rguKey, int iSeedSize, byte* rguSeed,
                       const char* label, int iOutSize, byte* rgOut);
bool        hmac_sha256(byte* rguMsg, int iInLen, byte* rguKey, int iKeyLen, byte* rguDigest);


inline void inlineXor(byte* pTo, byte* pA, byte* pB, int len)
{
    int i;

    for(i=0;i<len;i++)
        pTo[i]= pA[i]^pB[i];
}

inline void inlineXorto(byte* pTo, byte* pFrom, int len)
{
    int i;

    for(i=0;i<len;i++)
        *(pTo++)^= *(pFrom++);
}


inline bool isEqual(byte* pu1, byte* pu2, int len)
{
    int     i;

    for(i=0;i<len;i++) {
        if(*(pu1++)!=*(pu2++))
            return false;
    }

    return true;
}


#endif


// --------------------------------------------------------------------


bool AES128CBCHMACSHA256SYMPADEncryptBlob(int insize, byte* in, 
                                          int* poutsize, byte* out,
                                          byte* enckey, byte* intkey);

bool AES128CBCHMACSHA256SYMPADDecryptBlob(int insize, byte* in, 
                                          int* poutsize, byte* out,
                                          byte* enckey, byte* intkey);


// --------------------------------------------------------------------


