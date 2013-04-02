//
//  File: rsaHelper.h
//      John Manferdelli
//
//  Description:  rsa helper function definitions
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

#include "jlmTypes.h"
#include "tinyxml.h"
#include "bignum.h"
#include "modesandpadding.h"


// --------------------------------------------------------------------------


#ifndef _RSAHELPER__H
#define _RSAHELPER__H


RSAKey*     generateRSAKeypair(int keySize);
bool        initRSAKeyFromKeyInfo(RSAKey** ppKey, TiXmlNode* pNode);
bool        initRSAKeyFromStringRSAKey(RSAKey** ppKey, const char* szXml, const char* szLoc);

char*       rsaXmlEncodeChallenge(bool fEncrypt, RSAKey& rgKey, byte* puChallenge,
                int sizeChallenge);

char*       rsaXmlEncodeChallenges(bool fEncrypt, int iNumKeys, RSAKey** rgKeys,
                                    byte* puChallenge, int sizeChallenge);
bool        rsaXmlDecodeandVerifyChallenge(bool fEncrypt, RSAKey& rgKey, const char* szSig,
                int sizeChallenge, byte* puOriginal);
bool        rsaXmlDecryptandGetNonce(bool fEncrypt, RSAKey& rgKey, int sizein, 
                byte* rgIn, int sizeNonce, byte* rgOut);
bool        bumpChallenge(int iSize, byte* puChallenge);

#endif


// -----------------------------------------------------------------------------


