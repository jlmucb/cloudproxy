//
//  File: algs.h
//      John Manferdelli
//
//  Description:  algorithm definitions
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


// -------------------------------------------------------------------------------


#ifndef _ALGS__H
#define _ALGS__H


#define BLOCK        1
#define STREAM       2
#define ASYMMETRIC   3

#define NOPAD        0
#define PKCSPAD      1
#define SYMPAD       2

#define NOHASH       0
#define SHA256HASH   1
#define SHA1HASH     2
#define SHA512HASH   3
#define SHA384HASH   4
#define MD5HASH      5

#define NOMODE       0
#define ECBMODE      1
#define CBCMODE      2
#define CTRMODE      3
#define GCMMODE      4

#define NOALG        0
#define AES128       1
#define AES256       2
#define RSA1024      6
#define RSA2048      7

#define NOHMAC       0
#define HMACSHA256   1

#define NOKEYTYPE        0
#define AESKEYTYPE       1
#define RSAKEYTYPE       2


#define AES128BYTEBLOCKSIZE        16
#define AES128BYTEKEYSIZE          16
#define AES256BYTEBLOCKSIZE        16
#define AES256BYTEKEYSIZE          32

#define RSA1024BYTEKEYSIZE        128
#define RSA2048BYTEKEYSIZE        256

#define RSA1024BYTEBLOCKSIZE      128
#define RSA2048BYTEBLOCKSIZE      256

#define SHA1BLOCKBYTESIZE          64
#define SHA1DIGESTBYTESIZE         20
#define SHA256BLOCKBYTESIZE        64
#define SHA256DIGESTBYTESIZE       32
#define SHA512BLOCKBYTESIZE        64
#define SHA512DIGESTBYTESIZE       64

#define GLOBALMAXDIGESTSIZE       128
#define GLOBALMAXSYMKEYSIZE       128
#define GLOBALMAXPUBKEYSIZE       512
#define GLOBALMAXSEALEDKEYSIZE   1024

#define SMALLKEYSIZE              128
#define BIGKEYSIZE                512
#define KEYNAMEBUFSIZE            128
#define KEYTYPEBUFSIZE            128
#define BIGSYMKEYSIZE              64
#define BIGBLOCKSIZE               32

#define AES128CBCSYMPADHMACSHA256  (AES128|(CBCMODE<<8)|(SYMPAD<<16)|(HMACSHA256<<24))
#define AES128GCM                  (AES128 | (GCMMODE<<8))

#define NOENCRYPT                 0
#define DEFAULTENCRYPT            1


inline int maxGlobalDigestSize() {return GLOBALMAXDIGESTSIZE;}
inline int maxGlobalSymKeySize() {return GLOBALMAXSYMKEYSIZE;}
inline int maxGlobalPubKeySize() {return GLOBALMAXPUBKEYSIZE;}
inline int maxGlobalSealedKeySize() {return GLOBALMAXSEALEDKEYSIZE;}


#endif


// -----------------------------------------------------------------------------


