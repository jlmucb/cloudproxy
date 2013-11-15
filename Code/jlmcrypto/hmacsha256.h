
//  File: hmacsha256.h
//
//  Copyright (c) 2012, John Manferdelli.  All rights reserved.
//      Some contributions (c) Intel Corporation
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


#ifndef __HMACSHA256_H
#define __HMACSHA256_H

#include "jlmTypes.h"
#include "keys.h"
#include "aesni.h"
#include "sha256.h"

// hmac-sha256(msg)= Sha256((secret^opad)||Sha256((secret^ipad)||msg))

class hmacsha256 {
public:
    Sha256      oHash;
    byte        rguipad[SHA256_DIGESTSIZE_BYTES];
    byte        rguopad[SHA256_DIGESTSIZE_BYTES];
    byte        rguNewKey[SHA256_DIGESTSIZE_BYTES];

                hmacsha256();
                ~hmacsha256();
    void        Init(byte* rguKey, int iKeyLen);
    void        Update(const byte* rguMsg, int iInLen);
    void        Final(byte* rguDigest);
};

#endif

// ----------------------------------------------------------------------------


