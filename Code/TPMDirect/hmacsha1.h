
//  File: hmacsha1.h, hmac sha1
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


#ifndef __HMACSHA1_H
#define __HMACSHA1_H

#include "jlmTypes.h"
#include "algs.h"
#include "sha1.h"
// Get rid of this

// hmac-sha1(msg)= Sha1((secret^opad)||Sha1((secret^ipad)||msg))
class hmacsha1 {
public:
    Sha1        m_oHash;
    byte        m_ipad[SHA1BLOCKBYTESIZE];
    byte        m_opad[SHA1BLOCKBYTESIZE];
    byte        m_key[SHA1BLOCKBYTESIZE];

                hmacsha1();
                ~hmacsha1();
    void        Init(byte* key, int kLen);
    void        Update(byte* msg, int mLen);
    void        Final(byte* digest);
};

bool hmac_sha1(byte* msg, int mlen, byte* key, int klen, byte* digest);

#endif


// ----------------------------------------------------------------------------


