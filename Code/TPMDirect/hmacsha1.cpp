//  File: hmacsha1.cpp, hmac sha1
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

#include "algs.h"
#include "sha1.h"
#include "hmacsha1.h"

#include <string.h>


// ------------------------------------------------------------------------------------


hmacsha1::hmacsha1() 
{
    memset(m_ipad, 0, SHA1BLOCKBYTESIZE);
    memset(m_opad, 0, SHA1BLOCKBYTESIZE);
    memset(m_key, 0, SHA1BLOCKBYTESIZE);
}


hmacsha1::~hmacsha1() 
{
    memset(m_key, 0, SHA1BLOCKBYTESIZE);
    memset(m_ipad, 0, SHA1BLOCKBYTESIZE);
    memset(m_opad, 0, SHA1BLOCKBYTESIZE);
}


void  hmacsha1::Init(byte* key, int klen) 
{
    int     i;

    // if key is longer than SHA1BLOCKBYTESIZE, make it key=SHA1(key)
    if(klen>SHA1BLOCKBYTESIZE) {
        m_oHash.Init();
        m_oHash.Update(key, klen);
        m_oHash.Final();
        m_oHash.getDigest(m_key);
        klen= SHA1BLOCKBYTESIZE;
    }
    else {
        memcpy(m_key, key, klen);
        if(klen<SHA1BLOCKBYTESIZE) {
            memset(&m_key[klen], 0, SHA1BLOCKBYTESIZE-klen);
        }
    }

    for(i=0; i<SHA1BLOCKBYTESIZE;i++) {
        m_ipad[i]= 0x36^m_key[i];
        m_opad[i]= 0x5c^m_key[i];
    }

    // start inner hash
    m_oHash.Init();
    m_oHash.Update(m_ipad, SHA1BLOCKBYTESIZE);

    return;
}


void  hmacsha1::Update(const byte* msg, int mLen) 
{
    m_oHash.Update(msg, mLen);
    return;
}


void  hmacsha1::Final(byte* digest) 
{
    byte      inner[SHA1DIGESTBYTESIZE];

    memset(inner, 0, SHA1DIGESTBYTESIZE);

    // Finish inner hash
    m_oHash.Final();
    m_oHash.getDigest(inner);

    // Outer hash
    m_oHash.Init();
    m_oHash.Update(m_opad, SHA1BLOCKBYTESIZE);
    m_oHash.Update(inner, SHA1DIGESTBYTESIZE);
    m_oHash.Final();
    m_oHash.getDigest(digest);

    return;
}


bool hmac_sha1(byte* msg, int mLen, byte* key, int kLen, byte* digest)
// hmac-sha1(msg)= Sha1((secret^opad)||Sha1((secret^ipad)||msg))
{
    hmacsha1  ohmac;

    ohmac.Init(key, kLen);
    ohmac.Update(msg, mLen);
    ohmac.Final(digest);
    return true;
}


// ------------------------------------------------------------------------------------



