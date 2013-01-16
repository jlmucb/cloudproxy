//  File: hmacsha256.cpp, hmac sha256
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


#include "keys.h"
#include "aes.h"
#include "sha256.h"
#include "hmacsha256.h"


// ------------------------------------------------------------------------------------


hmacsha256::hmacsha256() 
{
    memset(rguipad, 0, SHA256_DIGESTSIZE_BYTES);
    memset(rguopad, 0, SHA256_DIGESTSIZE_BYTES);
    memset(rguNewKey, 0, SHA256_DIGESTSIZE_BYTES);
}


hmacsha256::~hmacsha256() 
{
    memset(rguNewKey, 0, SHA256_DIGESTSIZE_BYTES);
    memset(rguipad, 0, SHA256_DIGESTSIZE_BYTES);
    memset(rguopad, 0, SHA256_DIGESTSIZE_BYTES);
}


void  hmacsha256::Init(byte* rguKey, int iKeyLen) 
{
    int     i;
    int     k= iKeyLen;

    // if key is longer than SHA256_DIGESTSIZE_BYTES, make it key=SHA256(key)
    if(k>SHA256_DIGESTSIZE_BYTES) {
        oHash.Init();
        oHash.Update(rguKey, iKeyLen);
        oHash.Final();
        oHash.GetDigest(rguNewKey);
        k= SHA256_DIGESTSIZE_BYTES;
    }
    else {
        memcpy(rguNewKey, rguKey, k);
        if(k<SHA256_DIGESTSIZE_BYTES) {
            memset(&rguNewKey[k], 0, SHA256_DIGESTSIZE_BYTES-k);
        }
    }

    for(i=0; i<SHA256_DIGESTSIZE_BYTES;i++) {
        rguipad[i]= 0x36^rguNewKey[i];
        rguopad[i]= 0x5c^rguNewKey[i];
    }

    // start inner hash
    oHash.Init();
    oHash.Update(rguipad, SHA256_DIGESTSIZE_BYTES);

    return;
}


void  hmacsha256::Update(byte* rguMsg, int iInLen) 
{
    oHash.Update(rguMsg, iInLen);
    return;
}


void  hmacsha256::Final(byte* rguDigest) 
{
    byte    rguInner[SHA256_DIGESTSIZE_BYTES];

    memset(rguInner, 0, SHA256_DIGESTSIZE_BYTES);

    // Finish inner hash
    oHash.Final();
    oHash.GetDigest(rguInner);

    // Outer hash
    oHash.Init();
    oHash.Update(rguopad, SHA256_DIGESTSIZE_BYTES);
    oHash.Update(rguInner, SHA256_DIGESTSIZE_BYTES);
    oHash.Final();
    oHash.GetDigest(rguDigest);

    return;
}


bool hmac_sha256(byte* rguMsg, int iInLen, byte* rguKey, int iKeyLen, byte* rguDigest)
// hmac-sha256(msg)= Sha256((secret^opad)||Sha256((secret^ipad)||msg))
{
    hmacsha256  ohmac;

    ohmac.Init(rguKey, iKeyLen);
    ohmac.Update(rguMsg, iInLen);
    ohmac.Final(rguDigest);
    return true;
}


// ------------------------------------------------------------------------------------



/*
 *  PRF
 *      P_hash(s1, s2)= HMAC_hash(s1, A(1)+s2)+HMAC_hash(s1, A(2)+s2)+HMAC_hash(s1, A(3)+s2)+...
 *      PRF(secret, label, seed) = P_<hash>(secret, label+seed)
 *
 *                ipad = the byte 0x36 repeated B times
 *                opad = the byte 0x5C repeated B times.
 *
 *      To compute HMAC over the data `text' we perform
 *
 *                  H(K XOR opad, H(K XOR ipad, text))
 *
 *      Namely,
 *          (1) append zeros to the end of K to create a B byte string
 *              (e.g., if K is of length 20 bytes and B=64, then K will be
 *              appended with 44 zero bytes 0x00)
 *          (2) XOR (bitwise exclusive-OR) the B byte string computed in step
 *              (1) with ipad
 *          (3) append the stream of data 'text' to the B byte string resulting
 *              from step (2)
 *          (4) apply H to the stream generated in step (3)
 *          (5) XOR (bitwise exclusive-OR) the B byte string computed in
 *              step (1) with opad
 *          (6) append the H result from step (4) to the B byte string
 *              resulting from step (5)
 *          (7) apply H to the stream generated in step (6) and output
 *              the result
 */


bool prf_SHA256(int iKeyLen, byte* rguKey, int iSeedSize, byte* rguSeed,
                       char* label, int iOutSize, byte* rgOut)
// A[0] = label||seed, A[i+1] = HMAC_hash(secret, A[i])
// PRF(secret, label, seed) = HMAC_hash(key, A[0]||seed)||HMAC_hash(key, A[1]||seed)...
// For TLS, secret is master secret, seed is server_random||client_random
{
    byte*   rgInBlock= NULL;
    byte    rgOutBlock[SHA256_DIGESTSIZE_BYTES];
    int     iL= strlen(label);
    int     iModifiedSize;

#ifdef TEST1
    fprintf(g_logFile, "prf_SHA256 %s %d %d %d\n", label, iKeyLen, iSeedSize, iOutSize);
    PrintBytes((char*)"Key  ", rguKey, iKeyLen);
    PrintBytes((char*)"Seed ", rguSeed, iSeedSize);
#endif

    iModifiedSize= iSeedSize+SHA256_DIGESTSIZE_BYTES+iL;
    rgInBlock= (byte*) malloc(iModifiedSize);
    if(rgOutBlock==NULL)
        return false;

    // first Block
    memcpy(rgInBlock, label, iL);
    memcpy(&rgInBlock[iL], rguSeed, iSeedSize);
    hmac_sha256(rgInBlock, iL+iSeedSize, rguKey, iKeyLen, rgOutBlock);  // A[0]

    // keys
    int     iLeft= iOutSize;
    memcpy(&rgInBlock[SHA256_DIGESTSIZE_BYTES], rguSeed, iSeedSize);
    while(iLeft>0) {
        memcpy(rgInBlock, rgOutBlock, SHA256_DIGESTSIZE_BYTES);
        hmac_sha256(rgInBlock, SHA256_DIGESTSIZE_BYTES+iSeedSize, rguKey, iKeyLen, rgOutBlock);
        if(iLeft<SHA256_DIGESTSIZE_BYTES)
            memcpy(rgOut, rgOutBlock, iLeft);
        else 
            memcpy(rgOut, rgOutBlock, SHA256_DIGESTSIZE_BYTES);
        rgOut+= SHA256_DIGESTSIZE_BYTES;
        iLeft-= SHA256_DIGESTSIZE_BYTES;
    }

    free(rgInBlock);
    return true;
}


// ------------------------------------------------------------------------------------
