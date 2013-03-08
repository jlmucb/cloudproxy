//
//  File: modesandpadding.cpp
//      John Manferdelli
//
//  Description:  Padding functions
//
//  Copyright (c) 2011, Intel Corporation. All rights reserved.
//  Some contributions (c) John Manferdelli.  All rights reserved.
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
#include "logging.h"
#include "jlmcrypto.h"
#include "keys.h"
#include "modesandpadding.h"
#include "aesni.h"
#include "sha256.h"

#include <string.h>


//
//  Headers with DER encoding
//
byte    rgMD5Hdr[]= { 
    0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 
    0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 
    0x04, 0x10 };
byte    rgSHA1Hdr[]= {
    0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 
    0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14};
byte    rgSHA256Hdr[]= {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 
    0x00, 0x04, 0x20};
byte    rgSHA384Hdr[]= {
    0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 
    0x00, 0x04, 0x30};
byte    rgSHA512Hdr[]= {
    0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 
    0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 
    0x00, 0x04, 0x40};


// ---------------------------------------------------------------------------------


//  Signature Padding
//      pkcs 1.5 for now
//      use pss later: Todo


//  PKCS1-v1_5-ENCODE(M, emLen)
//      Option: Hash    hash function (hLen is length in bytes)
//      Input:  M       message to be encoded
//      emLen   intended length of the encoded message (size of modulus)
//          at least tLen + 11 
//      tLen is octet length of the DER encoding (T)
//  Steps:
//      1.  H = Hash (M) .
//      2.  Encode the algorithm ID for the hash function and the hash value (T)
//      3.  If emLen<tLen+11, error
//      4.  Generate PS consisting of emLen–tLen–3 octets with value 0xff. 
//              The length of PS will be at least 8 octets.
//      5.  EM = 0x00 || 0x01 || PS || 0x00 || T .
//  MD2:      (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 02 05 00 04 10 || H. 
//  MD5:      (0x)30 20 30 0c 06 08 2a 86 48 86 f7 0d 02 05 05 00 04 10 || H. 
//  SHA-1:    (0x)30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14 || H. 
//  SHA-256:  (0x)30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 || H. 
//  SHA-384:  (0x)30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30 || H. 
//  SHA-512:  (0x)30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40 || H. 


bool emsapkcspad(int hashType, byte* rgHash, int  sigSize, byte* rgSig)

{
    int     n= 0;
    int     hashLen= 0;
    int     hdrLen= 0;
    int     psLen= 0;
    int     minsigSize= 0;
    byte*   pHdr= NULL;

    switch(hashType) {
      case SHA256HASH:
        hashLen= SHA256DIGESTBYTESIZE;
        hdrLen= sizeof(rgSHA256Hdr);
        pHdr= rgSHA256Hdr;
        break;
      case SHA1HASH:
        hashLen= SHA1DIGESTBYTESIZE;
        hdrLen= sizeof(rgSHA1Hdr);
        pHdr= rgSHA1Hdr;
        break;
      case SHA512HASH:
        hashLen= SHA512DIGESTBYTESIZE;
        hdrLen= sizeof(rgSHA512Hdr);
        pHdr= rgSHA512Hdr;
        break;
      case SHA384HASH:
      case MD5HASH:
      default:
        fprintf(g_logFile, "pkcs padding, unsupported hash type\n");
        return false;
    }

    minsigSize= 11+hashLen+hdrLen;
    if(minsigSize>sigSize) {
        fprintf(g_logFile, "padded output buffer too small\n");
        return false;
    }

    // 2 byte header
    rgSig[n++]= 0x00; rgSig[n++]= 0x01;

    // PS
    psLen= sigSize-3-hashLen-hdrLen;
    memset(&rgSig[n], 0xff, psLen);
    n+= psLen;

    // 0
    rgSig[n++]= 0x00;

    // header
    memcpy(&rgSig[n], pHdr , hdrLen);
    n+= hdrLen;

    // hash
    memcpy(&rgSig[n], rgHash, hashLen);

#ifdef CRYPTOTEST4
    PrintBytes("Padded block\n", rgSig, sigSize);
#endif
    return true;
}


bool emsapkcsverify(int hashType, byte* rgHash, int sigSize, byte* rgSig)
{
    int     n= 0;
    int     hashLen= 0;
    int     hdrLen= 0;
    int     psLen= 0;
    int     minsigSize= 0;
    byte*   pHdr= NULL;
    byte    rgPre[2]= {0x00, 0x01};

#ifdef CRYPTOTEST7
    fprintf(g_logFile, "emsapkcsverify, hash type %d, blocksize %d\n", hashType, sigSize);
    PrintBytes("Padded block\n", rgSig, sigSize);
    PrintBytes("Hash\n", rgHash, 32);
#endif
    switch(hashType) {
      case SHA256HASH:
        hashLen= SHA256DIGESTBYTESIZE;
        hdrLen= sizeof(rgSHA256Hdr);
        pHdr= rgSHA256Hdr;
        break;
      case SHA1HASH:
        hashLen= SHA1DIGESTBYTESIZE;
        hdrLen= sizeof(rgSHA1Hdr);
        pHdr= rgSHA1Hdr;
        break;
      case SHA512HASH:
        hashLen= SHA512DIGESTBYTESIZE;
        hdrLen= sizeof(rgSHA512Hdr);
        pHdr= rgSHA512Hdr;
        break;
      case SHA384HASH:
      case MD5HASH:
      default:
        fprintf(g_logFile, "pkcs padding, unsupported hash type\n");
        return false;
    }

    minsigSize= 11+hashLen+hdrLen;
    if(minsigSize>sigSize) {
        fprintf(g_logFile, "padded input buffer too small %d %d\n", 
                minsigSize, sigSize);
        return false;
    }

    // preamble
    if(memcmp(&rgSig[n], rgPre, 2)!=0) {
        fprintf(g_logFile, "Bad preamble\n");
        return false;
    }
    n+= 2;

    // PS
    psLen= sigSize-3-hashLen-hdrLen;
    for(int i=n;i<(n+psLen);i++) {
        if(rgSig[i]!=0xff) {
            fprintf(g_logFile, "PS wrong at %d\n", i);
            fprintf(g_logFile, "fflen %d, sigsize: %d, hashLen: %d, hdrLen: %d\n", 
                    psLen,sigSize,hashLen, hdrLen);
            return false;
        }
    }
    n+= psLen;
   
    // 0 byte 
    if(rgSig[n]!=0x00) {
        fprintf(g_logFile, "verify off in byte %d %02x (PSS1) \n", n, rgSig[n]);
        return false;
    }
    n++;

    // Header
    if(memcmp(&rgSig[n], pHdr, hdrLen)!=0) {
        fprintf(g_logFile, "Bad header\n");
        return false;
    }
    n+= hdrLen;

    // Hash
    if(memcmp(&rgSig[n], rgHash, hashLen)!=0) {
        fprintf(g_logFile, "Bad hash\n");
#ifdef CRYPTOTEST
    PrintBytes("decoded hash\n", &rgSig[n], hashLen);
    PrintBytes("computed hash\n", rgHash, hashLen);
#endif
        return false;
    }
    n+= hdrLen;

    return true;
}


// ----------------------------------------------------------------


/*
 *  CBC
 *
 *      C[0]= IV, C[i]= E_K(C[i-1] xor P[i])
 */


cbc::cbc()
{
    m_iBlockSize= 0;
    m_iNumPlainBytes= 0;
    m_iNumCipherBytes= 0;
    m_iKeySize= 0;
    m_iIntKeySize= 0;
    m_fIVValid= false;
    m_uEncAlg= 0;
    m_rgLastBlock= NULL;
    m_rguFirstBlock= NULL;
    m_rguLastBlocks= NULL;
    m_rguHMACComputed= NULL;
    m_rguHMACReceived= NULL;
    m_rguIntKey= NULL;
}


cbc::~cbc()
{
#if 0
    m_oAESEnc.CleanKeys();
    m_oAESDec.CleanKeys();
    memset(m_rguIntKey, 0, m_iIntKeySize);
    if(m_rguFirstBlock!=NULL) {
        free(m_rguFirstBlock);
        m_rguFirstBlock= NULL;
    }
    if(m_rgLastBlock!=NULL) {
        free(m_rgLastBlock);
        m_rgLastBlock= NULL;
    }
    if(m_rguLastBlocks!=NULL) {
        free(m_rguLastBlocks);
        m_rguLastBlocks= NULL;
    }
    if(m_rguHMACComputed!=NULL) {
        free(m_rguHMACComputed);
        m_rguHMACComputed= NULL;
    }
    if(m_rguHMACReceived!=NULL) {
        free(m_rguHMACReceived);
        m_rguHMACReceived= NULL;
    }
    if(m_rguIntKey!=NULL) {
        free(m_rguIntKey);
        m_rguIntKey= NULL;
    }
#endif
}


bool cbc::computePlainLen()
{
    m_iNumPlainBytes= m_iNumCipherBytes-m_iBlockSize-SHA256_DIGESTSIZE_BYTES;
    return true;
}


bool cbc::computeCipherLen()
{
    int k;

    if((m_iNumPlainBytes%m_iBlockSize)==0) {
        m_iNumCipherBytes= m_iNumPlainBytes+2*m_iBlockSize+SHA256_DIGESTSIZE_BYTES;
    }
    else {
        k= (m_iNumPlainBytes+m_iBlockSize-1)/m_iBlockSize;
        m_iNumCipherBytes= k*m_iBlockSize+m_iBlockSize+SHA256_DIGESTSIZE_BYTES;
    }
    return true;
}


bool cbc::initDec(u32 alg, u32 pad, u32 hashalg, int keysize, byte* key, int intkeysize, byte* intkey,
                    int cipherLen)
{
#ifdef CRYPTOTEST4
    fprintf(g_logFile, "cbc::initDec\n");
#endif
    if(!init(alg, pad, hashalg, keysize, key, intkeysize, intkey))
        return false;
    m_iNumCipherBytes= cipherLen;
    computePlainLen();
    if(m_oAESDec.KeySetupDec(key, keysize*NBITSINBYTE)<0) {
        return false;
    }
    return true;
}


#ifdef CRYPTOTEST4
void printCBCState(cbc* pMode)
{
    fprintf(g_logFile, "CBC State:\n");
    fprintf(g_logFile, "\tBlock size: %d\n", pMode->m_iBlockSize);
    fprintf(g_logFile, "\tPlain bytes: %d, cipherBytes: %d\n", pMode->m_iNumPlainBytes, pMode->m_iNumCipherBytes);
    fprintf(g_logFile, "\tKey size: %d, integrity key size: %d\n", pMode->m_iKeySize, pMode->m_iIntKeySize);

    if(pMode->m_fIVValid)
        fprintf(g_logFile, "\tIV valid\n");
    else
        fprintf(g_logFile, "\tIV invalid\n");
    fprintf(g_logFile, "\tEnc %d, mac: %d, pad: %d\n", pMode->m_uEncAlg, pMode->m_uMacAlg, pMode->m_uPadAlg);

    // m_rguIV;
    // m_rgLastBlock;
    // m_rguFirstBlock;
    // m_rguLastBlocks;
    // m_rguHMACComputed;
    // m_rguHMACReceived;
    // m_rguIntKey;
}
#endif


bool cbc::initEnc(u32 alg, u32 pad, u32 hashalg, int keysize, byte* key, int intkeysize, byte* intkey,
                    int plainLen, int ivSize, byte* iv)
{
#ifdef CRYPTOTEST4
    fprintf(g_logFile, "cbc::initEnc\n");
#endif
    if(!init(alg, pad, hashalg, keysize, key, intkeysize, intkey))
        return false;
    if(iv!=NULL) {
        memcpy(m_rguFirstBlock, iv, m_iBlockSize);
        memcpy(m_rgLastBlock, iv, m_iBlockSize);
        m_fIVValid= true;
    }
    m_iNumPlainBytes= plainLen;
    computeCipherLen();
    if(m_oAESEnc.KeySetupEnc(key, keysize*NBITSINBYTE)<0) {
        return false;
    }
    return true;
}


bool cbc::init(u32 alg, u32 pad, u32 macalg, int keysize, byte* key, int intkeysize, byte* intkey)
{
    m_iNumPlainBytes= 0;
    m_iNumCipherBytes= 0;
    m_fIVValid= false;

    if(alg!=AES128)
        return false;
    m_uEncAlg= alg;
    m_iBlockSize= 16;

    if(macalg!=HMACSHA256)
        return false;
    m_uMacAlg= macalg;

    if(pad!=SYMPAD)
        return false;
    m_uPadAlg= pad;

    if(m_rguFirstBlock==NULL)
        m_rguFirstBlock= (byte*) malloc(m_iBlockSize);
    if(m_rguLastBlocks==NULL)
        m_rguLastBlocks= (byte*) malloc(4*m_iBlockSize);
    if(m_rgLastBlock==NULL)
        m_rgLastBlock= (byte*) malloc(m_iBlockSize);
    if(m_rguHMACComputed==NULL)
        m_rguHMACComputed= (byte*) malloc(SHA256_DIGESTSIZE_BYTES);
    if(m_rguHMACReceived==NULL)
        m_rguHMACReceived= (byte*) malloc(SHA256_DIGESTSIZE_BYTES);
    if(m_rguIntKey!=NULL) {
        if(m_iIntKeySize!=intkeysize) {
            free(m_rguIntKey);
            m_rguIntKey= NULL;
        }
    }
    m_iIntKeySize= intkeysize;
    if(m_rguIntKey==NULL)
        m_rguIntKey= (byte*) malloc(m_iIntKeySize);

    if(m_rguFirstBlock==NULL || m_rguLastBlocks==NULL || m_rgLastBlock==NULL ||
            m_rguHMACComputed==NULL || m_rguHMACReceived==NULL || m_rguIntKey==NULL)
        return false;

    memcpy(m_rguIntKey, intkey, m_iKeySize);
    m_ohMac.Init(intkey, intkeysize);

    return true;
}


int cbc::getMac(int size, byte* puMac)
{
#ifdef CRYPTOTEST4
    fprintf(g_logFile, "cbc::getMac\n");
#endif
    memcpy(puMac, m_rguHMACComputed, SHA256_DIGESTSIZE_BYTES);
    return SHA256_DIGESTSIZE_BYTES;
}


void cbc::nextMac(byte* puA)
// always full block at a time
{
#ifdef CRYPTOTEST4
    PrintBytes("cbc::nextMac", puA, m_iBlockSize);
#endif
    m_ohMac.Update(puA, m_iBlockSize);
}


bool cbc::nextPlainBlockIn(byte* puIn, byte* puOut)
{
    byte    oldX[MAXAUTHSIZE];

#ifdef CRYPTOTEST4
    fprintf(g_logFile, "cbc::nextPlainBlockIn\n");
    PrintBytes("In", puIn, 16);
#endif
    inlineXor(oldX, m_rgLastBlock, puIn, m_iBlockSize);
    m_oAESEnc.Encrypt(oldX, puOut); 
    memcpy(m_rgLastBlock, puOut, m_iBlockSize);
#ifdef ENCRYPTTHENMAC
    nextMac(puIn);
#else
    nextMac(puOut);
#endif
    return true;
}


bool cbc::nextCipherBlockIn(byte* puIn, byte* puOut)
{
    byte    oldX[MAXAUTHSIZE];

#ifdef CRYPTOTEST4
    fprintf(g_logFile, "cbc::nextCipherBlockIn\n");
    PrintBytes("In", puIn, 16);
#endif
    m_oAESDec.Decrypt(puIn, oldX); 
    inlineXor(puOut, m_rgLastBlock, oldX, m_iBlockSize);
    memcpy(m_rgLastBlock, puIn, m_iBlockSize);
#ifdef ENCRYPTTHENMAC
    nextMac(puOut);
#else
    nextMac(puIn);
#endif
    return true;
}


bool cbc::firstCipherBlockIn(byte* puIn)
{
#ifdef CRYPTOTEST4
    fprintf(g_logFile, "cbc::firstCipherBlockIn\n");
    PrintBytes("IV", puIn, m_iBlockSize);
#endif
    memcpy(m_rguFirstBlock, puIn, m_iBlockSize);
    memcpy(m_rgLastBlock, puIn, m_iBlockSize);
    m_fIVValid= true;
    return true;
}


bool cbc::firstCipherBlockOut(byte* puOut)
{
#ifdef CRYPTOTEST4
    fprintf(g_logFile, "cbc::firstCipherBlockOut\n");
    PrintBytes("IV", m_rgLastBlock, m_iBlockSize);
#endif
    memcpy(puOut, m_rgLastBlock, m_iBlockSize);
    return true;
}


bool cbc::validateMac()
{
#ifdef CRYPTOTEST4
    fprintf(g_logFile, "cbc::validateMac\n");
#endif
    return isEqual(m_rguHMACComputed, m_rguHMACReceived, SHA256_DIGESTSIZE_BYTES);
}


int cbc::lastPlainBlockIn(int size, byte* puIn, byte* puOut)
{   
    int     num= 0;
    int     i;

#ifdef CRYPTOTEST1
    PrintBytes("cbc::lastPlainBlockIn\n", puIn, size);
#endif
    memcpy(m_rguLastBlocks, puIn, size);
    // pad
    if(size==m_iBlockSize) {
        m_rguLastBlocks[m_iBlockSize]= 0x80;
        for(i=1;i<m_iBlockSize;i++)
            m_rguLastBlocks[m_iBlockSize+i]= 0x00;
        num= 2;
        nextPlainBlockIn(m_rguLastBlocks, puOut);
        nextPlainBlockIn(m_rguLastBlocks+m_iBlockSize, puOut+m_iBlockSize);
        m_ohMac.Final(m_rguHMACComputed);
    }
    else {
        m_rguLastBlocks[size]= 0x80;
        for(i=(size+1);i<m_iBlockSize;i++)
            m_rguLastBlocks[i]= 0x00;
        num= 1;
        nextPlainBlockIn(m_rguLastBlocks, puOut);
        m_ohMac.Final(m_rguHMACComputed);
    }
    memcpy(puOut+num*m_iBlockSize, m_rguHMACComputed, SHA256_DIGESTSIZE_BYTES);
    num+= 2;

    // Note that the HMAC (whether encrypted or not) is returned as part of cipher stream
    return m_iBlockSize*num;
}


int cbc::lastCipherBlockIn(int size, byte* puIn, byte* puOut)
// last three or four blocks
{
    int     residue= 0;
    int     hmacsize= SHA256_DIGESTSIZE_BYTES;
    int     maxpadsize= 2*m_iBlockSize;
    int     startofdecoded= 0;

#ifdef CRYPTOTEST
    PrintBytes("cbc::lastCipherBlockIn: ", puIn, size);
    fflush(g_logFile);
#endif

    if(!m_fIVValid) {
        fprintf(g_logFile, "cbc::lastCipherBlockIn: first cipherblock was not processed\n");
        return -1;
    }
    
    if(size!=(maxpadsize+hmacsize)) {
        maxpadsize-= m_iBlockSize;
        if(size!=(maxpadsize+hmacsize)) {
            fprintf(g_logFile, "cbc::lastCipherBlockIn: wrong lastBlock size, got %d bytes\n", 
                    size);
            return -1;
        }
    }
    m_iNumPlainBytes-= maxpadsize;

    if(maxpadsize==2*m_iBlockSize) {
        nextCipherBlockIn(puIn, m_rguLastBlocks);
        puIn+= m_iBlockSize;
        startofdecoded+= m_iBlockSize;
    }

    nextCipherBlockIn(puIn, m_rguLastBlocks+startofdecoded);
    puIn+= m_iBlockSize;
    m_ohMac.Final(m_rguHMACComputed);

#ifdef CRYPTOTEST
    PrintBytes("last cipher blocks decoded: ", m_rguLastBlocks, maxpadsize);
    fflush(g_logFile);
#endif

#ifdef ENCRYPTTHENMAC
    // decrypt Mac
    byte    oldX[MAXAUTHSIZE];

    m_oAESDec.Decrypt(puIn, oldX);
    inlineXor(m_rguHMACReceived, m_rgLastBlock, oldX, m_iBlockSize);
    memcpy(m_rgLastBlock, puIn, m_iBlockSize);
    puIn+= m_iBlockSize;
    m_oAESDec.Decrypt(puIn, oldX);
    inlineXor(m_rguHMACReceived+m_iBlockSize, m_rgLastBlock, oldX, m_iBlockSize);
    memcpy(m_rgLastBlock, puIn, m_iBlockSize);
    puIn+= m_iBlockSize;
#else
    memcpy(m_rguHMACReceived, puIn, SHA256DIGESTBYTESIZE);
#endif

    // depad
    for(residue=maxpadsize-1; residue>=0; residue--) {
        if(m_rguLastBlocks[residue]!=0) {
            if(m_rguLastBlocks[residue]!=0x80) {
                fprintf(g_logFile, "cbc::lastCipherBlockIn: bad pad error, %02x, res: %d size: %d\n",
                       m_rguLastBlocks[residue], residue, size);
                return -1;
            }
            break;
        }
    }
    if(residue<0) {
        fprintf(g_logFile, "cbc::lastCipherBlockIn: CBC bad pad error\n");
        return -1;
    }
#ifdef CRYPTOTEST
    fprintf(g_logFile, "cbc::lastCipherBlockIn, residue: %d\n", residue); 
    fflush(g_logFile);
#endif
    m_iNumPlainBytes+= residue;
    memcpy(puOut, m_rguLastBlocks, residue);
    return residue;
}


// ---------------------------------------------------------------


/*
 *  GCM
 *
 *  H= E_K(0^128)
 *  Y[0]= IV[96]||0^31||1
 *  C[i]= P[i] xor E_K(Y[i-1])  (use MSB ifnot full block)
 *  T= MSB_t(GHASH(H,A,C) xor E_K(Y[0]))
 * 
 *  GHASH(H,A,C) 
 *      X[0]= 0
 *      X[i]= (X[i-1] xor A[i]) x H, i=1,...,m-1
 *      X[m]= (X[m-1] xor A[m-1]||0^(128-v)) x H
 *      X[m+i]= (X[m+i-1] xor C[i]) x H  ,i=1, ...n-1
 *      X[m+n]= (X[m+n-1] xor C[n]||0^(128-u)) x H 
 *      X[m+n+1]= (X[m+n] xor (len(A)||len(C))) x H 
 *      GHASH(H,A,C)= X[m+n+1]
 *
 *      F= x^128+x^7+x^2+x+1
 *
 *  Note: no pad
 */


//
//  Note on GF(2)^n calculations
//
//  Bit position in GF(2) polynomials are as follows
//      If byte array d[0], d[1], ..., d[n-1] represents the poly,
//      f(x)= d[0]_8 + d[0]_7 x + d[0]_6 x^2 + ... + d[0]_1 x^7 + d[1]_8 x^8 +
//            ... + d[n-1]_8 x^(8n-8) + ... + d[n-1]_1 x^(8n-1)
//            
//  For example, the reduction polynomial f(x)= 1+x+x^2+x^7+ ...+ x^128
//      by f[0]= 0xe1= 11100001, f[1]=0, f[2]=0,..., f[14]==, f[15]=0, f[16]= 0x80
//
//  Note that constant term is MSB of first byte!
//      
//  For GCM, n=16 for the polynomials


const byte  F= 0xe1;  // 1110 0001 (0xe1)


byte coeff(byte* rguA, int i, int n)
{
    int     k= i/NBITSINBYTE;                     // coefficient lies in A[k]
    int     m= NBITSINBYTE-1-(i%NBITSINBYTE);      // in bit position shifted m

    if(((rguA[k]>>m)&(0x1))!=0)
        return 1;
    return 0;
}


struct fLoHi {
    byte lo;
    byte hi;
};


struct fLoHi FS[8] = {
    /* FS[0] */ {(byte)(F>>7), (byte)(F<<1)},
    /* FS[1] */ {(byte)(F>>6), (byte)(F<<2)},
    /* FS[2] */ {(byte)(F>>5), (byte)(F<<3)},
    /* FS[3] */ {(byte)(F>>4), (byte)(F<<4)},
    /* FS[4] */ {(byte)(F>>3), (byte)(F<<5)},
    /* FS[5] */ {(byte)(F>>2), (byte)(F<<6)},
    /* FS[6] */ {(byte)(F>>1), (byte)(F<<7)},
    /* FS[7] */ {(byte)(F),    (byte)(0x00)}
};


void shiftmaskF(byte in, byte* poutLo, byte* poutHi)

{
    byte uLo=0;
    byte uHi=0;
    int i;

    for(i=0;i<NBITSINBYTE; i++) {
        if(((in>>i)&0x01)!=0) {
            uLo^= FS[i].lo;
            uHi^= FS[i].hi;
        }
    }
    *poutLo= uLo;
    *poutHi= uHi;
}


void reduceXorF(byte* rguR, int iPos, byte val, int n)
{
    byte    uoutLo, uoutHi;
    int     k= iPos-n;

    shiftmaskF(val, &uoutLo, &uoutHi);
    if(k<n)
        rguR[k]^= uoutLo;
    else
        reduceXorF(rguR, k, uoutLo, n);
    if((k+1)<n)
        rguR[k+1]^= uoutHi;
    else
        reduceXorF(rguR, k+1, uoutHi, n);
}


void shiftXorandFreduce(byte* rguR, byte* rguA, int i, int n) 
{
    int     j;
    int     k= i/NBITSINBYTE;
    int     m= i%NBITSINBYTE;
    int     t;
    byte    x;
    byte    uHi, uLo;

    if(i>NBITSINBYTE*n)      // max shift
        return;

    for(j=0;j<n;j++) {
        t= k+j;
        x= rguA[j];
        uLo= x>>m;
        uHi= x<<(8-m);
        if(t<n) {
            rguR[t]^= uLo;
        }
        else {
            reduceXorF(rguR, t, uLo, n);
        }
        if(t<(n-1)) {
            rguR[t+1]^= uHi;
        }
        else {
            reduceXorF(rguR, t+1, uHi, n);
        }
    }
}


void shiftXor(byte* rguR, byte* rguA, int i, int n) 
//
//  rguR has 2n emtries, rguA has n entries
//      Shift A by i>=0 and xor it into R
//
{
    int     j;
    int     k= i/NBITSINBYTE;
    int     m= i%NBITSINBYTE;
    byte    uHi, uLo;

    if(i>NBITSINBYTE*n)      // max shift
        return;
    for(j=0;j<n;j++) {
        uLo= rguA[j]>>m;
        uHi= rguA[j]<<(8-m);
        rguR[k+j]^= uLo;
        rguR[k+j+1]^= uHi;
    }
}

byte rguD[32];


bool multmodF(byte* rguC, byte* rguA, byte* rguB, int n)
//
//  rguA, rguB and rguC have n entries
//
{
    int     j;

    memset(rguC, 0, n);
    for(j=0;j<NBITSINBYTE*n;j++) {
        if(coeff(rguB, j, n)!=0) {
            shiftXorandFreduce(rguC, rguA, j, n);
        }
    }
    return true;
}

u32 reverseInt(u32 u)
{
    byte  v;
    byte* pu= (byte*) &u;
    
    v= *pu;
    *pu= *(pu+3);
    *(pu+3)= v;
    v= *(pu+1);
    *pu= *(pu+2);
    *(pu+2)= v;
    return u;
}


gcm::gcm()
{
    m_iNumAuthBytes= 0;
    m_iNumPlainBytes= 0;
    m_iNumCipherBytes= 0;
    m_uEncAlg= 0;
    m_uPadAlg= 0;
    m_iBlockSize= 0;
    m_iTagSize= 0;
    m_fHValid= false;
    m_fYValid= false;
    m_rguFirstBlock= NULL;
    m_rguLastBlocks= NULL;
    m_rguH= NULL;
    m_rgFirstY= NULL;
    m_rgLastY= NULL;
    m_rgLastX= NULL;
    m_rgTag= NULL;
    m_rgsentTag= NULL;
}


gcm::~gcm()
{
    if(m_rguFirstBlock!=NULL) {
        free(m_rguFirstBlock);
        m_rguFirstBlock= NULL;
    }
    if(m_rguLastBlocks!=NULL) {
        free(m_rguLastBlocks);
        m_rguLastBlocks= NULL;
    }
    if(m_rguH!=NULL) {
        free(m_rguH);
        m_rguH= NULL;
    }
    if(m_rgLastY!=NULL) {
        free(m_rgLastY);
        m_rgLastY= NULL;
    }
    if(m_rgFirstY!=NULL) {
        free(m_rgFirstY);
        m_rgFirstY= NULL;
    }
    if(m_rgLastX!=NULL) {
        free(m_rgLastX);
        m_rgLastX= NULL;
    }
    if(m_rgTag!=NULL) {
        free(m_rgTag);
        m_rgTag= NULL;
    }
    if(m_rgsentTag!=NULL) {
        free(m_rgsentTag);
        m_rgsentTag= NULL;
    }
   m_oAES.CleanKeys();
}


void gcm::incY()
{
    u32 u= reverseInt(*m_puCtr);
    u++;
    *m_puCtr+= reverseInt(u);
}


bool gcm::computePlainLen()
{
    m_iNumPlainBytes= m_iNumCipherBytes-m_iTagSize-m_iBlockSize;
    return true;
}


bool gcm::computeCipherLen()
{
    m_iNumCipherBytes= m_iNumPlainBytes+m_iBlockSize+m_iTagSize;
    return true;
}


bool gcm::initDec(u32 alg, int keysize, byte* key, int cipherLen, int authLen, int tagLen)
{
#ifdef CRYPTOTEST5
    fprintf(g_logFile, "gcm::initDec\n");
#endif
    m_iNumCipherBytes= cipherLen;
    if(!init(alg, keysize, key, tagLen, authLen))
        return false;
    m_puCtr= (u32*) &m_rgLastY[m_iBlockSize-sizeof(u32)];
    computePlainLen();
#ifdef CRYPTOTEST5
    PrintBytes("H", m_rguH, m_iBlockSize);
#endif
    return true;
}


bool gcm::initEnc(u32 alg, int ivSize, byte* rguIV, int keysize, byte* key, 
                     int plainLen, int authLen, int tagLen)
{
#ifdef CRYPTOTEST
    fprintf(g_logFile, "gcm::initEnc\n");
#endif
    m_iNumPlainBytes= plainLen;
    if(!init(alg, keysize, key, tagLen, authLen))
        return false;
    if(ivSize!=(m_iBlockSize-(int)sizeof(u32)))
        return false;
    if(rguIV!=NULL) {
        memcpy(m_rgLastY, rguIV, m_iBlockSize-sizeof(u32));
        m_puCtr= (u32*) &m_rgLastY[m_iBlockSize-sizeof(u32)];
        *m_puCtr= reverseInt(1);
        memcpy(m_rgFirstY, m_rgLastY, m_iBlockSize);
    }
    computeCipherLen();
    return true;
}


bool gcm::init(u32 alg, int keysize, byte* key, int iTagSize, int authLen)
{
    if(alg!=AES128)
        return false;
    m_uEncAlg= alg;
    m_iBlockSize= 16;
    m_iNumAuthBytes= authLen;
    m_iTagSize= iTagSize;

    m_rguFirstBlock= (byte*) malloc(m_iBlockSize);
    m_rguLastBlocks= (byte*) malloc(4*m_iBlockSize);
    m_rguH = (byte*) malloc(m_iBlockSize);
    m_rgLastY= (byte*) malloc(m_iBlockSize);
    m_rgLastX= (byte*) malloc(m_iBlockSize);
    m_rgFirstY= (byte*) malloc(m_iBlockSize);
    m_rgTag= (byte*) malloc(m_iBlockSize);
    m_rgsentTag= (byte*) malloc(m_iBlockSize);

    if(m_rguFirstBlock==NULL || m_rguLastBlocks==NULL || m_rguH==NULL || 
       m_rgLastX==NULL || m_rgLastY==NULL || m_rgTag==NULL || 
       m_rgFirstY==NULL || m_rgsentTag==NULL)
        return false;

    m_fYValid= true;
    if(m_oAES.KeySetupEnc(key, keysize*NBITSINBYTE)<0) {
        return false;
    }

    memset(m_rguFirstBlock, 0, m_iBlockSize);
    memset(m_rguLastBlocks, 0, m_iBlockSize);
    memset(m_rgLastX, 0, m_iBlockSize);
    m_oAES.Encrypt(m_rgLastX, m_rguH);
    m_fHValid= true;
    return true;
}


bool gcm::finalizeAuth()
// should finalizeCipher first
{
    byte    oldX[MAXAUTHSIZE];
    byte    rguLens[MAXAUTHSIZE];

    memset(rguLens, 0, m_iBlockSize);
    u32* rguLensInt= reinterpret_cast<u32*>(rguLens);
    *rguLensInt= reverseInt(NBITSINBYTE*m_iNumAuthBytes);
    u32* rguLensInt12= reinterpret_cast<u32*>(&rguLens[12]);
    *rguLensInt12= reverseInt(NBITSINBYTE*m_iNumPlainBytes);

    inlineXor(oldX, m_rgLastX, rguLens, m_iBlockSize);
    multmodF(m_rgTag, oldX, m_rguH, 16);
    m_oAES.Encrypt(m_rgFirstY, oldX);
    inlineXorto(m_rgTag, oldX, m_iBlockSize);
    memset(&m_rgTag[m_iTagSize], 0, m_iBlockSize-m_iTagSize);
    return true;
}


int gcm::getTag(int bufSize, byte* puTag)
{
    if(bufSize<m_iTagSize)
        return -1;
    memcpy(puTag, m_rgTag, m_iBlockSize);
    return m_iTagSize;
}


void gcm::nextAuth(byte* puA)
// always full block at a time
{
    byte    oldX[MAXAUTHSIZE];

    inlineXor(oldX, m_rgLastX, puA, m_iBlockSize);
    multmodF(m_rgLastX, oldX, m_rguH, 16);
}


bool gcm::nextPlainBlockIn(byte* puIn, byte* puOut)
{
    byte    oldX[MAXAUTHSIZE];

#ifdef CRYPTOTEST
    PrintBytes("gcm::nextPlainBlockIn, in", puIn, m_iBlockSize);
#endif
    incY();
    m_oAES.Encrypt(m_rgLastY, oldX); 
    inlineXor(puOut, oldX, puIn, m_iBlockSize);
    nextAuth(puOut);
    return true;
}


bool gcm::nextCipherBlockIn(byte* puIn, byte* puOut)
{
    byte    oldX[MAXAUTHSIZE];

    nextAuth(puIn);
    incY();
    m_oAES.Encrypt(m_rgLastY, oldX); 
    inlineXor(puOut, oldX, puIn, m_iBlockSize);
#ifdef CRYPTOTEST
    PrintBytes("gcm::nextCipherBlockIn, out", puOut, m_iBlockSize);
#endif
    return true;
}


bool gcm::firstCipherBlockIn(byte* puIn)
{
#ifdef CRYPTOTEST5
    PrintBytes("gcm::firstCipherBlockIn, in", puIn, m_iBlockSize);
#endif
    memcpy(m_rgLastY, puIn, m_iBlockSize);
    memcpy(m_rguFirstBlock, puIn, m_iBlockSize);
    m_puCtr= (u32*) &m_rgLastY[m_iBlockSize-sizeof(u32)];
    *m_puCtr= reverseInt(1);
    return true;
}


bool gcm::firstCipherBlockOut(byte* puOut)
{
#ifdef CRYPTOTEST
    PrintBytes("gcm::firstCipherBlockout", m_rguFirstBlock, m_iBlockSize);
#endif
    memcpy(puOut, m_rguFirstBlock, m_iBlockSize);
    return true;
}


bool gcm::validateTag()
{
#ifdef CRYPTOTEST5
    PrintBytes("gcm::validateTag, computed", m_rgTag, m_iBlockSize);
    PrintBytes("gcm::validateTag, sent", m_rgsentTag, m_iBlockSize);
#endif
    return isEqual(m_rgTag, m_rgsentTag, m_iBlockSize);
}


int gcm::lastPlainBlockIn(int size, byte* puIn, byte* puOut)
{
    byte    rgLast[32];
    byte    rgOut[32];
    int     iPlainLeft= size;

#ifdef CRYPTOTEST5
    fprintf(g_logFile, "lastPlainBlockIn(%d)\n", size);
    PrintBytes("lastPlainBlockIn", puIn, m_iBlockSize);
#endif
    memcpy(rgLast, puIn, iPlainLeft);
    incY();
    m_oAES.Encrypt(m_rgLastY, rgOut); 
    inlineXor(puOut, rgOut, rgLast, iPlainLeft);
    memset(&puOut[iPlainLeft], 0, m_iBlockSize-iPlainLeft);
    nextAuth(puOut);
    finalizeAuth();
    return iPlainLeft;
}


int gcm::lastCipherBlockIn(int size, byte* puIn, byte* puOut)
// last partial block and tag
//  0 < size <= m_iBlockSize+tagsize
{
    byte    rgLast[32];
    byte    rgOut[32];
    int     iPlainLeft= size-m_iBlockSize;

#ifdef CRYPTOTEST5
    fprintf(g_logFile, "lastCipherBlockIn(%d)\n", size);
    PrintBytes("gcm::lastCipherBlockIn, in", puIn, m_iBlockSize);
#endif
    memset(rgLast, 0, m_iBlockSize);
    memcpy(rgLast, puIn, iPlainLeft);
    nextAuth(rgLast);
    finalizeAuth();
    incY();
    m_oAES.Encrypt(m_rgLastY, rgOut); 
    inlineXor(puOut, rgOut, rgLast, iPlainLeft);

// Fix
    incY();
    m_oAES.Encrypt(m_rgLastY, rgOut); 
    inlineXor(puOut, rgOut, rgLast, iPlainLeft);

    memcpy(m_rgsentTag, puOut, m_iBlockSize);
    return iPlainLeft;
}


// ---------------------------------------------------------------


