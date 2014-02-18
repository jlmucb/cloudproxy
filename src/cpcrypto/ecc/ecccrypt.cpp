//
//  File: ecccrypt.cpp
//  Description: ECC crypto operations
//
//  Copyright (c) 2014, John Manferdelli.  All rights reserved.
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


#include "common.h"
#include "bignum.h"
#include "ecc.h"
#include "mpFunctions.h"
#ifdef TEST
#include "logging.h"
#endif


/*
 * For an ECC system, public key parameters are q,a,b,G,orderG 
 * G is called the base point.
 * pick 1 < secret < orderG, secret is the private key. 
 * Public key is Q = (secret) G. 
 *
 * ECC Encrypt: To encrypt m (already an integer in the right range), map it to a point 
 *  on the curve M , pick 1 < k < p, send (kG, kQ + M ). 
 * ECC Decrypt: Receive (L, K) calculate K − (secret)L = M and map it back to the 
 *      integer message. 
 *
 * ECDSA sign: h= hash bits to sign.  Select k at random, compute kG, Q=kG
 *      r= Qx (mod orderG), s= k^(-1)(h+r(secret)) (mod orderG)
 *    Signature is (r,s). 
 * ECDSA verify: u = s^(−1)h (mod orderG), v = s^(−1)r (mod orderG)
 *  R= uG+vQ.  Valid if Rx=r.
 */



bool ecSign(ECKey& K, bnum& bnH, bnum& bnR, bnum& bnS)
{
    extern bool     getCryptoRandom(i32 numBits, byte* rguBits);
    bnum            bnK(K.m_myCurve->m_bnM->mpSize());
    bnum            bnKInv(K.m_myCurve->m_bnM->mpSize());
    bnum            bnT(K.m_myCurve->m_bnM->mpSize()+1);
    bnum            bnTA(K.m_myCurve->m_bnM->mpSize()+1);
    ECPoint         Q(K.m_myCurve, K.m_myCurve->m_bnM->mpSize());

    // Select k at random, compute kG, Q=kG
    if(!getCryptoRandom(NUMBITSINU64*K.m_myCurve->m_bnM->mpSize(), (byte*)bnK.m_pValue))
        return false;
    bnK.m_pValue[bnK.mpSize()-1]&= 0x7fffffffffffffff;
    if(!ecMult(*K.m_G, bnK, Q))
        return false;
 
    // r= Qx (mod orderG)
    mpMod(*Q.m_bnX, *K.m_myCurve->m_bnorderG, bnR);
    // s= k^(-1)(h+r(secret)) (mod orderG)
    if(!mpModInv(bnK, *K.m_myCurve->m_bnorderG, bnKInv))
        return false;
    mpModMult(bnR, *K.m_secret, *K.m_myCurve->m_bnorderG, bnT);
    mpModAdd(bnT, bnH, *K.m_myCurve->m_bnorderG, bnTA);
    mpModMult(bnTA, bnKInv, *K.m_myCurve->m_bnorderG, bnS);

    return true;
}


bool ecVerify(ECKey& K, bnum& bnH, bnum& bnR, bnum& bnS)
{
    bnum    bnSInv(K.m_myCurve->m_bnM->mpSize());
    bnum    bnU(K.m_myCurve->m_bnM->mpSize()+1);
    bnum    bnV(K.m_myCurve->m_bnM->mpSize()+1);
    ECPoint R(K.m_myCurve, K.m_myCurve->m_bnM->mpSize()+1);
    ECPoint A(K.m_myCurve, K.m_myCurve->m_bnM->mpSize()+1);
    ECPoint B(K.m_myCurve, K.m_myCurve->m_bnM->mpSize()+1);

    // u = s^(−1)h (mod orderG), v = s^(−1)r (mod orderG)
    if(!mpModInv(bnS, *K.m_myCurve->m_bnorderG, bnSInv))
        return false;
    mpModMult(bnSInv, bnH, *K.m_myCurve->m_bnorderG, bnU);
    mpModMult(bnSInv, bnR, *K.m_myCurve->m_bnorderG, bnV);

    // R= uG+vQ.  Valid if Rx=r.
    if(!ecMult(*K.m_G, bnU, A))
        return false;
    if(!ecMult(*K.m_Public, bnV, B))
        return false;
    if(!ecAdd(A, B, R))
        return false;
    return mpCompare(bnR, *R.m_bnX)==0;
}

#ifdef TEST
bool ecSignwithgivennonce(ECKey& K, bnum& bnH, bnum& bnK, bnum& bnR, bnum& bnS)
{
    bnum            bnKInv(K.m_myCurve->m_bnM->mpSize());
    bnum            bnT(K.m_myCurve->m_bnM->mpSize()+1);
    bnum            bnTA(K.m_myCurve->m_bnM->mpSize()+1);
    ECPoint         Q(K.m_myCurve, K.m_myCurve->m_bnM->mpSize());

    if(!ecMult(*K.m_G, bnK, Q))
        return false;
 
    // r= Qx (mod orderG)
    mpMod(*Q.m_bnX, *K.m_myCurve->m_bnorderG, bnR);
    // s= k^(-1)(h+r(secret)) (mod orderG)
    if(!mpModInv(bnK, *K.m_myCurve->m_bnorderG, bnKInv))
        return false;
    mpModMult(bnR, *K.m_secret, *K.m_myCurve->m_bnorderG, bnT);
    mpModAdd(bnT, bnH, *K.m_myCurve->m_bnorderG, bnTA);
    mpModMult(bnTA, bnKInv, *K.m_myCurve->m_bnorderG, bnS);

    return true;
}
#endif


bool ecEncrypt(ECKey& K, bnum& bnX, ECPoint& R1, ECPoint& R2)
{
    extern bool getCryptoRandom(i32 numBits, byte* rguBits);
    bnum  bnK(K.m_myCurve->m_bnM->mpSize());

    // ECC Encrypt: pick 1 < k < p, send (kGen, kBase + M). 
    ECPoint M(K.m_myCurve, K.m_myCurve->m_bnM->mpSize());
    ECPoint P(K.m_myCurve, K.m_myCurve->m_bnM->mpSize()+4);
    ECPoint bnT1(K.m_myCurve, K.m_myCurve->m_bnM->mpSize()+4);

    // embed message
    if(!ecEmbed(K.m_sizejunk, bnX, M))
        return false;
#ifdef TEST
    fprintf(g_logFile, "Embedded point: ");
    M.printMe();
#endif

    if(!getCryptoRandom(NUMBITSINU64*K.m_myCurve->m_bnM->mpSize(), (byte*)bnK.m_pValue))
        return false;
    bnK.m_pValue[bnK.mpSize()-1]&= 0x7fffffffffffffff;
    if(!ecMult(*K.m_G, bnK, R1))
        return false;
    if(!ecMult(*K.m_Public, bnK, bnT1))
        return false;
    if(!ecAdd(bnT1, M, R2))
        return false;
    return true;
}


bool ecDecrypt(ECKey& K, ECPoint& P1, ECPoint& P2, bnum& bnX)
{
    bnum  bnK(K.m_myCurve->m_bnM->mpSize());

    // ECC Decrypt: multiply R1 by secret and subtract it from R2
    // then extract
    ECPoint M(K.m_myCurve, K.m_myCurve->m_bnM->mpSize()+2);
    ECPoint bnT1(K.m_myCurve, K.m_myCurve->m_bnM->mpSize()+4);

    if(!ecMult(P1, *K.m_secret, bnT1))
        return false;
    if(!ecSub(P2, bnT1, M)) {
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "Recovered message point: ");
    M.printMe();
#endif
    if(!ecExtract(K.m_sizejunk, M, bnX))
        return false;
    return true;
}


// ----------------------------------------------------------------------------

