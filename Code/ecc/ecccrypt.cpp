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


#include "jlmTypes.h"
#include "bignum.h"
#include "ecc.h"
#ifdef TEST
#include "logging.h"
#endif


/*
 * ECDSA: For an ECC system, public key parameters are q,a,b,P (P is called the base point); 
 * pick 1 < x < p, x is the private key. Public key is Q = xP. 
 * ECC Encrypt: To encrypt m (already an integer in the right range), map it to a point 
 *  on the curve PM , pick 1 < k < p, send (kP, kQ + PM ). 
 *  ECC Decrypt: Receive (L, M ) calculate M − xL = PM and map it back to the 
 *      integer message. 
 *
 *  ECDSA sign: Select k at random, compute kP,r = fE(kP),s = k−1(H(M)+xr). 
 *    Signature is (r,s). ECDSA verify: u1 = s^(−1)H(M),u2 = s^(−1)r, accept if 
 */

bool ecSign(ECurve& C, ECKey& K,bnum& bnX, ECPoint& R)
{
    return false;
}


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
    if(!ecMult(*K.m_generator, bnK, R1))
        return false;
    if(!ecMult(*K.m_base, bnK, bnT1))
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

