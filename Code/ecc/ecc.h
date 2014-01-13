//
//  File: ecc.h:
//  Description: ECC algs
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


#ifndef _ECC_H
#define _ECC_H


#include "jlmTypes.h"
#include "bignum.h"


//  Curve in Weirestrauss form y^2= x^3+ax+b (mod m)
//  m is prime (no GF(2) curves)
class ECurve {
public:
    bnum*   m_bnM;
    bnum*   m_bnA;
    bnum*   m_bnB;
    bnum*   m_bnDisc;
    bnum*   m_bnGx;
    bnum*   m_bnGy;

    ECurve();
    ~ECurve();

#ifdef TEST
    void printMe();
#endif

    bool    isnonSingular();
    bnum*   discriminant();
};


// Point in projective coordinates usually normalized
// O=(0:1:0) and −(X:Y:Z)=(X:−Y :Z).
class ECPoint {
public:
    bool    m_normalized;
    ECurve* m_myCurve;
    bnum*   m_bnX;
    bnum*   m_bnY;
    bnum*   m_bnZ;

    ECPoint(ECurve* curve, int size);
    ECPoint(ECurve* curve);
    ~ECPoint();

#ifdef TEST
    void printMe();
#endif

    bool    makeZero();
    bool    copyPoint(ECPoint& P);
    bool    iszeroPoint();
    bool    normalize();
    bool    isNormalized();
};


class  ECKey {
public:
    bool      m_publicValid;
    bool      m_privateValid;
    int       m_sizejunk;

    ECurve*   m_myCurve;
    ECPoint*  m_generator;
    ECPoint*  m_base;
    bnum*     m_secret;

    ECKey(ECurve* curve);
    ~ECKey();

#ifdef TEST
    void printMe();
#endif

    bool makePrivateKey();
    bool getSecret(bnum *secret);
    bool setGenerator(bnum& Gx, bnum& Gy);
    bool getGenerator(bnum& Gx, bnum& Gy);
    bool computePublic();
    bool getPublic(ECPoint& point);
};


bool ecAdd(ECPoint& P, ECPoint& Q, ECPoint& R);
bool ecSub(ECPoint& P, ECPoint& Q, ECPoint& R);
bool ecInv(ECPoint& P, ECPoint& R);
bool ecMult(ECPoint& P, bnum& bnA, ECPoint& R);
bool ecEvaluatePoint(ECurve& C, bnum& bnX, bnum& Y2);

bool ecEmbed(int sizejunk, bnum& bnX, ECPoint& R);
bool ecExtract(int sizejunk, ECPoint& R, bnum& bnX);

bool ecSign(ECKey& K,bnum& bnX, ECPoint& R);
bool ecVerify(ECKey& K,bnum& bnX, ECPoint& R);

bool ecEncrypt(ECKey& K,bnum& bnX, ECPoint& R1, ECPoint& R2);
bool ecDecrypt(ECKey& K,ECPoint& P1, ECPoint& P2, bnum& bnX);


#endif    // _ECC_H


// ----------------------------------------------------------------------------

