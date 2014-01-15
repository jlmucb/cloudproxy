//
//  File: nist.h:
//  Description: nist curves
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


#include "jlmTypes.h"
#include "bignum.h"
#include "ecc.h"
#include "mpFunctions.h"


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
 *  fE(u1P + u2Q) = r.
 *
 *  NIST Curves: Use prime fields Fp with p = 2^192 −2^64 −1, 
 *        p= 2^224 −2^96 +1, p= 2^256 −2^224 +2^192 +2^96 −1, 
 *        p= 2^384 −2^128 − 2^96+2^32−1, or p= 2^521−1.
 *
 *
 *  P-256
 *  y^2=x^3-3x+b
 *
 *  p256 = ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff ffffffff
 *  The parameter a = p256 − 3:
 *  a = ffffffff 00000001 00000000 00000000 00000000 ffffffff ffffffff fffffffc
 *  b = 5ac635d8 aa3a93e7 b3ebbd55 769886bc 651d06b0 cc53b0f6 3bce3c3e 27d2604b
 *  xG = 6b17d1f2 e12c4247 f8bce6e5 63a440f2 77037d81 2deb33a0 f4a13945 d898c296
 *  yG = 4fe342e2 fe1a7f9b 8ee7eb4a 7c0f9e16 2bce3357 6b315ece cbb64068 37bf51f5
 *  orderG= ffffffff 00000000 ffffffff ffffffff bce6faad a7179e84 f3b9cac2 fc632551
 *   =115792089210356248762697446949407573529996955224135760342 422259061068512044369
 *
 *  P-521
 *  p= 686479766013060971498190079908139321726943530014330540939 
 *     446345918554318339765605212255964066145455497729631139148 
 *     0858037121987999716643812574028291115057151 
 *  n= 686479766013060971498190079908139321726943530014330540939 
 *     446345918554318339765539424505774633321719753296399637136 
 *     3321113864768612440380340372808892707005449
 *
 * Seed= d09e8800 291cb853 96cc6717 393284aa a0da64ba 
 * c= 0b4 8bfa5f42 0a349495 39d2bdfc 264eeeeb 4fbf0ad8 f6d0edb3 
 *        7bd6b533 28100051 8e19f1b9 ed8a3c22 00b8f875 e523868c 
 *        70c1e5bf 55bad637 
 *
 * b= 051 953eb961 8e1c9a1f 929a21a0 b68540ee 99b315f3 b8b48991 8ef109e1 
 *        56193951 ec7e937b 3bb1bf07 3573df88 3d2c34f1 ef451fd4 6b503f00
 * Gx= c6 858e06b7 0404e9cd 9e3ecb66 2395b442 9c648139 053fb521 f828af60 
 *        6b4d3dba a14b5e77 efe75928 a2ffa8de 3348b3c1 856a429b f97e7e31 
 *        c2e5bd66 
 *
 * Gy= 118 39296a78 9a3bc004 5c8a5fb4 2c7d1bd9 579b4468 17afbd17 273e662c 
 *         97ee7299 5ef42640 3fad0761 353c7086 a272c240 88be9476 9fd16650
 */


// ----------------------------------------------------------------------------


bool    nistinitialized= false;

ECurve  nist256curve;
u64 tempp256[4] = {
                0xffffffff00000001ULL, 0x0000000000000000ULL, 0x00000000ffffffffULL,
                0xffffffffffffffffULL
                  };
u64 tempa256[4] = {
                0xffffffff00000001ULL, 0x0000000000000000ULL, 0x00000000ffffffffULL, 
                0xfffffffffffffffcULL
              };
u64 tempb256[4]=  {
                0x5ac635d8aa3a93e7ULL, 0xb3ebbd55769886bcULL, 0x651d06b0cc53b0f6ULL,
                0x3bce3c3e27d2604bULL
              };
u64 tempGx256[4]= {
                0x6b17d1f2e12c4247ULL, 0xf8bce6e563a440f2ULL, 0x77037d812deb33a0ULL,
                0xf4a13945d898c296ULL
              };
u64 tempGy256[4]= {
                0x4fe342e2fe1a7f9bULL, 0x8ee7eb4a7c0f9e16ULL, 0x2bce33576b315eceULL,
                0xcbb6406837bf51f5ULL
              };

u64 temporderG256[4]= {
                0xffffffff00000000ULL, 0xffffffffffffffffULL, 0xbce6faada7179e84ULL, 
                0xf3b9cac2fc632551ULL
    };

ECurve  nist521curve;


// p= 2^256 −2^224 +2^192 +2^96 −1
bool initNist()
{
    int i;

    if(nistinitialized)
        return true;
    nist256curve.m_bnM= new bnum(4);
    for(i=0;i<4; i++)
        nist256curve.m_bnM->m_pValue[i]= tempp256[3-i];
    nist256curve.m_bnA= new bnum(4);
    for(i=0;i<4; i++)
        nist256curve.m_bnA->m_pValue[i]= tempa256[3-i];
    nist256curve.m_bnB= new bnum(4);
    for(i=0;i<4; i++)
        nist256curve.m_bnB->m_pValue[i]= tempb256[3-i];
    nist256curve.m_bnGx= new bnum(4);
    for(i=0;i<4; i++)
        nist256curve.m_bnGx->m_pValue[i]= tempGx256[3-i];
    nist256curve.m_bnGy= new bnum(4);
    for(i=0;i<4; i++)
        nist256curve.m_bnGy->m_pValue[i]= tempGy256[3-i];
    nist256curve.m_bnorderG= new bnum(4);
    for(i=0;i<4; i++)
        nist256curve.m_bnorderG->m_pValue[i]= temporderG256[3-i];

    nist256curve.discriminant();
    nistinitialized= true;
    return true;
}


// ----------------------------------------------------------------------------

