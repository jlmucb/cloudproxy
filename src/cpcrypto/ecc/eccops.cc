//  Description: ecc operations (add, etc)
//
//  Copyright (c) 2014, John Manferdelli.  all rights reserved.
//
// use, duplication and disclosure of this file and derived works of
// this file are subject to and licensed under the apache license dated
// january, 2004, (the "license").  this license is contained in the
// top level directory originally provided with the cloudproxy project.
// your right to use or distribute this file, or derived works thereof,
// is subject to your being bound by those terms and your use indicates
// consent to those terms.
//
// if you distribute this file (or portions derived therefrom), you must
// include license in or with the file and, in the event you do not include
// the entire license in the file, the file must contain a reference
// to the location of the license.

// ----------------------------------------------------------------------------

#include "common.h"
#include "bignum.h"
#include "ecc.h"
#include "mpFunctions.h"
#ifdef TEST
#include "logging.h"
#endif

ECPoint::ECPoint(ECurve* curve, int size) {
  m_myCurve = curve;
  m_normalized = false;
  m_bnX = new bnum(size);
  m_bnY = new bnum(size);
  m_bnZ = new bnum(size);
}

ECPoint::ECPoint(ECurve* curve) {
  m_myCurve = curve;
  m_normalized = false;
  m_bnX = NULL;
  m_bnY = NULL;
  m_bnZ = NULL;
}

ECPoint::~ECPoint() {
  m_myCurve = NULL;
  m_normalized = false;
  if (m_bnX == NULL) {
    delete m_bnX;
    m_bnX = NULL;
  }
  if (m_bnY == NULL) {
    delete m_bnY;
    m_bnY = NULL;
  }
  if (m_bnZ == NULL) {
    delete m_bnZ;
    m_bnZ = NULL;
  }
}

#ifdef TEST
void ECPoint::printMe() {
  if (m_normalized)
    fprintf(g_logFile, "\nPoint normalized\n");
  else
    fprintf(g_logFile, "\nPoint not normalized\n");
  if (m_myCurve == NULL) fprintf(g_logFile, "No curve set\n");

  fprintf(g_logFile, "X: ");
  printNum(*m_bnX);
  fprintf(g_logFile, "\n");
  fprintf(g_logFile, "Y: ");
  printNum(*m_bnY);
  fprintf(g_logFile, "\n");
  fprintf(g_logFile, "Z: ");
  printNum(*m_bnZ);
  fprintf(g_logFile, "\n");
  return;
}
#endif

ECurve::ECurve() {
  m_bnM = NULL;
  m_bnA = NULL;
  m_bnB = NULL;
  m_bnGx = NULL;
  m_bnGy = NULL;
  m_bnDisc = NULL;
  m_bnorderG = NULL;
}

ECurve::~ECurve() {
  if (m_bnM == NULL) {
    delete m_bnM;
    m_bnM = NULL;
  }
  if (m_bnA == NULL) {
    delete m_bnA;
    m_bnA = NULL;
  }
  if (m_bnB == NULL) {
    delete m_bnB;
    m_bnB = NULL;
  }
  if (m_bnGx == NULL) {
    delete m_bnGx;
    m_bnGx = NULL;
  }
  if (m_bnGy == NULL) {
    delete m_bnGy;
    m_bnGy = NULL;
  }
  if (m_bnDisc == NULL) {
    delete m_bnDisc;
    m_bnDisc = NULL;
  }
  if (m_bnorderG == NULL) {
    delete m_bnorderG;
    m_bnorderG = NULL;
  }
}

#ifdef TEST
void ECurve::printMe() {
  fprintf(g_logFile, "\nCurve\n");
  if (m_bnM != NULL) {
    fprintf(g_logFile, "M: ");
    printNum(*m_bnM);
    fprintf(g_logFile, "\n");
  } else
    fprintf(g_logFile, "M is not set\n");
  if (m_bnA != NULL) {
    fprintf(g_logFile, "A: ");
    printNum(*m_bnA);
    fprintf(g_logFile, "\n");
  } else
    fprintf(g_logFile, "A is not set\n");
  if (m_bnB != NULL) {
    fprintf(g_logFile, "B: ");
    printNum(*m_bnB);
    fprintf(g_logFile, "\n");
  } else
    fprintf(g_logFile, "B is not set\n");
  if (m_bnDisc != NULL) {
    fprintf(g_logFile, "Disc: ");
    printNum(*m_bnDisc);
    fprintf(g_logFile, "\n");
  } else
    fprintf(g_logFile, "Disc is not set\n");
  if (m_bnGx != NULL) {
    fprintf(g_logFile, "Gx: ");
    printNum(*m_bnGx);
    fprintf(g_logFile, "\n");
  } else
    fprintf(g_logFile, "Gx is not set\n");
  if (m_bnGy != NULL) {
    fprintf(g_logFile, "Gy: ");
    printNum(*m_bnGy);
    fprintf(g_logFile, "\n");
  } else
    fprintf(g_logFile, "Gy is not set\n");
}
#endif

bool ECurve::isnonSingular() {
  bnum* disc = discriminant();
  if (disc == NULL || disc->mpIsZero()) return false;
  return true;
}

bool copynumwithalloc(bnum** bn1, bnum& bn2) {
  if (*bn1 == NULL) {
    *bn1 = new bnum(bn2.mpSize());
  }
  if (*bn1 == NULL) return false;
  if ((*bn1)->mpSize() < bn2.mpSize()) {
    delete *bn1;
    *bn1 = new bnum(bn2.mpSize());
  }
  if (*bn1 == NULL) return false;
  int i;
  for (i = 0; i < bn2.mpSize(); i++) (*bn1)->m_pValue[i] = bn2.m_pValue[i];
  for (; i < (*bn1)->mpSize(); i++) (*bn1)->m_pValue[i] = 0ull;
  if ((*bn1)->mpSign() != bn2.mpSign()) (*bn1)->mpNegate();
  return true;
}

bool ECPoint::copyPoint(ECPoint& P) {
  m_normalized = P.m_normalized;
  m_myCurve = P.m_myCurve;
  if (!copynumwithalloc(&m_bnX, *P.m_bnX)) return false;
  if (!copynumwithalloc(&m_bnY, *P.m_bnY)) return false;
  if (!copynumwithalloc(&m_bnZ, *P.m_bnZ)) return false;
  return true;
}

bnum* ECurve::discriminant()
    // −(4a^3+27b^2)
    {
  if (m_bnDisc != NULL) return m_bnDisc;
  if (m_bnM == NULL || m_bnA == NULL || m_bnB == NULL) return NULL;
  m_bnDisc = new bnum(m_bnM->mpSize() + 2);
  bnum bn4(1);
  bnum bn27(1);
  bnum bnT1(m_bnM->mpSize() + 2);
  bnum bnT2(m_bnM->mpSize() + 2);
  bnum bnT3(m_bnM->mpSize() + 2);
  bnum bnT4(m_bnM->mpSize() + 2);
  bn4.m_pValue[0] = 4;
  bn27.m_pValue[0] = 27;

  mpModExp(*m_bnA, g_bnThree, *m_bnM, bnT1);
  mpModMult(bnT1, bn4, *m_bnM, bnT2);
  mpZeroNum(bnT1);
  mpModExp(*m_bnB, g_bnTwo, *m_bnM, bnT2);
  mpModMult(bnT2, bnT3, *m_bnM, bnT4);
  mpZeroNum(bnT3);
  mpModAdd(bnT4, bnT2, *m_bnM, bnT3);
  mpModNormalize(bnT3, *m_bnM);
  mpModSub(*m_bnM, bnT3, *m_bnM, *m_bnDisc);
  mpModNormalize(*m_bnDisc, *m_bnM);
  return m_bnDisc;
}

bool ECPoint::makeZero() {
  if (m_myCurve == NULL || m_bnX == NULL || m_bnY == NULL || m_bnZ == NULL)
    return false;
  mpZeroNum(*m_bnX);
  mpZeroNum(*m_bnY);
  mpZeroNum(*m_bnZ);
  m_bnY->m_pValue[0] = 1ULL;
  m_normalized = true;
  return true;
}

bool ECPoint::iszeroPoint() {
  if (m_myCurve == NULL || m_bnX == NULL || m_bnY == NULL || m_bnZ == NULL)
    return false;
  if (m_bnX->mpIsZero() && m_bnZ->mpIsZero() && mpCompare(*m_bnY, g_bnOne) == 0)
    return true;
  return false;
}

bool ECPoint::isNormalized() { return m_normalized; }

bool ECPoint::normalize() {
  if (m_normalized) return true;
  if (m_myCurve == NULL || m_bnX == NULL || m_bnY == NULL || m_bnZ == NULL)
    return false;
  if (m_bnZ->mpIsZero() && mpCompare(*m_bnZ, g_bnOne) == 0) {
    m_normalized = true;
    return true;
  }

  bnum bnT1(m_myCurve->m_bnM->mpSize() + 2);
  mpModDiv(*m_bnX, *m_bnZ, *(m_myCurve->m_bnM), bnT1);
  mpZeroNum(*m_bnX);
  mpMod(bnT1, *(m_myCurve->m_bnM), *m_bnX);
  mpZeroNum(bnT1);
  mpModDiv(*m_bnY, *m_bnZ, *(m_myCurve->m_bnM), bnT1);
  mpZeroNum(*m_bnY);
  mpMod(bnT1, *(m_myCurve->m_bnM), *m_bnY);
  mpZeroNum(*m_bnZ);
  m_bnZ->m_pValue[0] = 1;
  return true;
}

ECKey::ECKey(ECurve* curve) {
  m_publicValid = false;
  m_privateValid = false;
  m_myCurve = curve;
  m_G = NULL;
  m_Public = NULL;
  m_secret = NULL;
  m_sizejunk = 10;
}

ECKey::~ECKey() {
  m_myCurve = NULL;
  if (m_G == NULL) {
    delete m_G;
    m_G = NULL;
  }
  if (m_Public == NULL) {
    delete m_Public;
    m_Public = NULL;
  }
  if (m_secret == NULL) {
    mpZeroNum(*m_secret);
    delete m_secret;
    m_secret = NULL;
  }
}

#ifdef TEST
void ECKey::printMe() {
  if (m_publicValid)
    fprintf(g_logFile, "\nEKey public key valid\n");
  else
    fprintf(g_logFile, "\nEKey public not valid\n");
  if (m_myCurve == NULL)
    fprintf(g_logFile, "Curve not set\n");
  else
    m_myCurve->printMe();
  fprintf(g_logFile, "sizejunk: %d\n", m_sizejunk);
  if (m_secret != NULL) {
    fprintf(g_logFile, "secret: ");
    printNum(*m_secret);
    fprintf(g_logFile, "\n");
  } else
    fprintf(g_logFile, "secret is not set\n");
  if (m_Public == NULL)
    fprintf(g_logFile, "base not set\n");
  else {
    fprintf(g_logFile, "Base:");
    m_Public->printMe();
  }
  if (m_G == NULL)
    fprintf(g_logFile, "Generator not set\n");
  else {
    fprintf(g_logFile, "Generator:");
    m_G->printMe();
  }
}
#endif

bool ECKey::makePrivateKey() {
  extern bool getCryptoRandom(i32 numBits, byte * rguBits);
  m_secret = new bnum(m_myCurve->m_bnM->mpSize());
  if (!getCryptoRandom(NUMBITSINU64 * m_myCurve->m_bnM->mpSize(),
                       (byte*)m_secret->m_pValue))
    return false;
  m_secret->m_pValue[m_secret->mpSize() - 1] &= 0x7fffffffffffffff;
  m_privateValid = true;
  return true;
}

bool ECKey::getSecret(bnum* secret) {
  secret->mpCopyNum(*m_secret);
  return true;
}

bool ECKey::setGenerator(bnum& Gx, bnum& Gy) {
  m_G = new ECPoint(m_myCurve, m_myCurve->m_bnM->mpSize());
  m_G->m_myCurve = m_myCurve;
  m_G->m_normalized = true;
  Gx.mpCopyNum(*(m_G->m_bnX));
  Gy.mpCopyNum(*(m_G->m_bnY));
  mpZeroNum(*m_G->m_bnZ);
  m_G->m_bnZ->m_pValue[0] = 1ULL;
  return true;
}

bool ECKey::getGenerator(bnum& Gx, bnum& Gy) {
  Gx.mpCopyNum(*m_G->m_bnX);
  Gy.mpCopyNum(*m_G->m_bnY);
  return true;
}

bool ECKey::computePublic() {
  if (!ecMult(*m_G, *m_secret, *m_Public)) return false;
  m_publicValid = true;
  return true;
}

bool ECKey::getPublic(ECPoint& point) {
  point.copyPoint(*m_Public);
  return true;
}

// To calculate R=P+Q.
//      If P or Q is O, the result is obvious.
//      If x(P)!=x(Q), set λ = (y(Q)−y(P))/(x(Q)-x(P)).
//      If x(P)=x(Q) and y(P) = −y(Q), R=O.
//      If x(P) = x(Q) and y(P)!= −y(Q), set λ = (3x(P)^2 + a)/(y(Q) + y(P)).
//      In either case, x(R) = λ^2 − x(P) − x(Q),
//          y(R) =λ(x(P)−x(R))−y(P)  and z(R)= 1.
bool ecAdd(ECPoint& P, ECPoint& Q, ECPoint& R) {
  if (P.m_myCurve == NULL) return false;
  bnum bnL(P.m_myCurve->m_bnM->mpSize() + 4);
  bnum bnT1(P.m_myCurve->m_bnM->mpSize() + 4);
  bnum bnT2(P.m_myCurve->m_bnM->mpSize() + 4);
  bnum bnMQ(P.m_myCurve->m_bnM->mpSize() + 4);

  if (P.iszeroPoint()) {
    R.copyPoint(Q);
    return true;
  }
  if (Q.iszeroPoint()) {
    R.copyPoint(P);
    return true;
  }

  if (mpCompare(*P.m_bnX, *Q.m_bnX) != 0) {
    mpModSub(*P.m_bnY, *Q.m_bnY, *P.m_myCurve->m_bnM, bnT1);
    mpModSub(*P.m_bnX, *Q.m_bnX, *P.m_myCurve->m_bnM, bnT2);
    mpModDiv(bnT1, bnT2, *P.m_myCurve->m_bnM, bnL);
  } else {
    mpModSub(*P.m_myCurve->m_bnM, *Q.m_bnY, *P.m_myCurve->m_bnM, bnMQ);
    mpModNormalize(bnMQ, *P.m_myCurve->m_bnM);
    if (mpCompare(*P.m_bnY, bnMQ) == 0) {
      R.makeZero();
      return true;
    }
    mpModMult(*P.m_bnX, *P.m_bnX, *P.m_myCurve->m_bnM, bnT1);
    mpModMult(bnT1, g_bnThree, *P.m_myCurve->m_bnM, bnT2);
    mpZeroNum(bnT1);
    mpModAdd(bnT2, *P.m_myCurve->m_bnA, *P.m_myCurve->m_bnM, bnT1);
    mpZeroNum(bnT2);
    mpModAdd(*P.m_bnY, *P.m_bnY, *P.m_myCurve->m_bnM, bnT2);
    mpModDiv(bnT1, bnT2, *P.m_myCurve->m_bnM, bnL);
  }
  mpZeroNum(bnT1);
  mpZeroNum(bnT2);
  mpZeroNum(*R.m_bnZ);
  R.m_bnZ->m_pValue[0] = 1ULL;
  R.m_normalized = true;
  mpZeroNum(bnT1);
  mpZeroNum(bnT2);
  // In either case, x(R) = λ^2 − x(P) − x(Q),
  mpModMult(bnL, bnL, *P.m_myCurve->m_bnM, bnT1);
  mpModSub(bnT1, *P.m_bnX, *P.m_myCurve->m_bnM, bnT2);
  mpModSub(bnT2, *Q.m_bnX, *P.m_myCurve->m_bnM, *R.m_bnX);
  // y(R) =λ(x(P)−x(R))−y(P)  and z(R)= 1.
  mpZeroNum(bnT1);
  mpZeroNum(bnT2);
  mpModSub(*P.m_bnX, *R.m_bnX, *P.m_myCurve->m_bnM, bnT1);
  mpModMult(bnL, bnT1, *P.m_myCurve->m_bnM, bnT2);
  mpModSub(bnT2, *P.m_bnY, *P.m_myCurve->m_bnM, *R.m_bnY);
  return true;
}

bool ecSub(ECPoint& P, ECPoint& Q, ECPoint& R) {
  ECPoint bnT1(P.m_myCurve, P.m_myCurve->m_bnM->mpSize() + 4);

  if (!ecInv(Q, bnT1)) {
    return false;
  }
  if (!ecAdd(P, bnT1, R)) {
    return false;
  }
  return true;
}

bool ecInv(ECPoint& P, ECPoint& R) {
  if (P.iszeroPoint()) {
    R.copyPoint(P);
    return true;
  }
  R.m_normalized = P.isNormalized();
  R.m_myCurve = P.m_myCurve;
  R.m_bnX = P.m_bnX;
  R.m_bnZ = P.m_bnZ;
  mpModSub(*(P.m_myCurve->m_bnM), *(P.m_bnY), *(P.m_myCurve->m_bnM),
           *(R.m_bnY));
  mpModNormalize(*R.m_bnY, *R.m_myCurve->m_bnM);
  return true;
}

bool ecMult(ECPoint& P, bnum& bnA, ECPoint& R) {
  ECPoint currentDouble(P.m_myCurve, P.m_myCurve->m_bnM->mpSize() + 2);
  ECPoint newDouble(P.m_myCurve, P.m_myCurve->m_bnM->mpSize() + 2);
  ECPoint currentAcc(P.m_myCurve, P.m_myCurve->m_bnM->mpSize() + 2);
  ECPoint newAcc(P.m_myCurve, P.m_myCurve->m_bnM->mpSize() + 2);

  // copy P to currentDouble
  // currentDouble.copyPoint(P);
  currentDouble.copyPoint(P);
  // zero Acc
  currentAcc.makeZero();

  int i;
  int n = mpBitsinNum(bnA.mpSize(), bnA.m_pValue) + 1;
#ifdef TEST1
  printf("high bit: %d\ncurrentacc: ", n - 1);
  currentAcc.printMe();
  printf("currentDouble: ");
  currentDouble.printMe();
#endif

  for (i = 0; i < n; i++) {
    if (IsBitPositionNonZero(bnA, i + 1)) {
      ecAdd(currentDouble, currentAcc, newAcc);
#ifdef TEST1
      printf("adding bit position %d\n", i + 1);
      currentAcc.printMe();
      printf("currentDouble: ");
      currentDouble.printMe();
      printf("newAcc: ");
      newAcc.printMe();
#endif
      currentAcc.copyPoint(newAcc);
      newAcc.makeZero();
    }
    if (i != n) {
      ecAdd(currentDouble, currentDouble, newDouble);
      currentDouble.copyPoint(newDouble);
    }
  }
  R.copyPoint(currentAcc);
  return true;
}

// calculate x^3+ax+b (mod p)
bool ecEvaluatePoint(ECurve& C, bnum& bnX, bnum& Y2) {
  bnum bnT1(C.m_bnM->mpSize() + 2);
  bnum bnT2(C.m_bnM->mpSize() + 2);
  bnum bnT3(C.m_bnM->mpSize() + 2);

  if (!mpModExp(bnX, g_bnThree, *C.m_bnM, bnT1)) {
    return false;
  }
  if (!mpModMult(*C.m_bnA, bnX, *C.m_bnM, bnT2)) {
    return false;
  }
  if (!mpModAdd(bnT1, bnT2, *C.m_bnM, bnT3)) {
    return false;
  }
  if (!mpModAdd(*C.m_bnB, bnT3, *C.m_bnM, Y2)) {
    return false;
  }
  return true;
}

/*
 *  Here is a way to embed integers in curves: 
 *      For q = pr, odd, select parameter κ so that the probability of failure
 *  is 2^(−κ); m is message and 0≤m<M,q>κM and x=mκ+j∈Fq 
 *  For the first j for which x^3 + ax + b is a square, use the corresponding 
 *  point P = (x, √x). 
 */
bool ecEmbed(int sizejunk, bnum& bnX, ECPoint& R) {
  int i;
  int n = 1 << sizejunk;
  bnum bnT1(R.m_myCurve->m_bnM->mpSize() + 2);
  bnum bnT2(R.m_myCurve->m_bnM->mpSize() + 2);
  u64 a = 0ULL;

  bnX.mpCopyNum(bnT1);
  mpUSingleMultBy(bnT1, (u64)n);
  a = bnT1.m_pValue[0];
  for (i = 0; i < n; i++) {
    bnT1.m_pValue[0] = a | ((u64)i);
    if (!ecEvaluatePoint(*R.m_myCurve, bnT1, bnT2)) {
      return false;
    }
    if (!mpModisSquare(bnT2, *(R.m_myCurve->m_bnM))) {
      mpInc(bnT1);
      mpZeroNum(bnT2);
      continue;
    }
    bnT1.mpCopyNum(*R.m_bnX);
#ifdef TEST
    fprintf(g_logFile, "Evaluated point:");
    printNum(bnT2);
    fprintf(g_logFile, "\n");
#endif
    mpZeroNum(*R.m_bnZ);
    R.m_bnZ->m_pValue[0] = 1ULL;
    return mpModSquareRoot(bnT2, *(R.m_myCurve->m_bnM), *R.m_bnY);
  }
  return false;
}

bool ecExtract(int sizejunk, ECPoint& P, bnum& bnX) {
  u64 a = 1ULL << sizejunk;
  u64 b = 0ULL;
  bnum t(P.m_myCurve->m_bnM->mpSize());
  bnum Y1(2 * P.m_myCurve->m_bnM->mpSize() + 4);
  bnum Y2(P.m_myCurve->m_bnM->mpSize() + 4);

#ifdef TEST1
  fprintf(g_logFile, "exExtract\nX: ");
  printNum(*P.m_bnX);
  fprintf(g_logFile, "\nY:");
  printNum(*P.m_bnY);
  fprintf(g_logFile, "\nP: ");
  printNum(*(P.m_myCurve->m_bnM));
  fprintf(g_logFile, "\n");
#endif

  if (!mpModMult(*P.m_bnY, *P.m_bnY, *(P.m_myCurve->m_bnM), Y1)) {
    fprintf(g_logFile, "mpModMult failed\n");
    return false;
  }
  if (!ecEvaluatePoint(*P.m_myCurve, *P.m_bnX, Y2)) {
    return false;
  }
  if (mpCompare(Y1, Y2) != 0) {
    fprintf(g_logFile, "ecExtract: point not on curve\n");
    fprintf(g_logFile, "Y1: ");
    printNum(Y1);
    fprintf(g_logFile, "\nY2:");
    printNum(Y2);
    fprintf(g_logFile, "\n");
    return false;
  }

  mpSingleUDiv(*P.m_bnX, a, t, &b, false);
  t.mpCopyNum(bnX);
  return true;
}

// ----------------------------------------------------------------------------

//
