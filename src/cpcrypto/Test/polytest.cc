//
//  File: polytest.cc
//  Description: polynomial test
//
//  Copyright (c) John Manferdelli.  All rights reserved.
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <iostream>

#include "common.h"
#include "logging.h"
#include "polyarith.h"
#include "ecc.h"
using namespace std;


extern bool schoof(bnum& a, bnum& b, bnum& p, bnum& order);
extern void SymbolicTest(u64 test_prime, u64 test_a, u64 test_b);


// ----------------------------------------------------------------------------


extern bool pickS(bnum& p);
extern int   g_sizeS;
extern u64  g_S[];
extern u64  g_tl[];
extern bool useCRT(bnum& t);


int main(int an, char** av) {
  bnum  p(2);
  p.m_pValue[0]= 47ULL;

  initBigNum();
  initLog(NULL);

  polynomial   x_poly(p,2,1);
  x_poly.c_array_[1]->m_pValue[0]= 1ULL;

  polynomial*  pp1= new polynomial(p, 5, 4);
  polynomial*  pp2= new polynomial(p, 5, 4);
  polynomial*  pp3= new polynomial(p, 5, 4);
  polynomial*  pa= new polynomial(p, 5, 4);
  polynomial*  pb= new polynomial(p, 5, 4);
  polynomial*  pc= new polynomial(p, 5, 4);
  polynomial*  pd= new polynomial(p, 5, 4);
  polynomial*  pg= new polynomial(p, 5, 4);
  polynomial*  pq= new polynomial(p, 5, 4);
  polynomial*  pr= new polynomial(p, 5, 4);

  pp1->c_array_[0]->m_pValue[0]= 2;
  pp1->c_array_[1]->m_pValue[0]= 7;
  pp2->c_array_[0]->m_pValue[0]= 13;
  pp2->c_array_[1]->m_pValue[0]= 6;
  printf("polytest\n");

  printf("pp1, "); printpoly(*pp1);
  printf("pp2, "); printpoly(*pp2);
  pp3->ZeroPoly();
  printf("\npp1+pp2= ");
  if(!PolyAdd(*pp1, *pp2, *pp3))
     printf("PolyMult returns false\n");
  else
    printpoly(*pp3);
  pp3->ZeroPoly();
  printf("\npp1-pp2= ");
  if(!PolySub(*pp1, *pp2, *pp3))
     printf("PolyMult returns false\n");
  else
    printpoly(*pp3);
  pp3->ZeroPoly();
  printf("\npp1*pp2= ");
  if(!PolyMult(*pp1, *pp2, *pp3))
     printf("PolyMult returns false\n");
  else
    printpoly(*pp3);

  pa->c_array_[0]->m_pValue[0]= 1;
  pa->c_array_[1]->m_pValue[0]= 2;
  pa->c_array_[2]->m_pValue[0]= 1;
  pb->c_array_[0]->m_pValue[0]= 46;
  pb->c_array_[1]->m_pValue[0]= 1;

  printf("\nPolyEuclid\n");
  printf("a, "); printpoly(*pa);
  printf("b, "); printpoly(*pb);

  if(!PolyEuclid(*pa, *pb, *pq, *pr)) {
    printf("PolyEuclid returns false\n");
  } else {
    printf("PolyEuclid returns\n");
    printf("q, "); printpoly(*pq);
    printf("r, "); printpoly(*pr);
  }

  printf("\nPolyExtendedgcd\n");
  if(!PolyExtendedgcd(*pa, *pb, *pc, *pd, *pg)) {
    printf("PolyExtendedgcd returns false\n");
  } else {
    printf("PolyExtendedgcd returns\n");
    printpoly(*pa);printf(" * ");
    printpoly(*pc);printf(" + ");
    printpoly(*pb);printf(" * ");
    printpoly(*pd);printf(" = ");
    printpoly(*pg);printf("\n");
  }

  bnum  s(2);
  bnum  res(2);
  int   k= 6;
  u64   t[6]= {49, 48, 35, 1, 0, 6};
  int   i;
 
  for(i=0; i<k; i++) { 
    s.m_pValue[0]= t[i];
    if(!SquareRoot(s, res)) {
      printf("SquareRoot returns false\n");
    }
    else {
      printf("Sqrt of ");
      printNumberToConsole(s);
      printf(" is ");
      printNumberToConsole(res);
      printf("\n\n");
    }
  }

  polynomial  x(p, 5, 8);
  polynomial  q(p, 5, 8);
  polynomial  mod_poly(p, 5, 8);
  polynomial  result(p, 5, 8);
  bnum        power(5);

  mod_poly.ZeroPoly();
  power.m_pValue[0]= 1ULL;
  mod_poly.c_array_[0]->m_pValue[0]= 1ULL;
  mod_poly.c_array_[1]->m_pValue[0]= 1ULL;
  x.c_array_[1]->m_pValue[0]= 1ULL;

  if(!PolyEuclid(x, mod_poly, q, result)) {
    printf("PolyEuclid returns false\n");
  } else {
    printf("PolyEuclid returns\n");
    printpoly(x); printf(" = "); 
    printpoly(mod_poly); printf(" * "); 
    printpoly(q); printf(" + "); 
    printpoly(result); printf("\n"); 
  }
  result.ZeroPoly();

  u64   v[6]= {0, 1, 2, 3, 4, 5};
  k= 6;
  for(i=0; i<k;i++) {
    power.m_pValue[0]= v[i];
    result.ZeroPoly();
    if(!Reducelargepower(power, x_poly, mod_poly, result)) {
        printf("Reducelargepower returns false\n");
    }
    else {
        printf("x** ");printNumberToConsole(power);printf("\n");
        printf(" mod "  ); printpoly(mod_poly);
        printf(" = "); printpoly(result); printf("\n");
    }
  }

  printf("ECC counting\n");
  mpZeroNum(p);
  p.m_pValue[0]= 3671;
  printf("Prime "); printNumberToConsole(p); printf("\n");
  if(!pickS(p)) {
    printf("can't pick primes for ");
    printNumberToConsole(p);
    printf("\n");
    return 0;
  }
  printf("pickS got %d primes\n\t", g_sizeS);
  for(i=0; i<g_sizeS;i++)
    printf("%lld, ", g_S[i]);
  printf("\n");
  for(i=0;i<g_sizeS;i++)
    g_tl[i]= g_S[i]-1;
  bnum	solution(2);
  if(!useCRT(solution)) {
    printf("can't solve CRT\n");
    return 1;
  }
  printf("tl's\n\t");
  for(i=0; i<g_sizeS;i++)
    printf("%lld, ", g_tl[i]);
  printf("\n");

  printf("CRT solution is ");
  printNumberToConsole(solution);
  printf("\n");

  SymbolicTest(97ULL, 46ULL, 74ULL);

  printf("\n\n");
  printf("bsgs tests\n");
  // y^2= x^3+ 46x + 74 (mod 97)
  ECurve  curve;
  bnum	  a(2);
  bnum	  b(2);
  bnum	  c(2);
  bnum    ecp(2);
  bnum	  order(10);
  bnum	  X(2);
  bnum	  Y(2);
  bnum	  Z(2);

  a.m_pValue[0]= 46ULL;
  b.m_pValue[0]= 74ULL;
  ecp.m_pValue[0]= 97ULL;
  curve.m_bnM= &ecp;
  curve.m_bnA= &a;
  curve.m_bnB= &b;
  printf("curve:\n");
  curve.printMe(true);
  ECPoint   P(&curve, 2);
  ECPoint   R(&curve, 2);
  P.makeZero();
  printf("\nP:");
  P.printMe();

  P.m_bnX->m_pValue[0]= 6ULL;
  P.m_bnY->m_pValue[0]= 9ULL;
  P.m_bnZ->m_pValue[0]= 1ULL;

  c.m_pValue[0]= 0ULL;
  if(!ecMult(P, c, R)) {
    printf("ecMult failed\n");
    return 1;
  }
  printf("\n%lldP is", c.m_pValue[0]);
  R.printMe();

  c.m_pValue[0]= 80ULL;
  if(!ecMult(P, c, R)) {
    printf("ecMult failed\n");
    return 1;
  }
  P.printMe();
  printf("\n%lldP is", c.m_pValue[0]);
  R.printMe();

  extern bool eccbsgspointorder(ECPoint&, bnum&);
  if(!eccbsgspointorder(P, order)) {
    printf("eccbsgspointorder failed\n");
    return 1;
  }
  printf("order of P is ");
  printNumberToConsole(order);
  printf("\n");

  mpZeroNum(order);
  printf("\nschoof\n");
  if(!schoof(a, b, ecp, order)) {
    printf("schoof failed\n");
    return 1;
  }
  return 0;
}

// ---------------------------------------------------------------------------
