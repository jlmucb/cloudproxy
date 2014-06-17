
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
using namespace std;



// ----------------------------------------------------------------------------


int main(int an, char** av) {
  bnum  p(2);
  p.m_pValue[0]= 47ULL;

  initBigNum();
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

  u64   v[6]= {0, 1, 2, 3, 4,5};
  k= 6;
  for(i=0; i<k;i++) {
    power.m_pValue[0]= v[i];
    result.ZeroPoly();
    if(!Reducelargepower(power, mod_poly, result)) {
        printf("Reducelargepower returns false\n");
    }
    else {
        printf("x** ");printNumberToConsole(power);printf("\n");
        printf(" mod "  ); printpoly(mod_poly);
        printf(" = "); printpoly(result); printf("\n");
    }
  }

  return 0;
}

// ---------------------------------------------------------------------------
