//
//  File: divpolys.cc
//  Description: calculate the division polynomials mod p
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


#include "common.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "polyarith.h"
#include "stdio.h"

//
// phi[0]= 0
// phi[1]= 1
// phi[2]= 2y
// phi[3]=  3x^4+6ax+12bx-a^2
// phi[4]= 4y(x^6+5ax^4+20bx^3-5a^2x^2-4abx-8b^2-a^3
// phi[2m+1]= phi[m+2]phi^3[m]-phi[m-1]phi^3[m+1]
// phi[2m]= phi[m]/phi[2](phi[m+2]phi^2[m-1]-phi[m-2]phi^2[m+1])
// theta[m]= x phi^2[m]-phi[m+1]phi[m-1]
// omega[m]= (phi[m]/(2 phi[2]) (phi[m+2] phi[m-1]-phi[m-2] phi^2[m+1])


int             g_maxcoeff= -1;   // max coeff calculated
polynomial**    g_phi2= NULL;     // polynomial in x

// note that the real division polynomial, g_phi, is
//  g_phi[m]= g_phi2[m], if m is odd, and
//  g_phi[m]= (2y)g_phi2[m], if m is even.
//  From now on, the 2y is implicit during the calculation for even m
//  elsewhere, we assume a coefficient of y (not 2y) on
//  these so, at the end, we multiply through by 2


#define JLMDEBUG

// ----------------------------------------------------------------------------


bool evenphirecurrence(int m, polynomial& curve_x_poly);
bool oddphirecurrence(int m, polynomial& curve_x_poly);
typedef polynomial* p_polynomial_t;


bool Initphi(int max, polynomial& curve_x_poly) {
#ifdef JLMDEBUG
  printf("In Initphi(%d)\n", max);
#endif
  if(max<5) {
    printf("Initphi too few polys to be computed\n");
    return false;
  }

  int   n= curve_x_poly.characteristic_->mpSize();
  bnum* a= curve_x_poly.c_array_[1];
  bnum* b= curve_x_poly.c_array_[0];
  bnum* p= curve_x_poly.characteristic_;

  bnum  r(2*n);
  bnum  s(2*n);
  bnum  t(2*n);

  g_phi2= (polynomial**) new p_polynomial_t[max+1];

  // phi[0]= 0
  g_phi2[0]= new polynomial(*p, 1, 1); 
  g_phi2[0]->c_array_[0]->m_pValue[0]= 0ULL;

  // phi[1]= 1
  g_phi2[1]= new polynomial(*p, 1, 1); 
  g_phi2[1]->c_array_[0]->m_pValue[0]= 1ULL;

  // phi[2]= 2y
  // phi2[2]= 1;
  g_phi2[2]= new polynomial(*p, 1, 1); 
  g_phi2[2]->c_array_[0]->m_pValue[0]= 1ULL;

  // phi[3]=  3x^4+6ax^2+12bx-a^2
  // Fix: size depends on a, b and p
  g_phi2[3]= new polynomial(*p, 5, 1); 
  g_phi2[3]->c_array_[4]->m_pValue[0]= 3ULL;
  g_phi2[3]->c_array_[3]->m_pValue[0]= 0ULL;
  mpZeroNum(t);
  t.m_pValue[0]= 6ULL;
  mpModMult(t,*a,*p,*(g_phi2[3]->c_array_[2]));
  mpZeroNum(t);
  t.m_pValue[0]= 12ULL;
  mpModMult(t,*b,*p,*(g_phi2[3]->c_array_[1]));
  mpZeroNum(s);
  mpModMult(*a,*a,*p,s);
  mpModSub(g_bnZero,s,*p,*(g_phi2[3]->c_array_[0]));

  // phi[4]= 2y(2(x^6+5ax^4+20bx^3-5a^2x^2-4abx-8b^2-a^3))
  // Fix: size depends on a, b and p
  g_phi2[4]= new polynomial(*p, 7, 1); 

  g_phi2[4]->c_array_[6]->m_pValue[0]= 1ULL;     // x^6
  g_phi2[4]->c_array_[5]->m_pValue[0]= 0ULL;
  mpZeroNum(t);
  t.m_pValue[0]= 5ULL;
  mpModMult(t,*a,*p,*(g_phi2[4]->c_array_[4]));    // 5ax^4
  mpZeroNum(t);
  t.m_pValue[0]= 20ULL;
  mpModMult(t,*b,*p,*(g_phi2[4]->c_array_[3]));    // 20bx^3
  mpZeroNum(r);
  mpZeroNum(t);
  mpZeroNum(s);
  s.m_pValue[0]= 5ULL;
  mpModMult(*a,*a,*p,t);
  mpModMult(s,t,*p,r);
  mpModSub(g_bnZero,r,*p,*(g_phi2[4]->c_array_[2])); // -5a^2x^2
  mpZeroNum(r);
  mpZeroNum(t);
  mpZeroNum(s);
  mpModMult(*a,*b,*p,t);
  s.m_pValue[0]= 4ULL;
  mpModMult(t,s,*p,r);
  mpModSub(g_bnZero,r,*p,*(g_phi2[4]->c_array_[1])); // -4abx
  mpZeroNum(r);
  mpZeroNum(s);
  mpZeroNum(t);
  mpModMult(*b,*b,*p,t);
  s.m_pValue[0]= 8ULL;
  mpModMult(t,s,*p,r);                             // 8b^2
  mpZeroNum(s);
  mpZeroNum(t);
  mpModMult(*a,*a,*p,s);
  mpModMult(s,*a,*p,t);                             // a^3
  mpZeroNum(s);
  mpModAdd(r,t,*p,s);                              // 8b^2+a^3
  mpModSub(g_bnZero,s,*p,(*g_phi2[4]->c_array_[0])); // -8b^2-a^3
  mpZeroNum(s);
  s.m_pValue[0]= 2ULL;
  g_phi2[4]->MultiplyByNum(s);

  int i;
  if(!oddphirecurrence(2, curve_x_poly)) {
    printf("oddphirecurrence(%d) failed\n", 2);
    return false;
  }
  for(i=3; i<=(max-1)/2; i+=2) {
    if(!evenphirecurrence(i, curve_x_poly)) {
      printf("evenphirecurrence(%d) failed\n", i);
      return false;
    }
    if(!oddphirecurrence(i, curve_x_poly)) {
      printf("oddphirecurrence(%d) failed\n", i);
      return false;
    }
  }

  s.m_pValue[0]= 2ULL;
  for(i=2; i<=max/2; i+=2)
    g_phi2[i]->MultiplyByNum(s); // assumed coefficient henceforth is y not 2y
  g_maxcoeff= max+1;
  return true;
}

void Freephi() {
  int i;
  for(i=0; i<g_maxcoeff; i++) {
    delete g_phi2[i];
    g_phi2[i]= NULL;
  }
  g_maxcoeff= -1;
}

extern bool EccSymbolicAdd(polynomial& curve_x_poly, 
                           polynomial& in1x, polynomial& in1y,
                           polynomial& in2x, polynomial& in2y, 
                           polynomial& outx, polynomial& outy);
extern bool EccSymbolicPointMult(polynomial& curve_x_poly, i64 t, 
                           polynomial& inx, polynomial& iny, 
                           polynomial& outx, polynomial& outy);

// calculate phi2[2m+1]
//  phi2[2m+1]= phi2[m+2]phi2^3[m]-phi2[m-1]phi2^3[m+1]
//  phi[2m+1]= phi1[m]
bool oddphirecurrence(int m, polynomial& curve_x_poly) {
  bnum*       p= curve_x_poly.characteristic_;
  int         n= p->mpSize();
  polynomial  r(*p,(2*m+1)*(2*m+1), n);
  polynomial  s(*p,(2*m+1)*(2*m+1), n);
  polynomial  t(*p,(2*m+1)*(2*m+1), n);
  polynomial  v(*p,(2*m+1)*(2*m+1), n);

#ifdef JLMDEBUG
  printf("oddrecurrence(%d), n= %d\n", m, n);
#endif
#ifdef JLMDEBUG1
  printf("oddrecurrence, g_phi2[%d]\n", m); printpoly(*g_phi2[m]);
  printf("oddrecurrence, g_phi2[%d]\n", m+2); printpoly(*g_phi2[m+2]);
  printf("oddrecurrence, g_phi2[%d]\n", m-1); printpoly(*g_phi2[m-1]);
  printf("oddrecurrence, g_phi2[%d]\n", m+1); printpoly(*g_phi2[m+1]);
#endif
  g_phi2[2*m+1]= new polynomial(*p, (2*m+1)*(2*m+1),n);

  r.ZeroPoly();
  s.ZeroPoly();
  t.ZeroPoly();
  if(!PolyMult(*g_phi2[m+2], *g_phi2[m], t))
    return false;
  if(!PolyMult(t, *g_phi2[m], s))
    return false;
  if(!PolyMult(s, *g_phi2[m], r))
    return false;
  // r now has the product phi2[m+2]*phi2^3[m]

  v.ZeroPoly();
  t.ZeroPoly();
  s.ZeroPoly();
  if(!PolyMult(*g_phi2[m-1], *g_phi2[m+1], s))
    return false;
  if(!PolyMult(s, *g_phi2[m+1], t))
    return false;
  if(!PolyMult(t, *g_phi2[m+1], v))
    return false;
  // v now has the product phi2[m-1]*phi2^3[m+1]
 
  if(!PolySub(r, v, *g_phi2[2*m+1]))
    return false;
  return true;
}

// calculate phi2[2m]
//    phi2[2m]= phi2[m](phi2[m+2]phi2^2[m-1]-phi2[m-2]phi2^2[m+1])
//    phi[2m]=phi2[2m]/(2y)
bool evenphirecurrence(int m, polynomial& curve_x_poly) {
  bnum*       p= curve_x_poly.characteristic_;
  int         n= p->mpSize();
  polynomial  r(*p,(2*m)*(2*m), n);
  polynomial  s(*p,(2*m)*(2*m), n);
  polynomial  t(*p,(2*m)*(2*m), n);
  polynomial  v(*p,(2*m)*(2*m), n);

#ifdef JLMDEBUG
  printf("evenrecurrence(%d), n= %d\n", m, n);
#endif
#ifdef JLMDEBUG1
  printf("evenrecurrence, g_phi2[%d]\n", m); printpoly(*g_phi2[m]);
  printf("evenrecurrence, g_phi2[%d]\n", m+2); printpoly(*g_phi2[m+2]);
  printf("evenrecurrence, g_phi2[%d]\n", m-1); printpoly(*g_phi2[m-1]);
  printf("evenrecurrence, g_phi2[%d]\n", m+1); printpoly(*g_phi2[m+1]);
  printf("evenrecurrence, g_phi2[%d]\n", m-2); printpoly(*g_phi2[m-2]);
#endif
  g_phi2[2*m]= new polynomial(*p, (2*m)*(2*m), n);

  if(!PolyMult(*g_phi2[m+2], *g_phi2[m-1], t))
    return false;
  if(!PolyMult(t, *g_phi2[m-1], s))
    return false;
  if(!PolyMult(s, *g_phi2[m], r))
    return false;
  // r now has the product phi2[m]*phi2[m+2]phi2^2[m-1]

  t.ZeroPoly();
  s.ZeroPoly();
  if(!PolyMult(*g_phi2[m-2], *g_phi2[m+1], t))
    return false;
  if(!PolyMult(t, *g_phi2[m+1], s))
    return false;
  if(!PolyMult(s, *g_phi2[m], v))
    return false;
  // v now has has the product phi2[m]*phi[m-2]*phi^2[m+1]

  if(!PolySub(r, v, *g_phi2[2*m]))
    return false;
  return true;
}


void printdivpoly(int m) {
  extern void printpoly(polynomial&);
  if(m>=g_maxcoeff) {
    printf("%d is invalid index, %d div polys calculated\n", m, g_maxcoeff);
    return;
  }
  if((m%2)==1)
    printf("divpoly(%d): ");
  else
    printf("divpoly(%d): (2y) ");
  printpoly(*g_phi2[m]);
  printf("\n");
}

// ----------------------------------------------------------------------------
