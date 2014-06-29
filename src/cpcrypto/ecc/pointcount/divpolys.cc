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


int           g_maxcoeff= -1;   // max coeff calculated
polynomial**  g_phi= NULL;      // x poly 
bnum**        g_coeff_y= NULL;  // coefficient of y factor
i16*          g_exp_y= NULL;    // exponent of y


// ----------------------------------------------------------------------------


bool evenphirecurrence(int m, bnum& a, bnum& b, bnum& p);
bool oddphirecurrence(int m, bnum& a, bnum& b, bnum& p);


bool initphicalc(int max, bnum& p, int maxnum, bnum& a, bnum& b) {
  if(max<5)
    return false;

  int n= p.mpSize();
  int j= a.mpSize();
  if(j>n)
    n= j;
  j= b.mpSize();
  if(j>n)
    n= j;

  bnum  r(2*n);
  bnum  s(2*n);
  bnum  t(2*n);

  g_phi= new polynomial* [max+1];
  g_coeff_y= new bnum* [max+1];
  g_exp_y= new i16[max+1];

  // phi[0]= 0
  g_phi[0]= new polynomial(p, 1, 1); 
  g_phi[0]->c_array_[0]->m_pValue[0]= 0ULL;
  g_exp_y[0]= 0;
  g_coeff_y[0]= new bnum(1);
  g_coeff_y[0]->m_pValue[0]= 1ULL;

  // phi[1]= 1
  g_phi[1]= new polynomial(p, 1, 1); 
  g_phi[1]->c_array_[0]->m_pValue[0]= 1ULL;
  g_exp_y[1]= 0;
  g_coeff_y[1]= new bnum(1);
  g_coeff_y[1]->m_pValue[0]= 0ULL;

  // phi[2]= 2y
  g_phi[2]= new polynomial(p, 1, 1); 
  g_phi[2]->c_array_[0]->m_pValue[0]= 1ULL;
  g_exp_y[2]= 1;
  g_coeff_y[2]= new bnum(1);
  g_coeff_y[2]->m_pValue[0]= 2ULL;

  // phi[3]=  3x^4+6ax^2+12bx-a^2
  // Fix: size depends on a, b and p
  g_phi[3]= new polynomial(p, 5, 1); 
  g_coeff_y[3]= new bnum(1);
  g_coeff_y[3]->m_pValue[0]= 1ULL;
  g_exp_y[3]= 0;
  g_phi[3]->c_array_[4]->m_pValue[0]= 3ULL;
  g_phi[3]->c_array_[3]->m_pValue[0]= 0ULL;
  mpZeroNum(t);
  t.m_pValue[0]= 6ULL;
  mpModMult(t,a,p,*(g_phi[3]->c_array_[2]));
  mpZeroNum(t);
  t.m_pValue[0]= 12ULL;
  mpModMult(t,b,p,*(g_phi[3]->c_array_[1]));
  mpZeroNum(s);
  mpModMult(a,a,p,s);
  mpModSub(g_bnZero,s,p,*(g_phi[4]->c_array_[0]));

  // phi[4]= 4y(x^6+5ax^4+20bx^3-5a^2x^2-4abx-8b^2-a^3
  // Fix: size depends on a, b and p
  g_phi[4]= new polynomial(p, 7, 1); 
  g_coeff_y[4]= new bnum(1);
  g_coeff_y[4]->m_pValue[0]= 4ULL;
  g_exp_y[4]= 1;

  g_phi[4]->c_array_[6]->m_pValue[0]= 1ULL;     // x^6
  g_phi[4]->c_array_[5]->m_pValue[0]= 0ULL;
  mpZeroNum(t);
  t.m_pValue[0]= 5ULL;
  mpModMult(t,a,p,*(g_phi[4]->c_array_[4]));    // 5ax^4
  mpZeroNum(t);
  t.m_pValue[0]= 20ULL;
  mpModMult(t,b,p,*(g_phi[4]->c_array_[3]));    // 20bx^3
  mpZeroNum(r);
  mpZeroNum(t);
  mpZeroNum(s);
  s.m_pValue[0]= 5ULL;
  mpModMult(a,a,p,t);
  mpModMult(s,t,p,r);
  mpModSub(g_bnZero,r,p,*(g_phi[4]->c_array_[2])); // -5a^2x^2
  mpZeroNum(r);
  mpZeroNum(t);
  mpZeroNum(s);
  mpModMult(a,b,p,t);
  s.m_pValue[0]= 4ULL;
  mpModMult(t,s,p,r);
  mpModSub(g_bnZero,r,p,*(g_phi[4]->c_array_[1])); // -4abx
  mpZeroNum(r);
  mpZeroNum(s);
  mpZeroNum(t);
  mpModMult(b,b,p,t);
  s.m_pValue[0]= 8ULL;
  mpModMult(t,s,p,r);                             // 8b^2
  mpZeroNum(s);
  mpZeroNum(t);
  mpModMult(a,a,p,s);
  mpModMult(s,a,p,t);                             // a^3
  mpZeroNum(s);
  mpModAdd(r,t,p,s);                              // 8b^2+a^3
  mpModSub(g_bnZero,s,p,(*g_phi[4]->c_array_[0])); // -8b^2-a^3

  int i;
  oddphirecurrence(2, a, b, p);
  for(i=3; i+=2;i<=(max-1)/2) {
    if(!evenphirecurrence(i, a, b, p))
      return false;
    if(!oddphirecurrence(i, a, b, p))
      return false;
  }
  g_maxcoeff= max;
  return true;
}

// calculate phi[2m+1]
// phi[2m+1]= phi[m+2]phi^3[m]-phi[m-1]phi^3[m+1]
bool oddphirecurrence(int m, bnum& a, bnum& b, bnum& p) {
  polynomial r(p,(2*m+1)*(2*m+1), 2*p.mpSize());
  polynomial s(p,(2*m+1)*(2*m+1), 2*p.mpSize());
  polynomial t(p,(2*m+1)*(2*m+1), 2*p.mpSize());

  r.ZeroPoly();
  s.ZeroPoly();
  t.ZeroPoly();
  if(!PolyMult(*g_phi[m+2], *g_phi[m], t))
    return false;
  if(!PolyMult(t, *g_phi[m], s))
    return false;
  t.ZeroPoly();
  if(!PolyMult(s, *g_phi[m], t))
    return false;
  // t now has phi[m+2]phi^3[m]
  r.ZeroPoly();
  s.ZeroPoly();
  if(!PolyMult(*g_phi[m-1], *g_phi[m+1], s))
    return false;
  if(!PolyMult(s, *g_phi[m+1], r))
    return false;
  s.ZeroPoly();
  if(!PolyMult(r, *g_phi[m+1], s))
    return false;
  // s now has phi[m-1]phi^3[m+1]
  if(!PolySub(t, s, *g_phi[2*m+1]))
    return false;

  // FIX: dont forget y coeff and exponent
  g_exp_y[2*m+1]= 0;
  g_coeff_y[2*m+1]= new bnum(1);
  g_coeff_y[2*m+1]->m_pValue[0]= 1ULL;
  return true;
}

// calculate phi[2m]
// phi[2m]= phi[m]/phi[2](phi[m+2]phi^2[m-1]-phi[m-2]phi^2[m+1])
bool evenphirecurrence(int m, bnum& a, bnum& b, bnum& p) {
  polynomial r(p,(2*m+1)*(2*m+1), 2*p.mpSize());
  polynomial s(p,(2*m+1)*(2*m+1), 2*p.mpSize());
  polynomial t(p,(2*m+1)*(2*m+1), 2*p.mpSize());

  r.ZeroPoly();
  s.ZeroPoly();
  r.ZeroPoly();
  if(!PolyMult(*g_phi[m+2], *g_phi[m-1], t))
    return false;
  if(!PolyMult(t, *g_phi[m-1], r))
    return false;
  // r now has phi[m+2]phi^2[m-1]
  t.ZeroPoly();
  s.ZeroPoly();
  if(!PolyMult(*g_phi[m-2], *g_phi[m+1], s))
    return false;
  if(!PolyMult(s, *g_phi[m+1], t))
    return false;
  // t now has phi[m-2]phi^2[m+1]
  s.ZeroPoly();
  if(!PolySub(r, t, s))
    return false;
  // s now has (phi[m+2]phi^2[m-1]-phi[m-2]phi^2[m+1])
  r.ZeroPoly();
  if(!PolyMult(s, *g_phi[m], r))
    return false;
  // r now has phi[m](phi[m+2]phi^2[m-1]-phi[m-2]phi^2[m+1])
  // divide by 2y=phi[2]
  t.ZeroPoly();

  // FIX: dont forget y coeff and exponent
  g_exp_y[2*m+1]= 0;
  g_coeff_y[2*m+1]= new bnum(1);
  g_coeff_y[2*m+1]->m_pValue[0]= 1ULL;
  return true;
}


// ----------------------------------------------------------------------------
