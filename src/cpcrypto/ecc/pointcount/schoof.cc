//
//  File: schoof.cc
//  Description: ECC point counting using schoof
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
#include "polyarith.h"
#include "stdio.h"

// ----------------------------------------------------------------------------

/*
 *  0. Precompute division polynomials
 *  1. Pick S= {p[1], ..., p[k]: p[1]*p[2}*...*p[k]>4(q^(1/4)), q not in S
 *  2. for p[1]=2, d=0 (2) iff (x^3+ax+b, x^q-x)= 1
 *  3. for each odd l in S
 *    3a. 
 *      q[l]= q (mod l), |q[l]|<l/2
 *    3b. 
 *      Compute (x', y')= (x^(q^2), y^(q^2)) + q[l] (x,y)
 *    3c. for j= 1,2,...(l-1)/2
 *      3c(i).  Compute x[j], (x[j], y[j])= j(x,y)
 *      3c(ii). If (x'-x[j]^q)= 0 (mod phi[l](x)), goto iii
 *              If not, try next j; if all tried, goto 3d
 *      3c(iii). Compute y' and y[j].  If (y'-y[j])/y= 0 (mod (phi[l](x))
 *                                  then d= j (mod l), if not
 *                                       d= -j (mod l)
 *    3d. Let w^2= q (mod l).  If no such w, d=0 (mod l)
 *    3e. If (gcd(numerator(x^q-x[w]), phi[l](x))= 1, d= 0 (mod l)
 *          otherwise, compute (gcd(numerator(y^q-y[w]), phi[l](x))
 *           if this is 1, d= 2w (mod l), otherwise, d= -2w (mod l)
 *  4. User CRT to compute d, #E(q)= q+1-d, with d in right range for Hasse
 */

int   g_sizeS= 0;
u64   g_S[512];
u64   g_tl[512];

const i32 sizeofFirstPrimes= 512;
extern u32 s_rgFirstPrimes[];

// select primes != p until prod>4(sqrt p)
bool pickS(bnum& p)
{
  int   j;
  bnum  v(2*p.mpSize());
  bnum  w(2*p.mpSize());
  bnum  prod(2*p.mpSize());
  bnum  top(2*p.mpSize());
  u64   nextprime;

  if(!SquareRoot(p, v))
    return false;
  mpUAddTo(v, g_bnOne);
  mpMult(v, g_bnTwo, w);
  mpMult(w, g_bnTwo, top);
  prod.m_pValue[0]= 1ULL;
  for(j=0;j<sizeofFirstPrimes;j++) {
    nextprime= (u64)s_rgFirstPrimes[j];
    mpZeroNum(v);
    mpZeroNum(w);
    v.m_pValue[0]= nextprime;
    mpMult(prod,v, w);
    w.mpCopyNum(prod);
    g_S[g_sizeS++]= nextprime;
    if(mpCompare(prod, top)!=s_isLessThan)
      break;
  }
  return true;
}

// return p_bar= p (mod l), |pbar|<l/2
i64 Reducedp(bnum& p, u64 l) {
  return 0;
}

bool eccMultPoint(polynomial& curve_x_poly, i64 t, polynomial& x_bar, polynomial& y_bar) {
  return true;
}

// compute t (mod 2)
bool computetmod2(polynomial& curve_x_poly, u64* tl)
{
  int         j;
  bnum*       p= curve_x_poly.characteristic_;
  polynomial  result(*p,4,p->mpSize());

  *tl= 1ULL;
  if(!Reducelargepower(*p, curve_x_poly, result))
    return false;
  for(j=1;j<result.numc_;j++) {
    if(mpCompare(*(result.c_array_[j]), g_bnZero) != s_isEqualTo) {
      *tl= 0ULL;
      return true;
    }
  }
  return true;
}

// compute t (mod l)
bool computetmododdprime(polynomial& curve_x_poly, u64 l, u64* tl)
{
  u64           j;
  i64           p_bar= Reducedp(*curve_x_poly.characteristic_, l);
  int           n= curve_x_poly.characteristic_->mpSize();
  rationalpoly  x_prime(*curve_x_poly.characteristic_, 5, n, 5, n);
  rationalpoly  y_prime(*curve_x_poly.characteristic_, 5, n, 5, n);
  polynomial    reduced_x_p_squared(*curve_x_poly.characteristic_, 5, n);
  polynomial    reduced_y_p_squared(*curve_x_poly.characteristic_, 5, n);
  polynomial    reduced_x_j_squared(*curve_x_poly.characteristic_, 5, n);
  polynomial    reduced_y_j_squared(*curve_x_poly.characteristic_, 5, n);
  polynomial    x_p_bar(*curve_x_poly.characteristic_, 5, n);
  polynomial    y_p_bar(*curve_x_poly.characteristic_, 5, n);
  polynomial    x_j(*curve_x_poly.characteristic_, 5, n);
  polynomial    y_j(*curve_x_poly.characteristic_, 5, n);
  bnum          p_squared(2*n+1);
  bnum          small_num(1);
  bnum          w(n);  // square root of p

  mpMult(*curve_x_poly.characteristic_, *curve_x_poly.characteristic_, p_squared);
  if(!Reducelargepower(p_squared, curve_x_poly, reduced_x_p_squared))
     return false;

  // Define j(x,y)= (x_j,y_j)
  //    Compute (x_p_bar, y_p_bar)
  if(!eccMultPoint(curve_x_poly, p_bar, x_p_bar, y_p_bar))
    return false;

  //    Compute x_prime= (y^(p^2) - y_p_bar)/(x^(p^2)-x_p_bar]) -x^(p^2)-x_p_bar, reduced by curve
  //    Compute y_prime

  for(j=1; j<=(l-1)/2; j++) {
    // compute j(x,y)= (x_j,y_j)
    if(!eccMultPoint(curve_x_poly, j, x_j, y_j))
      return false;
    small_num.m_pValue[0]= j;
    if(!Reducelargepower(small_num, curve_x_poly, reduced_x_j_squared))
      return false;
    // if(x_prime-x_j^p != 0 (mod phi[l]) continue;
    // compute test= (y_prime-y_j)/y (mod phi[l])
    // if test==0 *tl= j; else *tl= -j;
    *tl= j;
    return true;
  }

  // we're at (d)
  small_num.m_pValue[0]= l;
  if(!mpModisSquare(*curve_x_poly.characteristic_, small_num)) {
    *tl= 0;
    return true;
  }
  if(!mpModSquareRoot(*curve_x_poly.characteristic_, small_num, w))
    return false;
  u64  small_w= w.m_pValue[0];
  // if(gcd(num((y^p-y[w])/y), phi[l])==1) *tl= -2*w; else *tl= 2w;
  *tl= 2*small_w;
  return true;
}


bool useCRT(bnum& t)
{
  int   j;
  bnum  v(2*t.mpSize());
  bnum  crt_solution(2*t.mpSize());
  bnum  current_solution(2*t.mpSize());
  bnum  current_prime(2*t.mpSize());
  bnum  current_prime_solution(2*t.mpSize());
  bnum  prodprimes(2*t.mpSize());

  prodprimes.m_pValue[0]= 2ULL;
  current_solution.m_pValue[0]= g_tl[0];
  for(j=1; j<g_sizeS;j++) {
    mpZeroNum(current_prime);
    mpZeroNum(current_prime_solution);
    mpZeroNum(crt_solution);
    mpZeroNum(current_prime);
    current_prime.m_pValue[0]= g_S[j];
    current_prime_solution.m_pValue[0]= g_tl[j];
    if(!mpCRT(current_solution, prodprimes, current_prime_solution, current_prime, crt_solution))
      return false;
#ifdef JLMDEBUG
    printf("current solution ");printNumberToConsole(current_solution); printf(", ");
    printf("prodprimes ");printNumberToConsole(prodprimes); printf("\n");
    printf("current prime ");printNumberToConsole(current_prime); printf(", ");
    printf("current prime solution ");printNumberToConsole(current_prime_solution); printf(", ");
    printf("crt solution (%lld, %lld) ", g_S[j], g_tl[j]);
      printNumberToConsole(crt_solution); printf("\n");
#endif
    mpZeroNum(current_solution);
    crt_solution.mpCopyNum(current_solution);
    mpZeroNum(v);
    mpMult(prodprimes, current_prime, v);
    mpZeroNum(prodprimes);
    v.mpCopyNum(prodprimes);
  }
  current_solution.mpCopyNum(t);
  return true;
}


bool schoof(bnum& a, bnum& b, bnum& p, bnum& order)
{
  bnum  t(order.mpSize());
  bnum  s(order.mpSize());
  int   n= p.mpSize();
  polynomial curve_x_poly(p, 4, n);

  // pick primes to use
  if(!pickS(p))
    return false;
  curve_x_poly.c_array_[3]->m_pValue[0]= 1ULL;
  curve_x_poly.c_array_[2]->m_pValue[0]= 0ULL;
  a.mpCopyNum(*curve_x_poly.c_array_[1]);
  b.mpCopyNum(*curve_x_poly.c_array_[0]);

  int   j;
  // make sure division polys have been calculated
  if(!computetmod2(curve_x_poly, &g_tl[0]))
    return false;
  for(j=1; j<g_sizeS; j++) {
    if(!computetmododdprime(curve_x_poly, g_S[j], &g_tl[j]))
      return false;
  }
  if(!useCRT(t))
    return false;
  // #E= p+1-t
  mpZeroNum(order);
  p.mpCopyNum(s);
  mpUAddTo(s, g_bnOne);
  mpSub(s, t, order);
  return true;
}


// ----------------------------------------------------------------------------
