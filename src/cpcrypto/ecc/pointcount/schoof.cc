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
u64*  g_S= NULL;
u64*  g_tl= NULL;

extern const i32 s_iSizeofFirstPrimes;
extern u32 s_rgFirstPrimes[];

bool pickS(bnum& p)
{
  int   j;
  // select primes != p until prod>4(sqrt p)
  return true;
}

// compute t (mod 2)
bool computetmod2(bnum& a, bnum& b, bnum& p, u64* tl)
{
  *tl= 0ULL;
  // if (x^q-x, x^3+ax+b)=1, t=1
  return true;
}

// compute t (mod l)
bool computetmododdprime(bnum& a, bnum& b, bnum& p, u64 l, u64* tl)
{
  i64         pbar
  polynomial  xprime(l,numc, sizenum);
  polynomial  reduced_xprime(l,numc, sizenum);
  polynomial  yprime(l,numc, sizenum);
  i64         t;

  // pbar= p (mod l), |pbar|<l/2
  // compute xprime= (y^(p^2) - y[pbar])/(x^(q^2)-x[pbar]) -x^(q^2)-x[pbar]
  // compute reduced_xprime= xprime (mod phi[l])
  for(t=1; t<=(l-1)/2; t++) {
    // if (reduced_xprime - x[t]^p (mod phi[l]) !=0) continue;
    // if ((yprime-y[t]^p)/y= 0 (mod phi[l]) *tl= t; else *tl= -t; return true
  }
  // were at (d)
  // if p is not a square root mod l, *tl= 0; return true;
  // w= sqrt(p) (mod l)
  // if(gcd(num((y^p-y[w])/y), phi[l])==1) *tl= -2*w; else *tl= 2w; return true;
  return true;
}


bool useCRT(bnum& order)
{
  bnum  m1(1);
  bnum  m2(1);
  bnum  prodprimes(1);
  bnum  crt_soln(1);
  bnum  current_soln(1);
  bnum  current_prime(1);
  bnum  current_prime_solution(1);
  int   j;

  prodprimes.m_pValue[0]= 2ULL;
  current_solution.m_pValue[0]= g_tl[0];

  for(j=1; j<g_sizeS;j++) {
    ZeroNum(current_prime);
    ZeroNum(current_prime_solution);
    ZeroNum(crt_solution);
    ZeroNum(current_prime);
    current_prime.m_pValue[0]= g_S[j];
    current_solution.m_pValue[0]= g_tl[j];
    if(!mpCRT(current_solution, prodprimes, current_prime_solution, current_prime, crt_soln))
      return false;
    // prodprimes*= current_prime;
    // current_solution= crt_soln;
  }
  return true;
}


bool schoof(bnum& a, bnum& p, bnum& p, bnum& order)
{
  int   j;
  i64   pbar;
  bnum  t(order.mpSize());

  // pick primes to use
  if(!pickS(p))
    return false;
  g_tl= new u64 [g_sizeS];

  // make sure division polys have been calculated
  if(!computetmod2(a, b, p, &g_tl[0]))
    return false;
  for(j=1; j<g_sizeS; j++) {
    if(!computetmododdprime(a, b, p, g_S[j], &g_tl[j]))
      return false;
  }
  if(!useCRT(t))
    return false;
  // #E= p+1-t
  ZeroNum(order);
  p.CopyNum(order);
  mpUAddTo(order, g_bnOne);
  mpUSubFrom(order, t);
  return true;
}


// ----------------------------------------------------------------------------
