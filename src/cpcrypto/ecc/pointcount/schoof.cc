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

#if 0
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
  i64         pbar;
  polynomial  xprime(l,numc, sizenum);;
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
#endif


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
#if 0
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

  // pick primes to use
  if(!pickS(p))
    return false;
#if 0
  g_tl= new u64 [g_sizeS];
  i64   pbar;
  int   j;
  // make sure division polys have been calculated
  if(!computetmod2(a, b, p, &g_tl[0]))
    return false;
  for(j=1; j<g_sizeS; j++) {
    if(!computetmododdprime(a, b, p, g_S[j], &g_tl[j]))
      return false;
  }
#endif
  if(!useCRT(t))
    return false;
  // #E= p+1-t
  mpZeroNum(order);
  p.mpCopyNum(order);
  mpUAddTo(order, g_bnOne);
  mpUSubFrom(order, t);
  return true;
}


// ----------------------------------------------------------------------------
