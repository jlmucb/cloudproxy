//
//  File: schoof.cc
//  Description: ECC point counting using schoof
//
//  Copyright (c) 2014, John Manferdelli.  All rights reserved.
//  Portions Copyright (c) 2014, Intel Corporation.  All rights reserved.
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
 *  2. for p[1]=2, t=0 (2) iff (x^3+ax+b, x^q-x)= 1
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
 *                                  then t= j (mod l), if not
 *                                       t= -j (mod l)
 *    3d. Let w^2= q (mod l).  If no such w, t=0 (mod l)
 *    3e. If (gcd(numerator(x^q-x[w]), phi[l](x))= 1, t= 0 (mod l)
 *          otherwise, compute (gcd(numerator(y^q-y[w]), phi[l](x))
 *           if this is 1, t= 2w (mod l), otherwise, t= -2w (mod l)
 *  4. User CRT to compute t, #E(q)= q+1-t, with t in right range for Hasse
 */

int   g_sizeS= 0;
u64   g_S[512];
u64   g_tl[512];

const i32           sizeofFirstPrimes= 512;
extern u32          s_rgFirstPrimes[];
extern int          g_maxcoeff;
extern polynomial** g_phi2;

extern bool Initphi(int max, polynomial& curve_x_poly);
extern void Freephi();
extern bool Reducelargepower(bnum&, polynomial&, polynomial&);

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

// return x=p (mod l), |x|<l/2
i64 Reducedp(bnum& p, u64 l) {
  bnum  small_num(1);
  bnum  big_num(p.mpSize());

  // note assumption that l (and hence t below) fits in 64 bits
  small_num.m_pValue[0]= l;
  mpMod(p, small_num, big_num);
  i64   x= (i64) big_num.m_pValue[0];
  if(x>=(i64)(l/2))
    x= (i64)l-x;
  return x;
}


//  In the symbolic computations, we assume P=(r(x), yq(x)) but that the 
//  y is surpressed in the representation of the point as a polynomial 
//  (r1(x), r2(x)).  r(x) and q(x) are ratio's of polynomials.
//  Our data type for these ratios is rationalpoly.
//  Surpressing the y in the representationof points saves us
//  from having to do multi-variate polynomial caclulations.  
//  We have to be careful, however, in the calculations to
//  remember the implicit y.

//  In the calculation for addition, in1x, in2x, in1y and in2y
//  are all rationalpolys.  P= (in1x, y in1y) and Q=(in2x, y in2y).
//  m= y ((in2y-in1y)/(in2x-in1x) and so
//  m^2= y^2 ((in2y-in1y)/(in2x-in1x))^2 = 
//    curve_x_poly((in2y-in1y)/(in2x-in1x))^2.
//  P+Q= (outx, y outy), where 
//    outx= m^2-in1x-in2x,  and
//    outy= ((in2y-in1y)/(in2x-in1x))(in1x-outx) - in1y.
//  This is sort of confusing but that's the way it is.
bool EccSymbolicAdd(polynomial& curve_x_poly, 
                    rationalpoly& in1x, rationalpoly& in1y,
                    rationalpoly& in2x, rationalpoly& in2y, 
                    rationalpoly& outx, rationalpoly& outy) {
  bnum*         p= curve_x_poly.characteristic_;
  int           n= p->mpSize();
  rationalpoly  s1(*p, 5, n, 5, n);
  rationalpoly  s2(*p, 5, n, 5, n);
  rationalpoly  s3(*p, 5, n, 5, n);
  rationalpoly  slope(*p, 5, n, 5, n);
  rationalpoly  slope_squared(*p, 5, n, 5, n);
  rationalpoly  curve_rational(*p, 5, n, 5, n);

  if(RationalisEqual(in1x, in2x) &&
     RationalisEqual(in1y, in2y)) {
    // slope= (3x[1]^2+a)/(2curve_x_poly), remember implicit y
    s1.numerator->c_array_[0]->m_pValue[0]= 3ULL;
    s1.denominator->c_array_[0]->m_pValue[0]= 2ULL;
    curve_rational.numerator->Copyfrom(curve_x_poly);
    curve_rational.denominator->c_array_[0]->m_pValue[0]= 1ULL;
    if(!RationalMult(in1x, in1x, s2))
      return false;
    if(!RationalMult(s2, s1, s3))
      return false;
    s1.ZeroRational();
    s2.ZeroRational();
    // a as a rational function
    s1.numerator->c_array_[0]->mpCopyNum(*curve_x_poly.c_array_[1]); //a
    s1.denominator->c_array_[0]->m_pValue[0]= 1ULL;
    if(!RationalAdd(s3, s1, s2))
      return false;
    s1.ZeroRational();
    s3.ZeroRational();
    if(!RationalDiv(s2, curve_rational, slope))
      return false;
  }
  else {
    // slope= (in2y-in1y)/(in2x-in1x), remember implicit y
    if(!RationalSub(in2x, in1x, s1))
      return false;
    if(!RationalSub(in2y, in1y, s2))
      return false;
    if(!RationalDiv(s2, s1, slope))
      return false;
  }
  if(!RationalReduce(slope))
    return false;
  s1.ZeroRational();
  s2.ZeroRational();
  s3.ZeroRational();
  if(!RationalMult(slope, slope, s1))
    return false;
  if(!RationalMult(s1, curve_rational, slope_squared))
    return false;
  if(!RationalReduce(slope_squared))
    return false;

  //  outx= slope_squared-in1x-in2x
  if(!RationalSub(slope_squared, in1x, s2))
    return false;
  if(!RationalSub(s2, in2x, outx))
    return false;
  
  //  outy= m(x[1]-x[3])-y[1]
  s1.ZeroRational();
  s2.ZeroRational();
  s3.ZeroRational();
  if(!RationalSub(in1x, outx, s1))
    return false;
  if(!RationalReduce(outx))
    return false;
  if(!RationalMult(slope, s1, s2))
    return false;
  if(!RationalSub(s2, in1y, outy))
    return false;
  if(!RationalReduce(outy))
    return false;
  return true;
}

bool EccSymbolicSub(polynomial& curve_x_poly, 
                    rationalpoly& in1x, rationalpoly& in1y,
                    rationalpoly& in2x, rationalpoly& in2y, 
                    rationalpoly& outx, rationalpoly& outy) {
  bnum*         p= curve_x_poly.characteristic_;
  int           n= p->mpSize();
  rationalpoly  s1(*p, in2y.numerator->numc_, n, in2y.denominator->numc_, n);
  int           i;
  bnum*         bn1;
  bnum*         bn2;

  s1.Copyfrom(in2y);
  for(i=0; i<in2y.numerator->numc_;i++) {
    bn1= in2y.numerator->c_array_[i];
    bn2= s1.numerator->c_array_[i];
    mpModSub(g_bnZero, *bn1, *p, *bn2);
  }
  return EccSymbolicAdd(curve_x_poly, in1x, in1y,
                      in2x, s1, outx, outy);
}

int HighBit(i64 x) {
  int j;
  int n= 0;

  for(j=1;j<64;j++) {
    if(x&1)
      n= j;
    x>>= 1ULL;
  }
  return n;
}


// Because t(x,y) is an endomorphism, t(x,y)=(r[1](x), yr[2](x))
// Here, out_x= r1[x] and out_y= r[2](x).  So out_y should be multiplied by y
// to give a correct answer. 
bool EccSymbolicPointMult(polynomial& curve_x_poly, i64 t, 
                          rationalpoly& x, rationalpoly& y, 
                          rationalpoly& out_x, rationalpoly& out_y) {
  int i;
  int n = HighBit(t);
  i64 r= t;
  bnum* p= curve_x_poly.characteristic_;
  rationalpoly  acc_rationalx(*p, x.numerator->numc_, p->mpSize(), 
                              x.denominator->numc_, p->mpSize());
  rationalpoly  acc_rationaly(*p, x.numerator->numc_, p->mpSize(), 
                              x.denominator->numc_, p->mpSize());
  rationalpoly  double_rationalx(*p, x.numerator->numc_, p->mpSize(), 
                                 x.denominator->numc_, p->mpSize());
  rationalpoly  double_rationaly(*p, x.numerator->numc_, p->mpSize(), 
                              x.denominator->numc_, p->mpSize());
  rationalpoly  resultx(*p, x.numerator->numc_, p->mpSize(), 
                        x.denominator->numc_, p->mpSize());
  rationalpoly  resulty(*p, x.numerator->numc_, p->mpSize(), 
                        x.denominator->numc_, p->mpSize());

  double_rationalx.numerator->Copyfrom(*x.numerator);
  double_rationaly.numerator->Copyfrom(*y.numerator);
  double_rationalx.numerator->c_array_[0]->m_pValue[0]= 1ULL;
  double_rationaly.numerator->c_array_[0]->m_pValue[0]= 1ULL;
  for (i = 0; i < n; i++) {
    if (r&1) {
      resultx.ZeroRational();
      resulty.ZeroRational();
      EccSymbolicAdd(curve_x_poly, acc_rationalx,  acc_rationaly, 
                     double_rationalx, double_rationaly, resultx, resulty);
      acc_rationalx.ZeroRational();
      acc_rationaly.ZeroRational();
      acc_rationalx.Copyfrom(resultx);
      acc_rationaly.Copyfrom(resulty);
    }
    if (i != n) {
      resultx.ZeroRational();
      resulty.ZeroRational();
      EccSymbolicAdd(curve_x_poly, double_rationalx,  double_rationaly, 
                     double_rationalx, double_rationaly, resultx, resulty);
      double_rationalx.Copyfrom(resultx);
      double_rationaly.Copyfrom(resulty);
    }
    r>>= 1ULL;
  }
  acc_rationalx.Copyto(out_x);
  acc_rationaly.Copyto(out_y);
  return true;
}


// Since this is an endomorphism, the result is (r(x), yq(x)) and we return
// out_x= r[x] and out_y= q(x).  So out_y should be multiplied by y to give the answer
bool ComputeMultEndomorphism(polynomial& curve_x_poly, i64 c, 
                              rationalpoly& out_x, rationalpoly& out_y)
{
  bnum*         p= curve_x_poly.characteristic_;
  int           n= p->mpSize();
  rationalpoly  x_poly(*p, 5, n, 5, n);
  rationalpoly  y_poly(*p, 5, n, 5, n);

  // set (x, y)
  x_poly.numerator->c_array_[1]->m_pValue[0]= 1ULL;
  x_poly.denominator->c_array_[0]->m_pValue[0]= 1ULL;
  y_poly.numerator->c_array_[0]->m_pValue[0]= 1ULL;
  y_poly.denominator->c_array_[0]->m_pValue[0]= 1ULL;
  if(!EccSymbolicPointMult(curve_x_poly, c, x_poly, y_poly, 
                          out_x, out_y))
    return false;
  return true;
}


// As above, since this is an endomorphism, the result is (r(x), yq(x)) and we return
// out_x= r[x] and out_y= q(x).  So out_y should be multiplied by y to give the answer
bool ComputePowerEndomorphism(polynomial& curve_x_poly, bnum& power, 
                              rationalpoly& out_x, rationalpoly& out_y)
{
#if 0
  bnum*         p= curve_x_poly.characteristic_;
  int           n= p->mpSize();
  rationalpoly  x_poly(*p, 5, n, 5, n);
  rationalpoly  y_poly(*p, 5, n, 5, n);

  // set (x, y)
  x_poly.numerator->c_array_[1]->m_pValue[0]= 1ULL;
  x_poly.denominator->c_array_[0]->m_pValue[0]= 1ULL;
  y_poly.numerator->c_array_[0]->m_pValue[0]= 1ULL;
  y_poly.denominator->c_array_[0]->m_pValue[0]= 1ULL;
#endif

  if(!Reducelargepower(power, curve_x_poly, *out_x.numerator))
    return false;
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
  bnum*         p= curve_x_poly.characteristic_;
  i64           p_bar= Reducedp(*p, l);
  int           n= p->mpSize();
  rationalpoly  x_prime(*p, 5, n, 5, n);
  rationalpoly  y_prime(*p, 5, n, 5, n);
  rationalpoly  x_p_bar(*p, 5, n, 5, n);
  rationalpoly  x_p_squared(*p, 5, n, 5, n);
  rationalpoly  y_p_squared(*p, 5, n, 5, n);
  rationalpoly  y_p_bar(*p, 5, n, 5, n);
  rationalpoly  x_j(*p, 5, n, 5, n);
  rationalpoly  y_j(*p, 5, n, 5, n);
  rationalpoly  x_w(*p, 5, n, 5, n);
  rationalpoly  y_w(*p, 5, n, 5, n);
  rationalpoly  x_poly(*p, 5, n, 5, n);
  rationalpoly  y_poly(*p, 5, n, 5, n);
  rationalpoly  t_x(*p, 5, n, 5, n);
  rationalpoly  t_y(*p, 5, n, 5, n);
  rationalpoly  s1(*p, 5, n, 5, n);
  rationalpoly  s2(*p, 5, n, 5, n);
  rationalpoly  s3(*p, 5, n, 5, n);
  rationalpoly  slope(*p, 5, n, 5, n);
  polynomial    t1(*p, (int) l, n);
  polynomial    t2(*p, (int) l, n);
  polynomial    g(*p, (int) l, n);
  polynomial    test(*p, (int) l, n);
  bnum          p_squared(2*n+1);
  bnum          small_num(1);
  bnum          w(n);  // square root of p

  // compute p^2
  mpMult(*p, *p, p_squared);

  // set (x, y)
  x_poly.numerator->c_array_[1]->m_pValue[0]= 1ULL;
  x_poly.denominator->c_array_[0]->m_pValue[0]= 1ULL;
  y_poly.numerator->c_array_[0]->m_pValue[0]= 1ULL;
  y_poly.denominator->c_array_[0]->m_pValue[0]= 1ULL;

  //    Compute (x_p_bar, y_p_bar) and (x^(p^2), y^(p^2))
  if(!ComputeMultEndomorphism(curve_x_poly, p_bar, x_p_bar, y_p_bar))
    return false;
  if(!ComputePowerEndomorphism(curve_x_poly, p_squared, x_p_squared, y_p_squared))
    return false;

  // Compute x_prime= curve_x_poly((y_p_squared- y_p_bar)/(x_p_squared-x_p_bar]))^2
  //                     -x_p_squared-x_p_bar
  if(!RationalSub(y_p_squared, y_p_bar, t_y))
    return false;
  if(!RationalSub(x_p_squared, x_p_bar, t_x))
    return false;
  if(!RationalDiv(t_y, t_x, s1))
    return false;
  if(!RationalMult(s1, s1, s2))
    return false;
  s1.ZeroRational();
  slope.ZeroRational();
  s1.denominator->c_array_[0]->m_pValue[0]= 1ULL;
  curve_x_poly.Copyto(*s1.numerator);
  if(!RationalMult(s2, s1, slope))
    return false;
  s1.ZeroRational();
  if(!RationalSub(slope, x_p_squared, s1))
    return false;
  if(!RationalSub(s1, x_p_bar, x_prime))
    return false;

  // Compute y_prime= slope(x_p_squared-x_prime)-y_p_squared
  s1.ZeroRational();
  s2.ZeroRational();
  if(!RationalSub(x_p_squared, x_prime, s1))
    return false;
  if(!RationalMult(slope, s1, s2))
    return false;
  if(!RationalSub(s2, y_p_squared, y_prime))
    return false;

  for(j=1; j<=(l-1)/2; j++) {
    // compute j(x,y)= (x_j,y_j)
    if(!ComputeMultEndomorphism(curve_x_poly, j, x_j, y_j))
      return false;
    if(!ComputePowerEndomorphism(curve_x_poly, *p, t_x, t_y))
      return false;
    s1.ZeroRational();
    s2.ZeroRational();
    s3.ZeroRational();
    // compute test= x_prime-x_j^p (mod phi[l])
    if(!RationalSub(x_prime, t_x, s1))
      return false;
    g.ZeroPoly();
    if(!PolyEuclid(*s1.numerator, *g_phi2[(int)l], g, test))
      return false;
    if(!test.IsZero())
      continue;
    g.ZeroPoly();
    // compute test= num (y_prime-y_j)/y (mod phi[l])
    if(!RationalSub(y_prime, y_j, s1))
      return false;
    test.ZeroPoly();
    if(!PolyEuclid(*s1.numerator, *g_phi2[(int)l], g, test))
       return false;
    if(test.IsZero())
      *tl= j; 
    else 
      *tl= -j;
    return true;
  }

  // we're at (d) in Schoof
  small_num.m_pValue[0]= l;
  if(!mpModisSquare(*p, small_num)) {
    *tl= 0;
    return true;
  }
  if(!mpModSquareRoot(*p, small_num, w))
    return false;
  i64  small_w= (i64)w.m_pValue[0];

  // compute g= (num((y^p-y[w])/y), phi[l])
  if(!ComputeMultEndomorphism(curve_x_poly, (u64)small_w, x_w, y_w))
    return false;
  s1.ZeroRational();
  g.ZeroPoly();
  if(!RationalSub(y_prime, y_w, s1))
    return false;
  if(!PolyEuclid(*s1.numerator, *g_phi2[(int)l], g, test))
     return false;
  // if test is degree1, ((num((y^p-y[w])/y), phi[l])=1
  if(g.Degree()==1) 
    *tl= -2*small_w; 
  else
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
  bnum        t(order.mpSize());
  bnum        s(order.mpSize());
  int         n= p.mpSize();
  polynomial  curve_x_poly(p, 4, n);
  int         j;

  // pick primes to use
  if(!pickS(p))
    return false;

  // curve
  curve_x_poly.c_array_[3]->m_pValue[0]= 1ULL;
  curve_x_poly.c_array_[2]->m_pValue[0]= 0ULL;
  a.mpCopyNum(*curve_x_poly.c_array_[1]);
  b.mpCopyNum(*curve_x_poly.c_array_[0]);

  if(Initphi((int)g_S[g_maxcoeff-1], curve_x_poly))
    return false;
  if(g_maxcoeff<0)
    return false;

  if(!computetmod2(curve_x_poly, &g_tl[0]))
    return false;
  for(j=1; j<g_sizeS; j++) {
    if(!computetmododdprime(curve_x_poly, g_S[j], &g_tl[j]))
      return false;
  }

  Freephi();

  // compute t mod prodprimes
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
