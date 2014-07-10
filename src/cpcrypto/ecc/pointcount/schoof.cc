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


#define JLMDEBUG

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
extern bool Reducelargepower(bnum&, polynomial&, polynomial&, polynomial&);


void smallprintpoly(polynomial& p,bool printmod=false) {
  int j;

  for(j=p.numc_-1; j>=0; j--)
    if(p.c_array_[j]->m_pValue[0]!=0)
      break;
  if(j<0) {
    printf("0 ");
  }
  else {
    int k= j;
    for(;j>=0; j--) {
      if(p.c_array_[j]->m_pValue[0]==0)
        continue;
      if(k==j && j==0)
        printf("%lld ", p.c_array_[j]->m_pValue[0],j);
      else if(k==j && j>0)
        printf("%lldx^%d", p.c_array_[j]->m_pValue[0],j);
      else if(j>0)
        printf("+%lldx^%d", p.c_array_[j]->m_pValue[0],j);
      else
        printf("+%lld ", p.c_array_[j]->m_pValue[0]);
    }
  }
  if(printmod)
    printf("(mod %lld)", p.characteristic_->m_pValue[0]);
}

void smallprintrational(rationalpoly& r, bool printmod=false) {
  printf("(");
  smallprintpoly(*r.numerator, printmod);
  printf("/");
  smallprintpoly(*r.denominator, printmod);
  printf(")");
}


// ------------------------------------------------------------------------------------


// select primes != p until prod>4(sqrt p)
bool pickS(bnum& p)
{
  int   j;
  bnum  v(2*p.mpSize());
  bnum  w(2*p.mpSize());
  bnum  prod(2*p.mpSize());
  bnum  top(2*p.mpSize());
  u64   nextprime;

  g_sizeS= 0;
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
    mpMult(prod, v, w);
    mpZeroNum(prod);
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
  if(x>(i64)(l/2))
    x-= (i64)l;
  return x;
}

int maxterms(rationalpoly& in1, rationalpoly& in2)
{
  int m= in1.numerator->numc_;
  if(in1.denominator->numc_>m)
    m= in1.denominator->numc_;
  if(in2.numerator->numc_>m)
    m= in2.numerator->numc_;
  if(in2.denominator->numc_>m)
    m= in2.denominator->numc_;
  return m;
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
//  m= y ((in2y-in1y)/(in2x-in1x) or (3in1x^2+a)/2in1y.
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
  int           m=  2*maxterms(outx, outy);
  rationalpoly  s1(*p, m, n, m, n);
  rationalpoly  s2(*p, m, n, m, n);
  rationalpoly  s3(*p, m, n, m, n);
  rationalpoly  slope(*p, m, n, m, n);
  rationalpoly  slope_squared(*p, m, n, m, n);
  rationalpoly  curve_rational(*p, m, n, 1, n);
  bnum          a(n);
  bnum          temp_num(n);
  polynomial    t1(*p, m, n);
  polynomial    t2(*p, m, n);
  bool          x_equal, y_equal;

#ifdef JLMDEBUG1
  printf("EccSymbolicAdd()\n"); 
  printf("curve: "); smallprintpoly(curve_x_poly, true); printf("\n");
#endif

  if(IsInfPoint(in1x, in1y)) {
    outx.Copyfrom(in2x);
    outy.Copyfrom(in2y);
    return true;
  }
  if(IsInfPoint(in2x, in2y)) {
    outx.Copyfrom(in1x);
    outy.Copyfrom(in1y);
    return true;
  }

  curve_rational.numerator->Copyfrom(curve_x_poly);
  curve_rational.denominator->c_array_[0]->m_pValue[0]= 1ULL;
  curve_x_poly.c_array_[1]->mpCopyNum(a); // a

  x_equal= RationalisEqual(in1x, in2x); 
  y_equal= RationalisEqual(in1y, in2y);
  if(x_equal && !y_equal) {
    MakeInfPoint(outx, outy);
    return true;
  }
  else if(x_equal && y_equal) {
    // slope= (3in1x^2+a)/(2curve_x_poly)= ((3in1x^2+a)/(2y^2))y, remember implicit y
    if(!RationalMult(in1x, in1x, s2))
      return false;
    // now s2= inx1^2
    mpZeroNum(temp_num);
    temp_num.m_pValue[0]= 3ULL;
    s2.numerator->MultiplyByNum(temp_num);
    s2.numerator->AddToByNum(a);
    // now s2= 3(in1^2)+a
#ifdef JLMDEBUG1
    printf("a:"); printNumberToConsole(a); printf("\n");
    printf("EccSymbolicAdd, (3x^2+a): "); smallprintrational(s2); printf("\n");
#endif

    s1.ZeroRational();
    if(!RationalMult(in1y, in1y, s1))
      return false;
    t1.ZeroPoly();
    if(!PolyMult(*s1.numerator, curve_x_poly, t1))
      return false;
    temp_num.m_pValue[0]= 2ULL;
    t1.MultiplyByNum(temp_num);
    s1.numerator->Copyfrom(t1);
    // now s1= 2y^2= 2*(iny1^2)curve_x_poly, y will be implicit after division
#ifdef JLMDEBUG1
    printf("EccSymbolicAdd, (2y^2: "); smallprintrational(s1); printf("\n");
#endif

    if(!RationalDiv(s2, s1, slope))
      return false;
#ifdef JLMDEBUG1
    printf("EccSymbolicAdd, slope (from 3x^2+a/2y^2: "); smallprintrational(slope, true); printf("\n");
#endif
  }
  else {
    // slope= (in2y-in1y)/(in2x-in1x), remember implicit y
    if(!RationalSub(in2x, in1x, s1))
      return false;
    if(!RationalSub(in2y, in1y, s2))
      return false;
    if(!RationalDiv(s2, s1, slope)) {
      printf("EccSymbolicAdd fails at RationalDiv\n");
      return false;
    }
#ifdef JLMDEBUG1
    printf("EccSymbolicAdd, slope (from (y2-y1)/x2-x2): "); smallprintrational(slope); printf("\n");
#endif
  }
  if(!RationalReduce(slope)) {
    printf("RationalReduce fails at RationalDiv\n");
    return false;
  }
  s1.ZeroRational();
  s2.ZeroRational();
  s3.ZeroRational();
  if(!RationalMult(slope, slope, s1))
    return false;
  if(!RationalMult(s1, curve_rational, slope_squared))
    return false;
  if(!RationalReduce(slope_squared)) {
    printf("RationalReduce after slope-squared fails\n");
    return false;
  }
#ifdef JLMDEBUG1
    printf("EccSymbolicAdd, slope_squared: "); smallprintrational(slope_squared); printf("\n");
#endif

  //  outx= slope_squared-in1x-in2x
  if(!RationalSub(slope_squared, in1x, s2))
    return false;
  if(!RationalSub(s2, in2x, outx))
    return false;
  if(!RationalReduce(outx))
    return false;
  
  //  outy= slope(x[1]-x[3])-y[1]
  s1.ZeroRational();
  s2.ZeroRational();
  s3.ZeroRational();
  if(!RationalSub(in1x, outx, s1))
    return false;
  if(!RationalMult(slope, s1, s2))
    return false;
  if(!RationalSub(s2, in1y, outy))
    return false;
  if(!RationalReduce(outy))
    return false;

#ifdef JLMDEBUG1
  printf("EccSymbolicAdd() result\n"); 
  printf("in1x: "); smallprintrational(in1x); printf("\n");
  printf("in1y: "); smallprintrational(in1y); printf("\n");
  printf("in2x: "); smallprintrational(in2x); printf("\n");
  printf("in2y: "); smallprintrational(in2y); printf("\n");
  printf("outx: "); smallprintrational(outx); printf("\n");
  printf("outy: "); smallprintrational(outy); printf("\n");
#endif
  return true;
}

bool EccSymbolicMult(polynomial& curve_x_poly, 
                    rationalpoly& in1x, rationalpoly& in1y,
                    rationalpoly& in2x, rationalpoly& in2y, 
                    rationalpoly& outx, rationalpoly& outy) {
  bnum*         p= curve_x_poly.characteristic_;
  int           n= p->mpSize();
  int           m=  maxterms(outx, outy);
  rationalpoly  s1(*p, m, n, m, n);
  int           i;
  bnum*         bn1;
  bnum*         bn2;

#ifdef JLMDEBUG1
  printf("EccSymbolicMult()\n"); 
#endif
  if(IsInfPoint(in2x, in2y)) {
    outx.Copyfrom(in1x);
    outy.Copyfrom(in1y);
    return true;
  }
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
bool EccSymbolicPointMult(polynomial& curve_x_poly, u64 t, rationalpoly& x, rationalpoly& y, 
                          rationalpoly& out_x, rationalpoly& out_y) {
  int   i;
  int   n = HighBit(t);
  bnum* p= curve_x_poly.characteristic_;
  int   nn1= out_x.numerator->numc_;
  int   nd1= out_x.denominator->numc_;
  int   nn2= out_y.numerator->numc_;
  int   nd2= out_y.denominator->numc_;
  int   size_num= p->mpSize()+1;
  i64   r= t;

#ifdef JLMDEBUG1
  printf("EccSymbolicPointMult(%lld)\n", t); 
#endif

  rationalpoly  acc_rationalx(*p, nn1, size_num, nd1, size_num);
  rationalpoly  acc_rationaly(*p, nn2, size_num, nd2, size_num);
  rationalpoly  double_rationalx(*p, nn1, size_num, nd1, size_num);
  rationalpoly  double_rationaly(*p, nn2, size_num, nd2, size_num);
  rationalpoly  resultx(*p, nn1, size_num, nd1, size_num);
  rationalpoly  resulty(*p, nn2, size_num, nd2, size_num);

  double_rationalx.Copyfrom(x);
  double_rationaly.Copyfrom(y);
  MakeInfPoint(acc_rationalx, acc_rationaly);

  if(IsInfPoint(x, y)) {
    MakeInfPoint(out_x, out_y);
    return true;
  }

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
      double_rationalx.ZeroRational();
      double_rationaly.ZeroRational();
      double_rationalx.Copyfrom(resultx);
      double_rationaly.Copyfrom(resulty);
    }
    r>>= 1ULL;
  }
  acc_rationalx.Copyto(out_x);
  acc_rationaly.Copyto(out_y);
#ifdef JLMDEBUG1
  printf("EccSymbolicPointMult returning\n");
  printf("x: "); printrational(acc_rationalx);
  printf("y: "); printrational(acc_rationaly);
#endif
  return true;
}

bool EccSymbolicMinus(rationalpoly& in, rationalpoly& out) {
  bnum*         p= in.numerator->characteristic_;
  int           n= p->mpSize()+1;
  bnum          bn1(n);
  int           i;

#ifdef JLMDEBUG1
  printf("EccSymbolicMinus()\n"); 
#endif
  if(out.numerator->numc_<=in.numerator->Degree())
    return false;
  if(out.denominator->numc_<=in.denominator->Degree())
    return false;
  out.denominator->Copyfrom(*in.denominator);
  for(i=0; i<=in.numerator->Degree();i++) {
    mpModSub(g_bnZero, *in.numerator->c_array_[i], *p, *out.numerator->c_array_[i]);
  }
  return true;
}

bool EccSymbolicPointMultWithReduction(polynomial& mod_poly, polynomial& curve_x_poly, 
                u64 t, rationalpoly& x, rationalpoly& y, 
                rationalpoly& out_x, rationalpoly& out_y) {
  int   i;
  int   n = HighBit(t);
  bnum* p= curve_x_poly.characteristic_;
  int   nn1= out_x.numerator->numc_;
  int   nd1= out_x.denominator->numc_;
  int   nn2= out_y.numerator->numc_;
  int   nd2= out_y.denominator->numc_;
  int   size_num= p->mpSize()+1;
  i64   r= t;

#ifdef JLMDEBUG1
  printf("EccSymbolicPointMultWithReduction(%lld)\n", t); 
  printf("mod_poly: "); smallprintpoly(mod_poly); printf("\n");
  printf("curve_poly: "); smallprintpoly(curve_x_poly); printf("\n");
#endif

  rationalpoly  acc_rationalx(*p, nn1, size_num, nd1, size_num);
  rationalpoly  acc_rationaly(*p, nn2, size_num, nd2, size_num);
  rationalpoly  double_rationalx(*p, nn1, size_num, nd1, size_num);
  rationalpoly  double_rationaly(*p, nn2, size_num, nd2, size_num);
  rationalpoly  resultx(*p, nn1, size_num, nd1, size_num);
  rationalpoly  resulty(*p, nn2, size_num, nd2, size_num);

  double_rationalx.Copyfrom(x);
  double_rationaly.Copyfrom(y);
  MakeInfPoint(acc_rationalx, acc_rationaly);

  if(IsInfPoint(x, y)) {
    MakeInfPoint(out_x, out_y);
    return true;
  }

  for (i = 0; i < n; i++) {
    if (r&1) {
      resultx.ZeroRational();
      resulty.ZeroRational();
      EccSymbolicAdd(curve_x_poly, acc_rationalx,  acc_rationaly, 
                     double_rationalx, double_rationaly, resultx, resulty);
      acc_rationalx.ZeroRational();
      acc_rationaly.ZeroRational();
      if(!ReduceModPoly(*resultx.numerator, mod_poly, *acc_rationalx.numerator))
        return false;
      if(!ReduceModPoly(*resulty.numerator, mod_poly, *acc_rationaly.numerator))
        return false;
      if(!ReduceModPoly(*resultx.denominator, mod_poly, *acc_rationalx.denominator))
        return false;
      if(!ReduceModPoly(*resulty.denominator, mod_poly, *acc_rationaly.denominator))
        return false;
    }
    if (i != n) {
      resultx.ZeroRational();
      resulty.ZeroRational();
      EccSymbolicAdd(curve_x_poly, double_rationalx,  double_rationaly, 
                     double_rationalx, double_rationaly, resultx, resulty);
      double_rationalx.ZeroRational();
      double_rationaly.ZeroRational();
      if(!ReduceModPoly(*resultx.numerator, mod_poly, *double_rationalx.numerator))
        return false;
      if(!ReduceModPoly(*resulty.numerator, mod_poly, *double_rationaly.numerator))
        return false;
      if(!ReduceModPoly(*resultx.denominator, mod_poly, *double_rationalx.denominator))
        return false;
      if(!ReduceModPoly(*resulty.denominator, mod_poly, *double_rationaly.denominator))
        return false;
    }
    r>>= 1ULL;
  }
  acc_rationalx.Copyto(out_x);
  acc_rationaly.Copyto(out_y);
#ifdef JLMDEBUG1
  printf("EccSymbolicPointMultWithReduction returning\n");
  printf("x: "); printrational(acc_rationalx);
  printf("y: "); printrational(acc_rationaly);
#endif
  return true;
}


// Since this is an endomorphism, the result is (r(x), yq(x)) and we return
// out_x= r[x] and out_y= q(x).  So out_y should be multiplied by y to give the answer
bool ComputeMultEndomorphism(polynomial& curve_x_poly, i64 c, 
                              rationalpoly& out_x, rationalpoly& out_y)
{
  bnum*         p= curve_x_poly.characteristic_;
  int           n= p->mpSize();
  int           m=  maxterms(out_x, out_y);
  rationalpoly  x_poly(*p, m, n, m, n);
  rationalpoly  y_poly(*p, m, n, m, n);

#ifdef JLMDEBUG1
  printf("ComputeMultEndomorphism(%d)\n", (int)c);
#endif
  x_poly.ZeroRational();
  y_poly.ZeroRational();

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
  bnum          t1(power.mpSize());
  bnum          t2(power.mpSize());
  bnum*         p= curve_x_poly.characteristic_;
  int           m= out_y.numerator->numc_;
  polynomial    s(*p, m, p->mpSize());
  polynomial    x_poly(*p,2,1);
  x_poly.c_array_[1]->m_pValue[0]= 1ULL;  // "x"

#ifdef JLMDEBUG1
  printf("ComputePowerEndomorphism( "); printNumberToConsole(power); printf(")\n");
#endif
  power.mpCopyNum(t1);
  mpUSubFrom(t1, g_bnOne);
  mpShift(t1, -1, t2);
  if(!Reducelargepower(power, x_poly, curve_x_poly, *out_x.numerator))
    return false;
  if(!Reducelargepower(t2, x_poly, curve_x_poly, s))
    return false;
  if(!PolyMult(s,curve_x_poly, *out_y.numerator))
    return false;
  out_x.denominator->c_array_[0]->m_pValue[0]= 1ULL;
  out_y.denominator->c_array_[0]->m_pValue[0]= 1ULL;
  // multiply out_y by curve_x_poly
#ifdef JLMDEBUG1
  printf("ComputePowerEndomorphism returning ");
  printf("("); printrational(out_x);
  printf(", "); printrational(out_y); printf(")\n");
#endif
  return true;
}

// compute t (mod 2)
bool computetmod2(polynomial& curve_x_poly, u64* tl)
{
  bnum*       p= curve_x_poly.characteristic_;
  polynomial  t1(*p, 8, p->mpSize()+1);
  polynomial  t2(*p, 8, p->mpSize()+1);
  polynomial  g(*p, 8, p->mpSize()+1);
  polynomial  result(*p, 8, p->mpSize()+1);
  polynomial  x_poly(*p,3,2);
  x_poly.c_array_[1]->m_pValue[0]= 1ULL;  // "x"

  if(!Reducelargepower(*p, x_poly, curve_x_poly, t1)) {
    printf("computetmod2, Reducelargepower fails\n");
    return false;
  }
  if(!PolySub(t1,x_poly,result)) {
    printf("computetmod2, PolySub fails\n");
    return false;
  }
  if(!PolyExtendedgcd(result, curve_x_poly, t1, t2, g)) {
    printf("computetmod2, PolyExtendedgcd fails\n");
    return false;
  }
#ifdef JLMDEBUG
  printf("computetmod2, result: "); smallprintpoly(result); printf("\n");
  printf("computetmod2, g.Degree(): %d\n", g.Degree());
#endif
  if(g.Degree()==0)
    *tl= 1;
  else
    *tl= 0;
  return true;
}


// outx= inx^power, outy= (iny^power) curve_x_poly^(p-1)/2
bool Raisetopower(bnum& power, polynomial& curve_x_poly, polynomial& mod_poly, 
                  polynomial& inx, polynomial& iny, polynomial& outx, polynomial& outy)
{
  bnum*         p= curve_x_poly.characteristic_;
  int           n= 2*p->mpSize()+1;
  int           m= 2*outy.numc_;
  bnum          t1(n);
  bnum          t2(n);
  polynomial    s1(*p, m, n);
  polynomial    s2(*p, m, n);
  polynomial    s3(*p, m, n);

#ifdef JLMDEBUG1
  printf("Raisetopower %lld\n", power.m_pValue[0]);
  smallprintpoly(inx, true); printf(" (inx)\n");
  smallprintpoly(mod_poly, true); printf(" (mod_poly)\n");
  smallprintpoly(outy, true); printf(" (outy)\n");
#endif
  if(mod_poly.Degree()<=0) {
    printf("Raisetopower, mod_poly does not have degree >0\n");
    return false;
  }
  power.mpCopyNum(t1);
  mpUSubFrom(t1, g_bnOne);
  mpShift(t1, -1, t2);
  polynomial    reduced_inx(*p, m, n);
  polynomial    reduced_iny(*p, m, n);

  reduced_inx.ZeroPoly();
  reduced_iny.ZeroPoly();
  if(!ReduceModPoly(inx, mod_poly, reduced_inx))
    return false;
  if(!ReduceModPoly(iny, mod_poly, reduced_iny))
    return false;

#ifdef JLMDEBUG1
  printf("inx: "); smallprintpoly(inx, true); printf("\n");
  printf("reduced_inx: "); smallprintpoly(reduced_inx, true); printf("\n");
#endif

  s1.ZeroPoly();
  s2.ZeroPoly();
  if(!Reducelargepower(power, reduced_inx, mod_poly, outx)) {
    printf("Raisetopower Reducelargepower(p, reduced_inx, mod_poly, outx) failed\n");
    return false;
  }
  if(!Reducelargepower(power, reduced_iny, mod_poly, s1)) {
    printf("Raisetopower Reducelargepower(p, reduced_iny, mod_poly, outx) failed\n");
    return false;
  }
  if(!Reducelargepower(t2, curve_x_poly, mod_poly, s2)) {
    printf("Raisetopower Reducelargepower(t2, curve_x_poly, mod_poly, s2), t2: %lld failed\n",
            t2.m_pValue[0]);
    return false;
  }
  s3.ZeroPoly();
  if(!PolyMult(s1, s2, s3)) {
    printf("Raisetopower PolyMult(s1, s2, s3) failed, %d\n", s3.numc_);
    printf("s1: "); smallprintpoly(s1); printf("\n");
    printf("s2: "); smallprintpoly(s2); printf("\n");
    return false;
  }
  if(!ReduceModPoly(s3, mod_poly, outy)) {
    printf("Raisetopower,ReduceModPoly(s3, mod_poly, outy) failed\n");
    return false;
  }
#ifdef JLMDEBUG1
  printf("Raisetopower returning\n");
#endif
  return true;
}


// compute t (mod l)
bool computetmododdprime(polynomial& curve_x_poly, u64 l, u64* tl) {
  i64           j;
  bnum*         p= curve_x_poly.characteristic_;
  i64           p_bar= Reducedp(*p, l);
  int           n= 2*p->mpSize()+1;
  int           m= 2*(int)l+1;
  bnum          p_squared(2*n+1);
  bnum          small_num(2);
  bnum          small_out(2);
  bnum          w(n);  // square root of p

#ifdef JLMDEBUG
  printf("computetmododdprime(%d), p_bar: %lld\n", (int) l, p_bar);
  printf("curve_x_poly: "); smallprintpoly(curve_x_poly, true); printf("\n");
#endif

  // note: check to see if m is an overestimate

  rationalpoly  x_prime(*p, 100, n, 100, n);
  rationalpoly  y_prime(*p, 100, n, 100, n);
  rationalpoly  x_p_squared(*p, 100, n, 100, n);
  rationalpoly  y_p_squared(*p, 100, n, 100, n);

  rationalpoly  x_p_bar(*p, 100, n, 100, n);
  rationalpoly  y_p_bar(*p, 100, n, 100, n);
  rationalpoly  x_j(*p, 100, n, 100, n);
  rationalpoly  y_j(*p, 100, n, 100, n);

  rationalpoly  x_w(*p, m, n, m, n);
  rationalpoly  y_w(*p, m, n, m, n);
  rationalpoly  slope(*p, 100, n, 100, n);

  rationalpoly  s1(*p, 100, n, 100, n);
  rationalpoly  s2(*p, 100, n, 100, n);
  rationalpoly  s3(*p, 100, n, 100, n);

  rationalpoly  x_j_p(*p, 100, n, 100, n);
  rationalpoly  y_j_p(*p, 100, n, 100, n);
  rationalpoly  x_exp_p(*p, 100, n, 100, n);
  rationalpoly  y_exp_p(*p, 100, n, 100, n);

  polynomial    g(*p, 100, n);
  polynomial    t1(*p, 100, n);
  polynomial    t2(*p, 100, n);
  rationalpoly  curve_rational(*p, m, n, 1, n);

  // current phi2
  polynomial    temp_phi(*p, (int)l*(int)l+1, n);
  temp_phi.Copyfrom(*g_phi2[(int)l]);

  curve_rational.numerator->Copyfrom(curve_x_poly);
  curve_rational.denominator->c_array_[0]->m_pValue[0]= 1ULL;

  polynomial    x_poly(*p, 2, n);
  x_poly.ZeroPoly();
  x_poly.c_array_[1]->m_pValue[0]= 1ULL;
  polynomial    y_poly(*p, 2, n);
  y_poly.OnePoly();

  rationalpoly  rational_x(*p, 2, n, 2, n);
  rational_x.ZeroRational();
  rational_x.numerator->Copyfrom(x_poly);
  rationalpoly  rational_y(*p, 2, n, 2, n);
  rational_y.OneRational();

  // compute p^2
  mpMult(*p, *p, p_squared);

  x_p_bar.ZeroRational();
  y_p_bar.ZeroRational();
  // Compute (x_p_bar, y_p_bar)
  if(p_bar>=0) {
    if(!EccSymbolicPointMultWithReduction(temp_phi, curve_x_poly, p_bar, 
                rational_x, rational_y, x_p_bar, y_p_bar))
      return false;
  }
  else {
    s1.ZeroRational();
    if(!EccSymbolicPointMultWithReduction(temp_phi, curve_x_poly, (u64)-p_bar, 
                rational_x, rational_y, x_p_bar, s1))
      return false;
    EccSymbolicMinus(s1, y_p_bar);
  }

  x_p_squared.ZeroRational();
  y_p_squared.ZeroRational();
  // Compute (x^(p^2), y^(p^2))
  if(!Raisetopower(p_squared, curve_x_poly, temp_phi, x_poly, y_poly, 
                   *x_p_squared.numerator, *y_p_squared.numerator)) {
    printf("Raisetopower(p_squared, curve_x_poly, temp_phi, x_poly, x_poly, x_p_squared, y_p_squared) failed\n");
    return false;
  }

  // (y_p_squared-y_p_bar)/((x_p_squared-x_p_bar)= slope
  s1.ZeroRational();
  s2.ZeroRational();
  s3.ZeroRational();
  if(!RationalSub(x_p_squared, x_p_bar, s2)) {
    return false;
  }
  if(!RationalSub(y_p_squared, y_p_bar, s1)) {
    return false;
  }
  if(!RationalDiv(s1, s2, s3)) {
    return false;
  }
  if(!ReduceModPoly(*s3.numerator, temp_phi, *slope.numerator)) {
    return false;
  }
  if(!ReduceModPoly(*s3.denominator, temp_phi, *slope.denominator)) {
    return false;
  }

  // is (slope.denominator, temp_phi) != 1?
  t1.ZeroPoly();
  t2.ZeroPoly();
  g.ZeroPoly();
  if(!PolyExtendedgcd(*slope.denominator, temp_phi, t1, t2, g)) {
    return false;
  }
#ifdef JLMDEBUG
    printf("slope: "); smallprintrational(slope); printf("\n");
    printf("slope.denominator: "); smallprintpoly(*slope.denominator); printf("\n");
    printf("g: "); smallprintpoly(g); printf("\n");
#endif
  if(g.Degree()>0) {
    printf("(slope.denominator, temp_phi) = 1\n");
    printf("g: "); smallprintpoly(g); printf("\n");
    // use p_squared as a temp
    mpZeroNum(p_squared);
    mpAdd(*p, g_bnOne, p_squared);
    small_num.m_pValue[0]= l;
    mpMod(p_squared, small_num, small_out);
    // t= p+1 (mod l)
    *tl= small_out.m_pValue[0];
    return true;
  }

  // x_prime= slope^2-x_p_squared-x_p_bar
  s1.ZeroRational();
  s2.ZeroRational();
  s3.ZeroRational();
  if(!RationalMult(slope, slope, s1))
    return false;
  if(!RationalMult(s1, curve_rational, s3))
    return false;
  if(!ReduceModPoly(*s3.numerator, temp_phi, *slope.numerator)) {
    return false;
  }
  if(!ReduceModPoly(*s3.denominator, temp_phi, *slope.denominator)) {
    return false;
  }
  if(!RationalSub(s3, x_p_squared, s2)) {
    return false;
  }
  s1.ZeroRational();
  if(!RationalSub(s2, x_p_bar, s1)) {
    return false;
  }
  if(!ReduceModPoly(*s1.numerator, temp_phi, *x_prime.numerator)) {
    return false;
  }
  if(!ReduceModPoly(*s1.denominator, temp_phi, *x_prime.denominator)) {
    return false;
  }
  
  // y_prime= slope(x_p_bar- x_prime) - y_p_squared
  s1.ZeroRational();
  s2.ZeroRational();
  s3.ZeroRational();
  if(!RationalSub(x_p_bar, x_prime, s1)) {
    return false;
  }
  if(!RationalMult(slope, s1, s2)) {
    return false;
  }
  if(!RationalSub(s2, y_p_squared, s3)) {
    return false;
  }
  if(!ReduceModPoly(*s3.numerator, temp_phi, *y_prime.numerator)) {
    return false;
  }
  if(!ReduceModPoly(*s3.denominator, temp_phi, *y_prime.denominator)) {
    return false;
  }

  // (x^p, y^p)
  x_exp_p.ZeroRational();
  y_exp_p.ZeroRational();
  if(!Raisetopower(*p, curve_x_poly, temp_phi, x_poly, y_poly, *x_exp_p.numerator, *y_exp_p.numerator)) {
    printf("Raisetopower(*p, curve_x_poly, temp_phi, x_poly, x_poly, x_p_exp, y_p_exp) failed\n");
    return false;
  }

#ifdef JLMDEBUG
    printf("x_p_squared: "); smallprintrational(x_p_squared); printf("\n");
    printf("y_p_squared: "); smallprintrational(y_p_bar); printf("\n");
    printf("x_p_bar: "); smallprintrational(x_p_bar); printf("\n");
    printf("y_p_bar: "); smallprintrational(y_p_bar); printf("\n");
    printf("x_exp_p: "); smallprintrational(x_exp_p); printf("\n");
    printf("y_exp_p: "); smallprintrational(y_exp_p); printf("\n");
    printf("x_prime: "); smallprintrational(x_prime); printf("\n");
    printf("y_prime: "); smallprintrational(y_prime); printf("\n");
    printf("\n");
#endif

  for(j=1; j<=(l-1)/2; j++) {

    // compute j(x^p,y^p)
    if(!EccSymbolicPointMultWithReduction(temp_phi, curve_x_poly, (u64)j, 
                x_exp_p, y_exp_p, x_j_p, y_j_p))
      return false;

#ifdef JLMDEBUG
    printf("x_j_p: "); smallprintrational(x_j_p); printf("\n");
    printf("y_j_p: "); smallprintrational(y_j_p); printf("\n");
#endif

    if(!RationalEqualModPoly(x_j_p, x_prime, temp_phi)) {
      printf("x_prime != x_p_%d\n", j);
      continue;
    }

#ifdef JLMDEBUG
    printf("x_prime == x_p_%d\n", j);
#endif

    if(RationalEqualModPoly(y_j_p, y_prime, temp_phi)) {
      *tl= j; 
#ifdef JLMDEBUG
      printf("y_prime == y_p_%d\n", j);
#endif
    }
    else  {
      *tl= l-j;
#ifdef JLMDEBUG
      printf("y_prime != y_p_%d\n", j);
#endif
    }
#ifdef JLMDEBUG
    printf("computemododdprime returning true from j loop, j= %lld\n",j);
#endif
    return true;
  }

  // we're at (d) in Schoof
  small_num.m_pValue[0]= l;
  if(!mpModisSquare(*p, small_num)) {
    *tl= 0;
#ifdef JLMDEBUG
    printf("computetmododdprime returning true from non-square test\n");
#endif
    return true;
  }
  if(!mpModSquareRoot(*p, small_num, w))
    return false;
  u64  small_w= w.m_pValue[0];

  // compute g= (num((y^p-y[w])/y), phi[l])
  if(!EccSymbolicPointMultWithReduction(temp_phi, curve_x_poly, small_w,
              rational_x, rational_y, x_w, y_w))
      return false;
  s1.ZeroRational();
  if(!RationalSub(x_exp_p, x_w, s1))
    return false;

#ifdef JLMDEBUG
    printf("small_num: %lld, small_w: %lld\n", small_num.m_pValue[0], small_w);
    printf("x_w: "); smallprintrational(x_w); printf("\n");
    printf("x_exp_p: "); smallprintrational(x_exp_p); printf("\n");
    printf("num(x_exp_p-x_w): "); smallprintpoly(*s1.numerator); printf("\n");
#endif

  t1.ZeroPoly();
  t2.ZeroPoly();
  if(!PolyExtendedgcd(*s1.numerator, temp_phi, t1, t2, g)) {
    return false;
  }
  if(g.Degree()==1)  {
    *tl= 0;
  }

  s2.ZeroRational();
  if(!RationalSub(y_exp_p, y_w, s2))
    return false;

#ifdef JLMDEBUG
    printf("y_w: "); smallprintrational(y_w); printf("\n");
    printf("y_exp_p: "); smallprintrational(y_exp_p); printf("\n");
    printf("num(y_exp_p-y_w): "); smallprintpoly(*s2.numerator); printf("\n");
#endif

  t1.ZeroPoly();
  t2.ZeroPoly();
  if(!PolyExtendedgcd(*s2.numerator, temp_phi, t1, t2, g)) {
    return false;
  }
#ifdef JLMDEBUG
  printf("g: "); smallprintpoly(g); printf("\n");
#endif
  if(g.Degree()==1) 
    *tl= l-2*small_w; 
  else
    *tl= 2*small_w;
  *tl %= l;
#ifdef JLMDEBUG
  printf("computetmododdprime returning true after testing square roots\n");
#endif
  return true;
}

bool useCRT(bnum& t, bnum& prod_primes)
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
#ifdef JLMDEBUG1
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
  prodprimes.mpCopyNum(prod_primes);
  return true;
}

bool schoof(bnum& a, bnum& b, bnum& p, bnum& order)
{
  bnum        t(order.mpSize());
  bnum        s(order.mpSize());
  bnum        r(order.mpSize());
  bnum        v(order.mpSize());
  int         n= p.mpSize();
  polynomial  curve_x_poly(p, 4, n);
  int         j;

#ifdef JLMDEBUG
  printf("schoof called\n");
  printf("y^2=x^x + ");
  printNumberToConsole(a); printf(" x + "); printNumberToConsole(b);
  printf(" (mod "); printNumberToConsole(p); printf(")\n");
#endif

  // pick primes to use
  if(!pickS(p))
    return false;

#ifdef JLMDEBUG
  printf("%d primes picked\n\t", g_sizeS);
  for(j=0; j<g_sizeS;j++) {
    printf(" %lld", g_S[j]);
  }
  printf("\n");
#endif

  // curve
  curve_x_poly.c_array_[3]->m_pValue[0]= 1ULL;
  curve_x_poly.c_array_[2]->m_pValue[0]= 0ULL;
  a.mpCopyNum(*curve_x_poly.c_array_[1]);
  b.mpCopyNum(*curve_x_poly.c_array_[0]);

  if(!Initphi((int)g_S[g_sizeS-1], curve_x_poly))
    return false;
  if(g_maxcoeff<0)
    return false;
#ifdef JLMDEBUG
  printf("\n%d division polynomials computed\n", g_maxcoeff);
  for(j=0; j<g_maxcoeff; j++) {
    printf("g_phi2[%d]: ", j); smallprintpoly(*g_phi2[j]); printf("\n");
  }
  printf("\n");
#endif

  if(!computetmod2(curve_x_poly, &g_tl[0]))
    return false;
#ifdef JLMDEBUG
  printf("t= %d (mod 2)\n", (int) g_tl[0]);
#endif
  for(j=1; j<g_sizeS; j++) {
    if(!computetmododdprime(curve_x_poly, g_S[j], &g_tl[j])) {
      printf("computetmododdprime(%d) failed\n", (int)g_S[j]);
      return false;
    }
#ifdef JLMDEBUG
    printf("t= %d (mod %d)\n", (int) g_tl[j], g_S[j]);
#endif
  }

  Freephi();

#ifdef JLMDEBUG
    printf("division polys freed\n");
#endif
  // compute t mod prodprimes
  if(!useCRT(t, r))
    return false;
#ifdef JLMDEBUG
    printf("computed p: "); printNumberToConsole(p); printf("\n");
    printf("computed t: "); printNumberToConsole(t); printf("\n");
    printf("computed prod_prime: "); printNumberToConsole(r); printf("\n");
#endif

  // if  |t|>2 sqrt (p), t=p-t;
  if(!SquareRoot(p, s))
    return false;
  if(!mpMult(s, g_bnTwo, v))
    return false;
#ifdef JLMDEBUG
    printf("computed 2*sqrt(p): "); printNumberToConsole(v); printf("\n");
#endif
  if(mpCompare(t,v)!=s_isLessThan) {
    mpZeroNum(v);
    mpSub(t,r,v);
    v.mpCopyNum(t);
  }

  // #E= p+1-t
  mpZeroNum(order);
  mpZeroNum(s);
  p.mpCopyNum(s);
  mpUAddTo(s, g_bnOne);
  mpSub(s, t, order);
#ifdef JLMDEBUG
    printf("p+1: "); printNumberToConsole(s); printf("\n");
    printf("final t: "); printNumberToConsole(t); printf("\n");
    printf("computed order: "); printNumberToConsole(order); printf("\n");
#endif
  return true;
}


// ----------------------------------------------------------------------------


#ifdef JLMDEBUG


void SymbolicTest(u64 test_prime, u64 test_a, u64 test_b)
{
  int         n= 2;   // size of bignum
  int         m= 48;  // number of terms
  bnum        p(n);
  bnum        a(n);
  bnum        b(n);

  p.m_pValue[0]= test_prime;
  a.m_pValue[0]= test_a;
  b.m_pValue[0]= test_b;

  polynomial  curve_x_poly(p, 4, n);
  bnum      bn_t1(2);

  printf("\n\nSymbolicTest\n\n");

  // initialize curve
  curve_x_poly.c_array_[3]->m_pValue[0]= 1ULL;
  curve_x_poly.c_array_[2]->m_pValue[0]= 0ULL;
  a.mpCopyNum(*curve_x_poly.c_array_[1]);
  b.mpCopyNum(*curve_x_poly.c_array_[0]);
  printf("y^2= ");
  smallprintpoly(curve_x_poly, true);printf("\n");
  printf("\n");

  polynomial      p_t1(p,m,n);
  polynomial      p_t2(p,m,n);
  polynomial      p_t3(p,m,n);
  polynomial      p_t4(p,m,n);
  polynomial      p_t5(p,m,n);
  polynomial      p_t6(p,m,n);
  polynomial      p_t7(p,m,n);
  polynomial      x_poly(p,2,1);
  x_poly.c_array_[1]->m_pValue[0]= 1ULL;  // "x"

  rationalpoly    r_t1(p,m,n,m,n);
  rationalpoly    r_t2(p,m,n,m,n);
  rationalpoly    r_t3(p,m,n,m,n);
  rationalpoly    r_t4(p,m,n,m,n);
  rationalpoly    r_t5(p,m,n,m,n);
  rationalpoly    r_t6(p,m,n,m,n);
  rationalpoly    r_t7(p,m,n,m,n);
  rationalpoly    r_t8(p,m,n,m,n);

  r_t1.ZeroRational();
  r_t2.ZeroRational();
  r_t3.ZeroRational();
  r_t4.ZeroRational();
  r_t5.ZeroRational();
  r_t6.ZeroRational();
  r_t7.ZeroRational();
  r_t8.ZeroRational();

  p_t1.OnePoly();
  // x+1
  p_t2.c_array_[0]->m_pValue[0]= 1;
  p_t2.c_array_[1]->m_pValue[0]= 1;
  p_t3.ZeroPoly();
  p_t4.ZeroPoly();
  p_t5.ZeroPoly();
  p_t6.ZeroPoly();

  printf("\n");
  if(!PolyAdd(p_t1, p_t1, p_t6)) {
    printf("PolyAdd fails\n");
  }
  smallprintpoly(p_t1); printf("+ ");
  smallprintpoly(p_t1); printf("= ");
  smallprintpoly(p_t6, true); printf("\n");
  p_t6.ZeroPoly();

  if(!PolyAdd(p_t1, p_t3, p_t6)) {
    printf("PolyAdd fails\n");
  }
  smallprintpoly(p_t1); printf("+ ");
  smallprintpoly(p_t3); printf("= ");
  smallprintpoly(p_t6, true); printf("\n");
  p_t6.ZeroPoly();

  if(!PolyAdd(p_t2, p_t2, p_t6)) {
    printf("PolyAdd fails\n");
  }
  smallprintpoly(p_t2); printf("+ ");
  smallprintpoly(p_t2); printf("= ");
  smallprintpoly(p_t6, true); printf("\n");
  p_t6.ZeroPoly();

  printf("\n");
  if(!PolySub(p_t1, p_t1, p_t6)) {
    printf("PolySub fails\n");
  }
  smallprintpoly(p_t1); printf("- ");
  smallprintpoly(p_t1); printf("= ");
  smallprintpoly(p_t6, true); printf("\n");
  p_t6.ZeroPoly();

  if(!PolySub(p_t2, p_t3, p_t6)) {
    printf("PolySub fails\n");
  }
  smallprintpoly(p_t1); printf("- ");
  smallprintpoly(p_t3); printf("= ");
  smallprintpoly(p_t6, true); printf("\n");
  p_t6.ZeroPoly();

  if(!PolySub(p_t1, p_t2, p_t6)) {
    printf("PolySub fails\n");
  }
  smallprintpoly(p_t1); printf("- ");
  smallprintpoly(p_t2); printf("= ");
  smallprintpoly(p_t6, true); printf("\n");
  p_t6.ZeroPoly();
  
  printf("\n");
  if(!PolyMult(p_t1, p_t2, p_t6)) {
    printf("PolyMult fails\n");
  }
  smallprintpoly(p_t1); printf("* ");
  smallprintpoly(p_t2); printf("= ");
  smallprintpoly(p_t6, true); printf("\n");
  p_t6.ZeroPoly();
  
  if(!PolyMult(p_t2, p_t2, p_t6)) {
    printf("PolyMult fails\n");
  }
  smallprintpoly(p_t2); printf("* ");
  smallprintpoly(p_t2); printf("= ");
  smallprintpoly(p_t6, true); printf("\n");

  if(!PolyMult(p_t6, p_t6, p_t5)) {
    printf("PolyMult fails\n");
  }
  smallprintpoly(p_t6); printf("* ");
  smallprintpoly(p_t6); printf("= ");
  smallprintpoly(p_t5, true); printf("\n");
  p_t6.ZeroPoly();
  p_t4.ZeroPoly();

  printf("\n");
  p_t5.Copyto(p_t4);
  printf("Copy ");
  smallprintpoly(p_t5, true);
  printf(" to ");
  smallprintpoly(p_t4, true);
  printf("\n");
  p_t4.ZeroPoly();
  p_t4.Copyfrom(p_t5);
  printf("Copy ");
  smallprintpoly(p_t4, true);
  printf(" from ");
  p_t4.Copyfrom(p_t5);
  smallprintpoly(p_t5, true);
  printf("\n");

  printf("\n");
  smallprintpoly(p_t5);
  if(PolyisEqual(p_t5, p_t5)) {
    printf(" == ");
  }
  else {
    printf(" != ");
  }
  smallprintpoly(p_t5);
  printf("\n");
  smallprintpoly(p_t5);
  if(PolyisEqual(p_t5, p_t1)) {
    printf(" == ");
  }
  else {
    printf(" != ");
  }
  smallprintpoly(p_t1);
  printf("\n");

  p_t4.ZeroPoly();
  p_t6.ZeroPoly();
  printf("\n");
  printf("Euclid: ");
  if(!PolyEuclid(p_t5, p_t2, p_t4, p_t6)) {
    printf("PolyEuclid fails\n");
  }
  smallprintpoly(p_t5); printf("= ");
  smallprintpoly(p_t2); printf(" (");
  smallprintpoly(p_t4); printf(") + ");
  smallprintpoly(p_t6); printf("\n");

  p_t4.ZeroPoly();
  p_t6.ZeroPoly();
  p_t3.c_array_[0]->m_pValue[0]= test_prime-1;
  p_t3.c_array_[1]->m_pValue[0]= 1;
  printf("Euclid: ");
  if(!PolyEuclid(p_t5, p_t3, p_t4, p_t6)) {
    printf("PolyEuclid fails\n");
  }
  smallprintpoly(p_t5); printf("= ");
  smallprintpoly(p_t3); printf(" (");
  smallprintpoly(p_t4); printf(") + ");
  smallprintpoly(p_t6); printf("\n");
  printf("\n");


  p_t1.ZeroPoly();
  p_t4.ZeroPoly();
  p_t6.ZeroPoly();
  printf("Extended gcd: ");
  if(!PolyExtendedgcd(p_t5, p_t2, p_t4, p_t1, p_t6)) {
    printf("Polyextendedgcd fails\n");
  }
  smallprintpoly(p_t6); printf("= (");
  smallprintpoly(p_t5); printf(") (");
  smallprintpoly(p_t4); printf(") + (");
  smallprintpoly(p_t2); printf(") (");
  smallprintpoly(p_t1); printf(")");
  printf("\n");

  if(!MakeInfPoint(r_t1, r_t2)) {
    printf("MakeInfPoint fails\n");
  }
  printf("Infinity: (");
  smallprintrational(r_t1); 
  printf(", ");
  smallprintrational(r_t2); 
  printf(")\n");
  if(IsInfPoint(r_t1, r_t2)) {
    printf("validates as infinity\n");
  }
  else {
    printf("does not validate as infinity\n");
  }
  printf("\n");

  p_t2.c_array_[0]->m_pValue[0]= 1;
  p_t2.c_array_[1]->m_pValue[0]= 1;
  p_t3.c_array_[0]->m_pValue[0]= 96;
  p_t3.c_array_[1]->m_pValue[0]= 1;
  r_t1.numerator->Copyfrom(p_t2);
  r_t1.denominator->OnePoly();

  r_t2.numerator->Copyfrom(p_t3);
  r_t2.denominator->OnePoly();

  if(!RationalAdd(r_t1, r_t2, r_t3)) {
    printf("RationalAdd fails\n");
  }
  smallprintrational(r_t1); printf(" + ");
  smallprintrational(r_t2); printf(" = ");
  smallprintrational(r_t3); printf("\n");
  printf("\n");

  r_t2.ZeroRational();
  r_t2.numerator->OnePoly();
  r_t2.denominator->Copyfrom(p_t3);
  if(!RationalAdd(r_t1, r_t2, r_t3)) {
    printf("RationalAdd fails\n");
  }
  smallprintrational(r_t1); printf(" + ");
  smallprintrational(r_t2); printf(" = ");
  smallprintrational(r_t3); printf("\n");
  printf("\n");

  r_t2.numerator->Copyfrom(p_t3);
  r_t2.denominator->OnePoly();

  if(!RationalSub(r_t1, r_t2, r_t3)) {
    printf("RationalSub fails\n");
  }
  smallprintrational(r_t1); printf(" - ");
  smallprintrational(r_t2); printf(" = ");
  smallprintrational(r_t3); printf("\n");

  r_t2.ZeroRational();
  r_t2.numerator->OnePoly();
  r_t2.denominator->Copyfrom(p_t3);
  if(!RationalSub(r_t1, r_t2, r_t3)) {
    printf("RationalSub fails\n");
  }
  smallprintrational(r_t1); printf(" - ");
  smallprintrational(r_t2); printf(" = ");
  smallprintrational(r_t3); printf("\n");
  printf("\n");

  if(!RationalMult(r_t1, r_t2, r_t3)) {
    printf("RationalMult fails\n");
  }
  smallprintrational(r_t1); printf(" * ");
  smallprintrational(r_t2); printf(" = ");
  smallprintrational(r_t3); printf("\n");
  if(!RationalMult(r_t3, r_t3, r_t4)) {
    printf("RationalMult fails\n");
  }
  smallprintrational(r_t3); printf(" * ");
  smallprintrational(r_t3); printf(" = ");
  smallprintrational(r_t4); printf("\n");
  printf("\n");

  if(!RationalDiv(r_t1, r_t2, r_t3)) {
    printf("RationalDiv fails\n");
  }
  smallprintrational(r_t1); printf(" / ");
  smallprintrational(r_t2); printf(" = ");
  smallprintrational(r_t3); printf("\n");
  if(!RationalDiv(r_t3, r_t3, r_t4)) {
    printf("RationalDiv fails\n");
  }
  smallprintrational(r_t3); printf(" / ");
  smallprintrational(r_t3); printf(" = ");
  smallprintrational(r_t4); printf("\n");
  printf("\n");

  r_t1.OneRational();
  r_t1.numerator->c_array_[0]->m_pValue[0]= 5ULL;
  smallprintrational(r_t1); printf(" * ");
  smallprintrational(r_t3); printf(" = ");
  if(!RationalMultBy(r_t3, r_t1)) {
    printf("RationalMultBy fails\n");
  }
  smallprintrational(r_t3); printf("\n");
  printf("\n");

  if(RationalisEqual(r_t3, r_t3)) {
    smallprintrational(r_t3); printf(" == ");
    smallprintrational(r_t3); printf("\n");
  }
  else {
    smallprintrational(r_t3); printf(" != ");
    smallprintrational(r_t3); printf("\n");
  }
  if(RationalisEqual(r_t1, r_t3)) {
    smallprintrational(r_t1); printf(" == ");
    smallprintrational(r_t3); printf("\n");
  }
  else {
    smallprintrational(r_t1); printf(" != ");
    smallprintrational(r_t3); printf("\n");
  }
  printf("\n");

  MakeInfPoint(r_t1, r_t2);

  r_t3.ZeroRational();
  r_t4.OneRational();
  r_t3.numerator->c_array_[1]->m_pValue[0]= 1ULL;
  if(!EccSymbolicAdd(curve_x_poly, r_t1, r_t2, r_t3, r_t4, r_t5, r_t6)) {
    printf("EccSymbolicAdd fails\n");
  }
  printf("( ");
  smallprintrational(r_t1); 
  printf(", ");
  smallprintrational(r_t2); 
  printf(" + (");
  smallprintrational(r_t3); 
  printf(", ");
  smallprintrational(r_t4); 
  printf(") = ");
  printf("( ");
  smallprintrational(r_t5); 
  printf(", ");
  smallprintrational(r_t6); 
  printf(")\n");

  if(!EccSymbolicAdd(curve_x_poly, r_t3, r_t4, r_t3, r_t4, r_t5, r_t6)) {
    printf("EccSymbolicAdd fails\n");
  }
  printf("( ");
  smallprintrational(r_t3); 
  printf(", ");
  smallprintrational(r_t4); 
  printf(" + (");
  smallprintrational(r_t3); 
  printf(", ");
  smallprintrational(r_t4); 
  printf(") = ");
  printf("( ");
  smallprintrational(r_t5); 
  printf(", ");
  smallprintrational(r_t6); 
  printf(")\n");

  r_t7.ZeroRational();
  r_t7.numerator->c_array_[2]->m_pValue[0]= 1ULL;
  r_t8.ZeroRational();
  r_t8.numerator->c_array_[1]->m_pValue[0]= 1ULL;
  if(!EccSymbolicAdd(curve_x_poly, r_t7, r_t8, r_t3, r_t4, r_t5, r_t6)) {
    printf("EccSymbolicAdd fails\n");
  }
  printf("( ");
  smallprintrational(r_t7); 
  printf(", ");
  smallprintrational(r_t8); 
  printf(" + (");
  smallprintrational(r_t3); 
  printf(", ");
  smallprintrational(r_t4); 
  printf(") = ");
  printf("( ");
  smallprintrational(r_t5); 
  printf(", ");
  smallprintrational(r_t6); 
  printf(")\n");

  int t= 1; 
  if(!EccSymbolicPointMult(curve_x_poly, t, r_t3, r_t4, r_t5, r_t6)) {
    printf("EccSymbolicPointMult fails\n");
  }
  printf("%lld( ", t);
  smallprintrational(r_t3); 
  printf(", ");
  smallprintrational(r_t4); 
  printf(") = ");
  printf("( ");
  smallprintrational(r_t5); 
  printf(", ");
  smallprintrational(r_t6); 
  printf(")\n");
  t= 2;
  if(!EccSymbolicPointMult(curve_x_poly, t, r_t3, r_t4, r_t5, r_t6)) {
    printf("EccSymbolicPointMult fails\n");
  }
  printf("%lld( ", t);
  smallprintrational(r_t3); 
  printf(", ");
  smallprintrational(r_t4); 
  printf(") = ");
  printf("( ");
  smallprintrational(r_t5); 
  printf(", ");
  smallprintrational(r_t6); 
  printf(")\n");

  t= 3;
  if(!EccSymbolicPointMult(curve_x_poly, t, r_t3, r_t4, r_t5, r_t6)) {
    printf("EccSymbolicPointMult fails\n");
  }
  printf("%lld( ", t);
  smallprintrational(r_t3); 
  printf(", ");
  smallprintrational(r_t4); 
  printf(") = ");
  printf("( ");
  smallprintrational(r_t5); 
  printf(", ");
  smallprintrational(r_t6); 
  printf(")\n");
  printf("\n");

  if(!ComputeMultEndomorphism(curve_x_poly, t, r_t7, r_t8)) {
    printf("ComputeMultEndomorphism fails\n");
  }
  printf("Endomorphism %lld(x,y) :", t);
  printf("( ");
  smallprintrational(r_t7); 
  printf(", ");
  smallprintrational(r_t8); 
  printf(")\n");

  p_t7.ZeroPoly();
  if(!Reducelargepower(p, x_poly, curve_x_poly, p_t7)) {
    printf("Reducelargepower fails\n");
  }
  printf("x^%d= ", test_prime);
  smallprintpoly(p_t7); 
  printf("\n");
  printf("\n");

  if(!ComputePowerEndomorphism(curve_x_poly, p, r_t7, r_t8)) {
    printf("ComputePowerEndomorphism fails\n");
  }
  printf("Frobenius_%d(x,y)= (", test_prime);
  smallprintrational(r_t7); 
  printf(", ");
  smallprintrational(r_t8); 
  printf(")\n");
  printf("\n");
}

#endif


// ----------------------------------------------------------------------------
