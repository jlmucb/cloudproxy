//
//  File: polyarith.cc
//  Description: polynomial arithmetic
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


// #define JLMDEBUG

// ----------------------------------------------------------------------------


polynomial::polynomial(bnum& p, int numc, int sizenum) {
  characteristic_= NULL;
  c_array_= new bnum* [numc];
  numc_= numc;
  size_num_= sizenum;
  int i;
  for(i=0; i<numc; i++)
      c_array_[i]= new bnum(sizenum);
  characteristic_= new bnum(p.mpSize());
  p.mpCopyNum(*characteristic_);
}

polynomial::~polynomial() {
  int i;

  if(c_array_==NULL)
    return;
  for(i=0; i<numc_; i++)
    if(c_array_[i]!=NULL)
      delete c_array_[i];
  delete c_array_;
   c_array_= NULL;
  c_array_= NULL;
  if(characteristic_!=NULL)
    delete characteristic_;
  characteristic_= NULL;
}


void polynomial::ZeroPoly() {
  int i;
  for(i=0; i<numc_; i++)
    mpZeroNum(*c_array_[i]);
}


void polynomial::OnePoly() {
  int i;
  for(i=1; i<numc_; i++)
    mpZeroNum(*c_array_[i]);
  c_array_[0]->m_pValue[0]= 1ULL;
}


bool polynomial::IsZero() {
  int i;

  if(numc_<=0)
    return true;
  for(i=0; i<numc_; i++)
    if(!c_array_[i]->mpIsZero())
      return false;
  return true;
}


bool polynomial::IsOne() {
  int i;

  if(numc_<=0)
    return true;
  for(i=1; i<numc_; i++)
    if(!c_array_[i]->mpIsZero())
      return false;
  if(c_array_[0]->m_pValue[0]==1ULL)
    return true;
  return false;
}


bool polynomial::Copyfrom(polynomial& from) {
  int   i, j;

  for(i=from.numc_-1;i>0;i--) {
    if(!from.c_array_[i]->mpIsZero())
      break;
  }
  if(i>=numc_)
    return false;
  ZeroPoly();
  for(j=0; j<=i; j++)
    from.c_array_[j]->mpCopyNum(*c_array_[j]);
  return true;
}


bool polynomial::Copyto(polynomial& to) {
  int   i, j;

  for(i=numc_-1;i>0;i--) {
    if(!c_array_[i]->mpIsZero())
      break;
  }
  if(i>=to.numc_)
    return false;
  to.ZeroPoly();
  for(j=0; j<=i; j++)
    c_array_[j]->mpCopyNum(*to.c_array_[j]);
  return true;
}


int polynomial::Degree() {
  int i= numc_-1;
  while(i>=0 && c_array_[i]->mpIsZero())
    i--;
  return i;
}


bool polynomial::MultiplyByNum(bnum& c) {
  int j, k, n;

  n= 0;
  for(j=0;j<numc_;j++) {
    k= c_array_[j]->mpSize();
    if(k>n)
      n= k;
  }
  bnum  t(n+1);
  for(j=0;j<numc_;j++) {
    mpZeroNum(t);
    mpModMult(*c_array_[j],c,*characteristic_,t);
    t.mpCopyNum(*c_array_[j]);
  }
  return true;
}

void printpoly(polynomial& p) {
  int i;

  if(p.Degree()<0) {
    printf("0\n");
    return;
  }
  for(i=p.Degree(); i>=0; i--) {
    printNumberToConsole(*p.c_array_[i]);
    printf(" * x**%d +", i);
  }
  printf(", Characteristic, ");
  printNumberToConsole(*p.characteristic_);
  printf("\n");
}

rationalpoly::rationalpoly(bnum& p, int numc1, int sizenum1, int numc2, int sizenum2) {
  numerator= new polynomial(p, numc1, sizenum1);
  denominator= new polynomial(p, numc2, sizenum2);
}

rationalpoly::~rationalpoly() {
  delete numerator;
  delete denominator;
  numerator= NULL;
  denominator= NULL;
}

void rationalpoly::ZeroRational() {
  numerator->ZeroPoly();
  denominator->OnePoly();
}

void rationalpoly::OneRational() {
  numerator->OnePoly();
  denominator->OnePoly();
}

void rationalpoly::InfRational() {
  numerator->OnePoly();
  denominator->ZeroPoly();
}

bool rationalpoly::Copyfrom(rationalpoly& from) {
  numerator->Copyfrom(*from.numerator);
  denominator->Copyfrom(*from.denominator);
  return true;
}

bool rationalpoly::Copyto(rationalpoly& to) {
  numerator->Copyto(*to.numerator);
  denominator->Copyto(*to.denominator);
  return true;
}


// ----------------------------------------------------------------------------


// in1(x)+in2(x)= out(x)
bool PolyAdd(polynomial& in1, polynomial& in2, polynomial& out) {
  int j;

  if(out.numc_<in1.numc_ || out.numc_<in2.numc_)
    return false;
  if(mpCompare(*in1.characteristic_, *in2.characteristic_)!=0 || 
      mpCompare(*in1.characteristic_, *out.characteristic_)!=0)
    return false;
  out.ZeroPoly();

  if(in1.characteristic_->mpIsZero()) {
    if(in1.numc_>in2.numc_) {
      for(j=0; j<in2.numc_; j++)
        mpAdd(*in1.c_array_[j], *in2.c_array_[j], *out.c_array_[j]);
      for(;j<in1.numc_;j++)
        in1.c_array_[j]->mpCopyNum(*out.c_array_[j]);
    } else {
      for(j=0; j<in1.numc_; j++)
        mpAdd(*in1.c_array_[j], *in2.c_array_[j], *out.c_array_[j]);
      for(;j<in2.numc_;j++)
        in2.c_array_[j]->mpCopyNum(*out.c_array_[j]);
    }
  } else {
    if(in1.numc_>in2.numc_) {
      for(j=0; j<in2.numc_; j++)
        mpModAdd(*in1.c_array_[j], *in2.c_array_[j], *in1.characteristic_, *out.c_array_[j]);
      for(;j<in1.numc_;j++)
        in1.c_array_[j]->mpCopyNum(*out.c_array_[j]);
    } else {
      for(j=0; j<in1.numc_; j++)
        mpModAdd(*in1.c_array_[j], *in2.c_array_[j], *in1.characteristic_, *out.c_array_[j]);
      for(;j<in2.numc_;j++)
        in2.c_array_[j]->mpCopyNum(*out.c_array_[j]);
    }
  }
  return true;
}


// in1(x)-in2(x)= out(x)
bool PolySub(polynomial& in1, polynomial& in2, polynomial& out) {
  int j;

  if(out.numc_<in1.numc_ || out.numc_<in2.numc_)
    return false;
  if(mpCompare(*in1.characteristic_, *in2.characteristic_)!=0 || 
      mpCompare(*in1.characteristic_, *out.characteristic_)!=0)
    return false;
  out.ZeroPoly();

  if(in1.characteristic_->mpIsZero()) {
    if(in1.numc_>in2.numc_) {
      for(j=0; j<in2.numc_; j++)
        mpSub(*in1.c_array_[j], *in2.c_array_[j], *out.c_array_[j]);
      for(;j<in1.numc_;j++)
        in1.c_array_[j]->mpCopyNum(*out.c_array_[j]);
    } else {
      for(j=0; j<in1.numc_; j++)
        mpSub(*in1.c_array_[j], *in2.c_array_[j], *out.c_array_[j]);
      for(;j<in2.numc_;j++)
        mpSub(g_bnZero, *in2.c_array_[j], *out.c_array_[j]);
    }
  } else {
    if(in1.numc_>in2.numc_) {
      for(j=0; j<in2.numc_; j++)
        mpModSub(*in1.c_array_[j], *in2.c_array_[j], *in1.characteristic_, *out.c_array_[j]);
      for(;j<in1.numc_;j++)
        in1.c_array_[j]->mpCopyNum(*out.c_array_[j]);
    } else {
      for(j=0; j<in1.numc_; j++)
        mpModSub(*in1.c_array_[j], *in2.c_array_[j], *in1.characteristic_, *out.c_array_[j]);
      for(;j<in2.numc_;j++)
        mpModSub(g_bnZero, *in2.c_array_[j], *in1.characteristic_, *out.c_array_[j]);
    }
  }
  return true;
}


// in1(x)*in2(x)= out(x), p is characteristic, 0 if integers
bool PolyMult(polynomial& in1, polynomial& in2, polynomial& out) {
  int i, j, k;

  if(mpCompare(*in1.characteristic_, *in2.characteristic_)!=0 || 
      mpCompare(*in1.characteristic_, *out.characteristic_)!=0)
    return false;
  // output size
  for(j=in1.numc_-1;j>0;j--) {
    if(!in1.c_array_[j]->mpIsZero())
      break;
  }
  for(i=in2.numc_-1;i>0;i--) {
    if(!in2.c_array_[i]->mpIsZero())
      break;
  }
  k= i+j;
  if(out.numc_<=k)
    return false;
  out.ZeroPoly();
  if(in1.characteristic_->mpIsZero()) {
    bnum  c(in1.c_array_[0]->mpSize());
    bnum  t(in1.c_array_[0]->mpSize());
    int m, n;

    for(i=k;i>=0;i--) {
      mpZeroNum(c);
      for(m=i; m>=0; m--) {
        if(m>=in1.numc_ || in1.c_array_[m]->mpIsZero())
          continue;
        n= i-m;
        if(n>=in2.numc_ || in2.c_array_[m]->mpIsZero())
          continue;
        mpZeroNum(t);
        mpMult(*in1.c_array_[m], *in2.c_array_[n], t);
        mpAddTo(c,t);
      }
      c.mpCopyNum(*out.c_array_[i]);
    }
  } else {
    bnum  c(2*in1.characteristic_->mpSize());
    bnum  t1(2*in1.characteristic_->mpSize());
    bnum  t2(2*in1.characteristic_->mpSize());
    int m, n;

    for(i=k;i>=0;i--) {
      mpZeroNum(c);
      for(m=i; m>=0; m--) {
        if(m>=in1.numc_ || in1.c_array_[m]->mpIsZero())
          continue;
        n= i-m;
        if(n>=in2.numc_ || in2.c_array_[n]->mpIsZero())
            continue;
        mpZeroNum(t1);
        mpZeroNum(t2);
        mpModMult(*in1.c_array_[m], *in2.c_array_[n], *in1.characteristic_, t1);
        mpModAdd(c,t1,*in1.characteristic_,t2);
        mpZeroNum(c);
        t2.mpCopyNum(c);
        }
      c.mpCopyNum(*out.c_array_[i]);
    }
  }
  return true;
}

// a(x)= b(x)*q(x)+r(x), deg(r(x))<deg(b(x))
bool PolyEuclid(polynomial& a, polynomial& b, polynomial& q, polynomial& r) {
  int   deg_a= a.Degree();
  int   deg_b= b.Degree();
  int   deg_r;
  bnum* p_b_lead_coeff;
  bnum* p_r_lead_coeff;

  if(deg_a<deg_b) {
    printf("PolyEuclid degree(b)>degree(a)\n");
    return false;
  }
  // prime characteristic only, for now
  if(a.characteristic_->mpIsZero()) {
    printf("PolyEuclid only works in finite fields\n");
    return false;
  }
  polynomial  prod_temp(*a.characteristic_, a.numc_, 2*(a.characteristic_->mpSize()));

  q.ZeroPoly();
  r.ZeroPoly();
  a.Copyto(r);
  p_b_lead_coeff= b.c_array_[deg_b];

  while((deg_r=r.Degree())>=deg_b && deg_b>=0) {
    // Subtract leadcoeff(r)/leadcoeff(b)*b(x)*x^(deg_r-deg_b) from r
    p_r_lead_coeff= r.c_array_[deg_r];
    mpModDiv(*p_r_lead_coeff, *p_b_lead_coeff, *a.characteristic_, *q.c_array_[deg_r-deg_b]);
    prod_temp.ZeroPoly();
    PolyMult(b, q, prod_temp);
    PolySub(a, prod_temp, r);
  }
  return true;
}


// a(x)*c(x)+b(x)*d(x)= g(x), p is characteristic, 0 if integers, g(x) is gcd
// deg a(x)>=deg b(x)
bool PolyExtendedgcd(polynomial& a, polynomial& b, 
                     polynomial& c, polynomial& d, polynomial& g) {
  int prior= 0;
  int current= 1;
  int next= 2;
  int num_coeff, size_num;
  int i;

  if(mpCompare(*a.characteristic_, *b.characteristic_)!=0 || 
      mpCompare(*a.characteristic_, *c.characteristic_)!=0 ||
      mpCompare(*a.characteristic_, *d.characteristic_)!=0 ||
      mpCompare(*a.characteristic_, *g.characteristic_)!=0)
    return false;

  c.ZeroPoly();
  d.ZeroPoly();
  g.ZeroPoly();

  num_coeff= 2*a.numc_;
  if(a.characteristic_->mpIsZero())
    size_num= 2*(a.c_array_[0]->mpSize()+b.c_array_[0]->mpSize());
  else
    size_num= 2*a.characteristic_->mpSize();

  polynomial* t_c[3];
  polynomial* t_d[3];
  polynomial* t_g[3];
  polynomial  q(*a.characteristic_, num_coeff, size_num);
  polynomial  r(*a.characteristic_, num_coeff, size_num);
  polynomial  temp(*a.characteristic_, num_coeff, size_num);
  bnum*       p_num= NULL;

  for(i=0; i<3;i++) {
    t_c[i]= new polynomial(*a.characteristic_, num_coeff, size_num);
    t_d[i]= new polynomial(*a.characteristic_, num_coeff, size_num);
    t_g[i]= new polynomial(*a.characteristic_, num_coeff, size_num);
  }

  p_num= t_c[prior]->c_array_[0];
  p_num->m_pValue[0]= 1ULL;
  p_num= t_d[prior]->c_array_[0];
  p_num->m_pValue[0]= 0ULL;
  p_num= t_c[current]->c_array_[0];
  p_num->m_pValue[0]= 0ULL;
  p_num= t_d[current]->c_array_[0];
  p_num->m_pValue[0]= 1ULL;
  t_g[prior]->Copyfrom(a);
  t_g[current]->Copyfrom(b);

  if(t_g[current]->Degree()==0 || t_g[current]->IsZero()) {
    t_g[current]->Copyto(g);
    t_c[current]->Copyto(c);
    t_d[current]->Copyto(d);
    return true;
  }

#ifdef JLMDEBUG1
  printf("PolyExtendedgcd\n");
  printf("c: "); printpoly(*t_c[prior]);
  printf("d: "); printpoly(*t_d[prior]);
  printf("g: "); printpoly(*t_g[prior]);
  printf("-----------\n");
  printf("c: "); printpoly(*t_c[current]);
  printf("d: "); printpoly(*t_d[current]);
  printf("g: "); printpoly(*t_g[current]);
#endif

  while(1) {
    t_g[next]->ZeroPoly();
    t_c[next]->ZeroPoly();
    t_d[next]->ZeroPoly();
    q.ZeroPoly();
    r.ZeroPoly();
    if(!PolyEuclid(*t_g[prior], *t_g[current], q, r)) {
      return false;
    }
    temp.ZeroPoly();
    PolyMult(*t_c[current], q, temp);
    PolySub(*t_c[prior], temp, *t_c[next]);
    temp.ZeroPoly();
    PolyMult(*t_d[current], q, temp);
    PolySub(*t_d[prior], temp, *t_d[next]);
    temp.ZeroPoly();
    PolyMult(*t_g[current], q, temp);
    PolySub(*t_g[prior], temp, *t_g[next]);
#ifdef JLMDEBUG1
    printf("-----------\n");
    printf("c: "); printpoly(*t_c[next]);
    printf("d: "); printpoly(*t_d[next]);
    printf("g: "); printpoly(*t_g[next]);
    printf("q: "); printpoly(q);
    printf("r: "); printpoly(r);
#endif
    if(r.IsZero()) {
      t_g[current]->Copyto(g);
      t_c[next]->Copyto(c);
      t_d[next]->Copyto(d);
      return true;
    }
    if(r.Degree()<=0) {
      t_g[next]->Copyto(g);
      t_c[next]->Copyto(c);
      t_d[next]->Copyto(d);
      return true;
    }
    prior= (prior+1)%3;
    current= (current+1)%3;
    next= (next+1)%3;
  }
  return true;
}


// floor(sqrt num) <= result < ceiling(sqrt num)
bool SquareRoot(bnum& num , bnum& result) {
  bnum left(num.mpSize());
  bnum right(num.mpSize());
  bnum guess(num.mpSize());
  bnum temp(num.mpSize());
  int  i, compare;

  g_bnZero.mpCopyNum(left);
  num.mpCopyNum(right);
  for(i=0;i<mpBitsinNum(num.mpSize(), num.m_pValue);i++) {
    mpZeroNum(temp);
    mpAdd(left, right, temp);
    mpShift(temp, -1, guess);
    mpZeroNum(temp);
    mpMult(guess, guess, temp);
    compare= mpCompare(num, temp);
    if(compare==s_isLessThan) {
      guess.mpCopyNum(right);
    }
    else if(compare==s_isGreaterThan) {
      guess.mpCopyNum(left);
    } else {
      guess.mpCopyNum(result);
      return true;
    }
  }
  // only two left
  mpZeroNum(temp);
  mpMult(right, right, temp);
  compare= mpCompare(num, temp);
  if(compare==s_isLessThan)
    left.mpCopyNum(result);
  else
    right.mpCopyNum(result);
  return true;
}


bool Reducelargepower(bnum& power, polynomial& mod_poly, polynomial& result) {
  int j;

  if(mpCompare(*mod_poly.characteristic_, *result.characteristic_)!=0)
    return false;

  int n= mpBitsinNum(power.mpSize(), power.m_pValue);
  if(n==0) {  // x^0=1
    g_bnOne.mpCopyNum(*result.c_array_[0]);
    return true;
  }

  polynomial   q(*mod_poly.characteristic_, 2*mod_poly.numc_, mod_poly.size_num_);
  polynomial   current_poly_power(*mod_poly.characteristic_, 2*mod_poly.numc_, mod_poly.size_num_);
  polynomial   current_poly_accum(*mod_poly.characteristic_, 2*mod_poly.numc_, mod_poly.size_num_);
  polynomial   temp_poly(*mod_poly.characteristic_, 2*mod_poly.numc_, mod_poly.size_num_);
  polynomial   square(*mod_poly.characteristic_, 2*mod_poly.numc_, mod_poly.size_num_);
  int          deg_mod_poly= mod_poly.Degree();

  current_poly_power.c_array_[1]->m_pValue[0]= 1ULL;  // x
  current_poly_accum.c_array_[0]->m_pValue[0]= 1ULL;  // 1

  for(j=1; j<=n; j++) {
    if(IsBitPositionNonZero(power,j)) {
      temp_poly.ZeroPoly();
      PolyMult(current_poly_power, current_poly_accum, temp_poly);
      if(temp_poly.Degree()>=deg_mod_poly) {  // reduce mod mod_poly
        q.ZeroPoly();
        if(!PolyEuclid(temp_poly, mod_poly, q, current_poly_accum))
          return false;
      } else {
        temp_poly.Copyto(current_poly_accum);
      }
    }

    if(j==n)
      break;
    // next square
    square.ZeroPoly();
    if(!PolyMult(current_poly_power, current_poly_power, square))
      return false;
    current_poly_power.ZeroPoly();
    if(square.Degree()>=deg_mod_poly) {  // reduce mod mod_poly
      if(!PolyEuclid(square, mod_poly, q, current_poly_power))
        return false;
    }
    else {
      square.Copyto(current_poly_power);
    }
  }
  result.ZeroPoly();
  current_poly_accum.Copyto(result);
  return true;
}

bool PolyisEqual(polynomial& in1, polynomial& in2) {
  int   j;

  if(in1.numc_>in2.numc_) {
    for(j=0; j<in2.numc_; j++) {
      if(mpCompare(*in1.c_array_[j], *in2.c_array_[j]) != s_isEqualTo)
        return false;
    }
    for(j=in2.numc_; j<in1.numc_; j++) {
      if(mpCompare(g_bnZero, *in1.c_array_[j]) != s_isEqualTo)
        return false;
    }
  } else {
    for(j=0; j<in1.numc_; j++) {
      if(mpCompare(*in1.c_array_[j], *in2.c_array_[j]) != s_isEqualTo)
        return false;
    }
    for(j=in1.numc_; j<in2.numc_; j++) {
      if(mpCompare(g_bnZero, *in2.c_array_[j]) != s_isEqualTo)
        return false;
    }
  }
  return true;
}


// ----------------------------------------------------------------------------


bool MakeInfPoint(rationalpoly& x, rationalpoly& y) {
  x.ZeroRational();
  y.InfRational();
  return true;
}

bool IsInfPoint(rationalpoly& x, rationalpoly& y) {
  return x.numerator->IsZero() && x.denominator->IsOne() &&
         y.numerator->IsOne() && y.denominator->IsZero();
}

// (in1.numerator in2.deniminator + in2.numerator in1.denominator)/ (in1.denominator in2.denominator)
bool RationalAdd(rationalpoly& in1, rationalpoly& in2, rationalpoly& out) {
  bnum* p= in1.numerator->characteristic_;
  int   nn= in1.numerator->numc_;
  int   nd= in1.denominator->numc_;

  if(in2.numerator->numc_>nn)
    nn= in2.numerator->numc_;
  if(in2.denominator->numc_>nd)
    nd= in2.denominator->numc_;

  polynomial t1(*p, nn+nd, p->mpSize());
  polynomial t2(*p, nn+nd, p->mpSize());
  polynomial top(*p, nn+nd, p->mpSize());
  polynomial bottom(*p, 2*nd, p->mpSize());

  if(!PolyMult(*in1.numerator,*in2.denominator, t1))
    return false;
  if(!PolyMult(*in2.numerator,*in1.denominator, t2))
    return false;
  if(!PolyAdd(t1, t2, top))
    return false;
  if(!PolyMult(*in1.denominator,*in2.denominator, bottom))
    return false;
  out.numerator->Copyfrom(top);
  out.denominator->Copyfrom(bottom);
  if(!RationalReduce(out))
    return false;
  return true;
}

bool RationalSub(rationalpoly& in1, rationalpoly& in2, rationalpoly& out) {
  bnum* p= in1.numerator->characteristic_;
  int   nn= in1.numerator->numc_;
  int   nd= in1.denominator->numc_;

  if(in2.numerator->numc_>nn)
    nn= in2.numerator->numc_;
  if(in2.denominator->numc_>nd)
    nd= in2.denominator->numc_;

  polynomial t1(*p, nn+nd, p->mpSize());
  polynomial t2(*p, nn+nd, p->mpSize());
  polynomial top(*p, nn+nd, p->mpSize());
  polynomial bottom(*p, 2*nd, p->mpSize());

  if(!PolyMult(*in1.numerator,*in2.denominator, t1))
    return false;
  if(!PolyMult(*in2.numerator,*in1.denominator, t2))
    return false;
  if(!PolySub(t1, t2, top))
    return false;
  if(!PolyMult(*in1.denominator,*in2.denominator, bottom))
    return false;
  out.numerator->Copyfrom(top);
  out.denominator->Copyfrom(bottom);
  if(!RationalReduce(out))
    return false;
  return true;
}

bool RationalMult(rationalpoly& in1, rationalpoly& in2, rationalpoly& out) {
  if(!PolyMult(*in1.numerator, *in2.numerator, *out.numerator))
    return false;
  if(!PolyMult(*in1.denominator, *in2.denominator, *out.denominator))
    return false;
  if(!RationalReduce(out))
    return false;
  return true;
}

bool RationalDiv(rationalpoly& in1, rationalpoly& in2, rationalpoly& out) {
  if(!PolyMult(*in1.numerator, *in2.denominator, *out.numerator))
    return false;
  if(!PolyMult(*in1.denominator, *in2.numerator, *out.denominator))
    return false;
  if(!RationalReduce(out))
    return false;
  return true;
}

bool RationalReduce(rationalpoly& inout) {
  bnum* p= inout.numerator->characteristic_;
  int   nn= inout.numerator->numc_;
  int   nd= inout.denominator->numc_;

#ifdef JLMDEBUG
  printf("RationalReduce in\n"); printrational(inout);
#endif

  polynomial num(*p, nn, p->mpSize());
  polynomial den(*p, nd, p->mpSize());

  num.Copyfrom(*inout.numerator);
  den.Copyfrom(*inout.denominator);
  int n= nn;
  if(nd>nn)
      n= nd;

  polynomial t1(*p, n, p->mpSize());
  polynomial t2(*p, n, p->mpSize());
  polynomial t3(*p, n, p->mpSize());
  polynomial g(*p, n, p->mpSize());

  if(num.Degree()>=den.Degree()) {
    if(!PolyExtendedgcd(num, den, t1, t2, g))
      return false;
  } else {
    if(!PolyExtendedgcd(den, num, t1, t2, g))
      return false;
  }
  
#ifdef JLMDEBUG
  printf("RationalReduce g\n"); printpoly(g);
#endif
  t1.ZeroPoly();
  t2.ZeroPoly();
  t3.ZeroPoly();
  if(!PolyEuclid(num,g,t1,t3))
    return false;
  t3.ZeroPoly();
  if(!PolyEuclid(den,g,t2,t3))
    return false;
  t1.Copyto(*inout.numerator);
  t2.Copyto(*inout.denominator);
#ifdef JLMDEBUG
  printf("RationalReduce out\n"); printrational(inout);
#endif
  return true;
}

bool RationalMultBy(rationalpoly& inout, rationalpoly& by) {
  bnum*       p= inout.numerator->characteristic_;
  int         nn= inout.numerator->numc_+by.numerator->numc_;
  int         nd= inout.denominator->numc_+by.denominator->numc_;
  polynomial  t1(*p, nn, p->mpSize());
  polynomial  t2(*p, nd, p->mpSize());

  if(!PolyMult(*inout.numerator, *by.numerator, t1))
    return false;
  if(!PolyMult(*inout.denominator, *by.denominator, t2))
    return false;
  inout.numerator->Copyfrom(t1);
  inout.denominator->Copyfrom(t2);
  if(!RationalReduce(inout))
    return false;
  return true;
}

bool RationalisEqual(rationalpoly& in1, rationalpoly& in2) {
  bnum*       p= in1.numerator->characteristic_;
  int         n1= in1.numerator->numc_+in2.denominator->numc_;
  int         n2= in2.numerator->numc_+in1.denominator->numc_;
  int         n= n1+n2;
  polynomial  t1(*p, n, p->mpSize());
  polynomial  t2(*p, n, p->mpSize());

  if(!PolyMult(*in1.numerator, *in2.denominator, t1))
    return false;
  if(!PolyMult(*in2.numerator, *in1.denominator, t2))
    return false;
  return PolyisEqual(t1,t2);
}

void printrational(rationalpoly& p) {
  printf("Rational polynomial:\n");
  printpoly(*p.numerator);
  printf("  /\n");
  printpoly(*p.denominator);
}


// ----------------------------------------------------------------------------


