//
//  File: polyarith.h
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


// ----------------------------------------------------------------------------

#ifndef _POLY_ARITH_H__
#define _POLY_ARITH_H__
#include "common.h"
#include "bignum.h"
#include "mpFunctions.h"


class polynomial {
public:
  bnum*   characteristic_;
  int     numc_;
  int     size_num_;
  bnum**  c_array_;

  polynomial(bnum& p, int numc, int sizenum);
  ~polynomial();
  void ZeroPoly();
  void OnePoly();
  int Degree();
  bool Copyfrom(polynomial& from);
  bool Copyto(polynomial& to);
  bool IsZero();
  bool MultiplyByNum(bnum& c);
};

class rationalpoly {
public:
  polynomial* numerator;
  polynomial* denominator;

  rationalpoly(bnum& p, int numc1, int sizenum1, int numc2, int sizenum2);
  ~rationalpoly();
  void ZeroRational();
  void OneRational();
  bool Copyfrom(rationalpoly& from);
  bool Copyto(rationalpoly& to);
};

bool PolyAdd(polynomial& in1, polynomial& in2, polynomial& out);
bool PolySub(polynomial& in1, polynomial& in2, polynomial& out);
bool PolyMult(polynomial& in1, polynomial& in2, polynomial& out);
bool PolyisEqual(polynomial& in1, polynomial& in2);

bool PolyEuclid(polynomial& a, polynomial& b, polynomial& q, polynomial& r);
bool PolyExtendedgcd(polynomial& a, polynomial& b, polynomial& c, 
                     polynomial& d, polynomial& g);
bool Reducelargepower(bnum& power, polynomial& mod_poly, polynomial& result);
bool SquareRoot(bnum& num , bnum& result);
void printpoly(polynomial& p);

bool RationalAdd(rationalpoly& in1, rationalpoly& in2, rationalpoly& out);
bool RationalSub(rationalpoly& in1, rationalpoly& in2, rationalpoly& out);
bool RationalMult(rationalpoly& in1, rationalpoly& in2, rationalpoly& out);
bool RationalDiv(rationalpoly& in1, rationalpoly& in2, rationalpoly& out);
bool RationalMultBy(rationalpoly& inout, rationalpoly& by);
bool RationalisEqual(rationalpoly& in1, rationalpoly& in2);
bool RationalReduce(rationalpoly& inout);
void printrational(rationalpoly& p);
#endif

// ----------------------------------------------------------------------------
