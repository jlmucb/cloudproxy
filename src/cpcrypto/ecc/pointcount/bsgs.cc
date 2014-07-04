//
//  File: bsgs.cc
//  Description: Baby step, giant step point counting in ECC
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
#include "ecc.h"
#include "polyarith.h"
#include "stdio.h"

// ----------------------------------------------------------------------------


const int first_primes_size = 512;
int first_primes[first_primes_size] = {
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71,
   73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151,
  157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233,
  239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317,
  331, 337, 347, 349, 353, 359, 367, 373, 379, 383, 389, 397, 401, 409, 419,
  421, 431, 433, 439, 443, 449, 457, 461, 463, 467, 479, 487, 491, 499, 503,
  509, 521, 523, 541, 547, 557, 563, 569, 571, 577, 587, 593, 599, 601, 607,
  613, 617, 619, 631, 641, 643, 647, 653, 659, 661, 673, 677, 683, 691, 701,
  709, 719, 727, 733, 739, 743, 751, 757, 761, 769, 773, 787, 797, 809, 811,
  821, 823, 827, 829, 839, 853, 857, 859, 863, 877, 881, 883, 887, 907, 911,
  919, 929, 937, 941, 947, 953, 967, 971, 977, 983, 991, 997, 1009, 1013, 1019,
  1021, 1031, 1033, 1039, 1049, 1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097,
  1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163, 1171, 1181, 1187, 1193, 1201,
  1213, 1217, 1223, 1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283, 1289, 1291,
  1297, 1301, 1303, 1307, 1319, 1321, 1327, 1361, 1367, 1373, 1381, 1399, 1409,
  1423, 1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459, 1471, 1481, 1483, 1487,
  1489, 1493, 1499, 1511, 1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571, 1579,
  1583, 1597, 1601, 1607, 1609, 1613, 1619, 1621, 1627, 1637, 1657, 1663, 1667,
  1669, 1693, 1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747, 1753, 1759, 1777,
  1783, 1787, 1789, 1801, 1811, 1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877,
  1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949, 1951, 1973, 1979, 1987, 1993,
  1997, 1999, 2003, 2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069, 2081, 2083,
  2087, 2089, 2099, 2111, 2113, 2129, 2131, 2137, 2141, 2143, 2153, 2161, 2179,
  2203, 2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267, 2269, 2273, 2281, 2287,
  2293, 2297, 2309, 2311, 2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377, 2381,
  2383, 2389, 2393, 2399, 2411, 2417, 2423, 2437, 2441, 2447, 2459, 2467, 2473,
  2477, 2503, 2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579, 2591, 2593, 2609,
  2617, 2621, 2633, 2647, 2657, 2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693,
  2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741, 2749, 2753, 2767, 2777, 2789,
  2791, 2797, 2801, 2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861, 2879, 2887,
  2897, 2903, 2909, 2917, 2927, 2939, 2953, 2957, 2963, 2969, 2971, 2999, 3001,
  3011, 3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079, 3083, 3089, 3109, 3119,
  3121, 3137, 3163, 3167, 3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221, 3229,
  3251, 3253, 3257, 3259, 3271, 3299, 3301, 3307, 3313, 3319, 3323, 3329, 3331,
  3343, 3347, 3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413, 3433, 3449, 3457,
  3461, 3463, 3467, 3469, 3491, 3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541,
  3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607, 3613, 3617, 3623, 3631, 3637,
  3643, 3659, 3671
};


/*
 * 1. Q= (q+1)P
 * 2. Choose m>q^(1/4)
 * 3. Compute Q+jP, j= 0, 1, ..., m and store
 * 4. Compute Q+k(2mP), k= -m, -m+1, ... 0, 1, ..., m
 *      until Q+k(2mP)= Q+jP or Q-jP
 * 5. (q+1+2mk+j)P= O or (q+1+2mk-j)P= O.  Let M be coefficient of P
 * 6. Factor M into p[0]^e[0] ... p[l]^e[l]
 * 7. Repeat until failure if (M/p[i]]P=0, replace M with /p[i] 
 * 8. Conclude |P|= M
 * If we're looking for the order of the group, do the above with
 *    random points until LCM divides one N with q+1-2(q^1/2)<=N<=q+1+2(q^1/2).
 *    Conclude N is the order
 */


#define JLMDEBUG


int PointinTable(ECPoint& P, ECPoint** table, int size) {
  int i;

  for(i=0;i<size;i++) {
    if(P.iszeroPoint() && table[i]->iszeroPoint())
      return i;
    if(mpCompare(*P.m_bnX, *table[i]->m_bnX)==0 &&
          mpCompare(*P.m_bnY, *table[i]->m_bnY)==0 &&
          mpCompare(*P.m_bnZ, *table[i]->m_bnZ)==0)
      return i;
  }
  return -1;
}


bool eccbsgspointorder(ECPoint& P, bnum& order)
{
  ECPoint     Q(P.m_myCurve, P.m_myCurve->m_bnM->mpSize());
  ECPoint     temp_point(P.m_myCurve, P.m_myCurve->m_bnM->mpSize());
  ECPoint     temp_point2(P.m_myCurve, P.m_myCurve->m_bnM->mpSize());
  bnum*       mod= P.m_myCurve->m_bnM;
  bnum        temp(2*mod->mpSize());
  bnum        j_num(2*mod->mpSize());
  bnum        m(2*mod->mpSize());
  bnum        M(2*mod->mpSize());
  ECPoint**   table= NULL;
  int         table_size;
  bool        fRet= true;
  u64         n;

#ifdef JLMDEBUG
  printf("eccbsgspointorder\n");
#endif
  mpAdd(*mod, g_bnOne, temp);
  if(!ecMult(P, temp, Q))
    return false;

  // m= mod*(1/4)
  if(!SquareRoot(*mod, temp)) {
    fRet= false;
  }
  if(!SquareRoot(temp, m))
    fRet= false;

#ifdef JLMDEBUG
  printf("fourth root of ");
  printNumberToConsole(*mod);
  printf(" is ");
  printNumberToConsole(m);
  printf("\n");
#endif
  // compute table, Q+jP, j= 0, 1, ..., m
  // m better be small
  if(max2PowerDividing(m)>16) {
    fRet= false;
  }
  table_size= (int) m.m_pValue[0]+1;
  table= new ECPoint*[table_size];

  // Fix: only store x coordinate and sort
  int j;
  for(j=0; j<table_size; j++) {
    table[j]= new ECPoint(P.m_myCurve, P.m_myCurve->m_bnM->mpSize());
    temp_point.makeZero();
    j_num.m_pValue[0]= (u64)j;
    if(!ecMult(P, j_num, temp_point)) {
      fRet= false;
      goto done;
    }
    if(!ecAdd(Q, temp_point, *table[j])) {
      fRet= false;
      goto done;
    }
  }
  
#ifdef JLMDEBUG
  printf("table computed\n");
  for(j=0; j<table_size; j++) {
    printf("\nentry[%d]: ", j);
    table[j]->printMe();
  }
#endif

  // Compute Q+k(2mP), k= -m, -m+1, ... 0, 1, ..., m
  //     until table match
  int k;
  for(j=(1-table_size); j<table_size-1; j++) {
    temp_point.makeZero();
    j_num.m_pValue[0]= 2*(table_size-1)*j;
    if(!ecMult(P, j_num, temp_point)) {
      fRet= false;
      goto done;
    }
    temp_point2.makeZero();
    if(!ecAdd(Q, temp_point, temp_point2)) {
      fRet= false;
      goto done;
    }
    // k= PointinTable(temp_point2, table, table_size+1);
    k= PointinTable(temp_point2, table, table_size);
    if(k>=0) {
      n= mod->m_pValue[0]+1+j_num.m_pValue[0]-k;
      break;
    }
    temp_point2.makeZero();
    if(!ecSub(Q, temp_point, temp_point2)) {
      fRet= false;
      goto done;
    }
    // k= PointinTable(temp_point2, table, table_size+1);
    k= PointinTable(temp_point2, table, table_size);
    if(k>=0) {
      n= mod->m_pValue[0]+1+j_num.m_pValue[0]+k;
      break;
    }
  }

#ifdef JLMDEBUG
  printf("reducing by small primes\n");
#endif
  // repeat until minimum order
  for(j=0; j<first_primes_size && n>first_primes[j]; j++) {
    while(n>first_primes[j]) {
      temp_point.makeZero();
      j_num.m_pValue[0]= n;
      if(!ecMult(P, j_num, temp_point)) {
        fRet= false;
        goto done;
      }
    if(!temp_point.iszeroPoint())
      break;
    n/= first_primes[j];
    }
  }
  order.m_pValue[0]= n;

done:
  for(j=0; j<table_size; j++) {
    delete table[j];
    table[j]= NULL;
  }
  delete table;
  return fRet;
}


// ----------------------------------------------------------------------------
