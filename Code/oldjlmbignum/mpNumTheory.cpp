//
//  File: mpNumTheory.cpp
//      Multiple Precision Arithmetic jmbignum
//      Number theoretic algorithms
//
//  Copyright (c) 2011, John Manferdelli.  All rights reserved.
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


//
//  Multiprecision arithmetic
//                GCD, Generate Primes, Primality Testing, Strong Primes
//
//      References:
//              Knuth, SemiNumerical Algorithms
//              Menzes, Handbook of Applied Cryptography

#include <stdio.h> 
#include <stdlib.h> 
#include <fcntl.h> 
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "bignum.h"
#include "mpFunctions.h"
#include "logging.h"
#ifdef  UNIXRANDBITS
extern bool getCryptoRandom(i32 iNumBits, byte* rguBits);
#else
#include "jlmcrypto.h"
#endif


// ---------------------------------------------------------------------------------

//
//          Number Theoretic Operations
//

inline u64 bottomMask64(int iNumBits)
{
    u64 uMask= (u64) (-1);

    uMask<<= (64-iNumBits);
    uMask>>= (64-iNumBits);
    return uMask;
}


void shiftupinplace(bnum& bnA, i32 iShiftNumBits)
{
    int         i,j;
    int         iWordShift= (iShiftNumBits>>6);
    int         iBitShift= iShiftNumBits&0x3f;
    int         iBottomShift= 64-iBitShift;
    i32         iSizeA= bnA.mpSize();
    u64*        rguA= bnA.m_pValue;
    u64         src1, src2;

    j= iSizeA-1-iWordShift;
    if(j<0)
        src1= 0ULL;
    else
        src1= rguA[j];
    for(i=(iSizeA-1); i>=0; i--) {
        j--;
        if(j<0)
            src2= 0ULL;
        else
            src2= rguA[j];
        rguA[i]= (src1<<iBitShift) | (src2>>iBottomShift);
        src1= src2;
    }
    return;
}


void shiftdowninplace(bnum& bnA, i32 iShiftNumBits)
{
    int         i, j;
    int         iWordShift= (iShiftNumBits>>6);
    int         iBitShift= iShiftNumBits&0x3f;
    int         iBottomShift= 64-iBitShift;
    i32         iSizeA= bnA.mpSize();
    u64*        rguA= bnA.m_pValue;
    u64         src1, src2;

    j= iWordShift;
    if(j>=iSizeA)
        src1= 0ULL;
    else
        src1= rguA[j];
    for(i=0;i<iSizeA; i++) {
        j++;
        if(j>=iSizeA)
            src2= 0ULL;
        else
            src2= rguA[j];
        rguA[i]= (src1>>iBitShift) | (src2<<iBottomShift);
        src1= src2;
    }
    return;
}


//  Function: mpShiftInPlace
//  Arguments:
//      bnum bnA
//      iShiftNumBits>0 means shift increases value
bool mpShiftInPlace(bnum& bnA, int iShiftNumBits)
{
    i32     iSizeA= bnA.mpSize();
    i32     iRealSizeA= LeadingNonZeroWord(iSizeA, bnA.m_pValue);

    if(iShiftNumBits==0)
        return true;
    // Enough room?
    if(iRealSizeA+((iShiftNumBits+63)/64)>iSizeA)
        return false;

    if(iShiftNumBits>0) {
        shiftupinplace(bnA, iShiftNumBits);
    }
    else {
        shiftdowninplace(bnA, -iShiftNumBits);
    }

    return true;
}


//  Function: inline void mpShortLoop
//  Arguments:
//      bnum bnU
//      bnum bnA
//      bnum bnB
//      bnum bnX
//      bnum bnY
inline void mpShortLoop(bnum& bnU, bnum& bnA, bnum& bnB, bnum& bnX, bnum& bnY)
{
    u64* rgU= bnU.m_pValue;
    u64* rgA= bnA.m_pValue;
    u64* rgB= bnB.m_pValue;

    while((rgU[0]&1)==0) {
        mpShiftInPlace(bnU, -1);
        if((rgA[0]&1)==(rgB[0]&1) && (rgA[0]&1)==0) {
             mpShiftInPlace(bnA, -1);
             mpShiftInPlace(bnB, -1);
        }
        else {
            mpAddTo(bnA, bnY);
            mpSubFrom(bnB, bnX);
            mpShiftInPlace(bnA, -1);
            mpShiftInPlace(bnB, -1);
        }
    }
}


#ifdef MPTESTEXTENDED
//  Function: void LabeledprintNum
//  Arguments:
//      IN const char* pszLabel
//      IN bNum bnA
void LabeledprintNum(const char* pszLabel, bnum& bnA)
{
    fprintf(g_logFile, "%s\t: ", pszLabel);
    printNum(bnA);
    fprintf(g_logFile, "\n");
}
#endif


//  Function: bool mpBinaryExtendedGCD
//  Arguments:
//      IN bnum bnXExt
//      IN bnum bnYExt 
//      OUT bnum bnAExt 
//      OUT bnum bnBExt 
//      OUT bnum bnGExt
//  Description:
//      Compute a, b, g where ax+by=g=(x,y)
bool mpBinaryExtendedGCD(bnum& bnXExt, bnum& bnYExt, bnum& bnAExt, bnum& bnBExt, bnum& bnGExt)

{       
    int     iMaxSize= bnXExt.mpSize();
    int     i, j;

    if((int)bnYExt.mpSize()>iMaxSize)
        iMaxSize= bnYExt.mpSize();

    bnum bnX(iMaxSize);
    bnum bnY(iMaxSize);
    bnum bnA(iMaxSize);
    bnum bnB(iMaxSize);
    bnum bnC(iMaxSize);
    bnum bnD(iMaxSize);
    bnum bnU(iMaxSize);
    bnum bnV(iMaxSize);
    bnum bnG(iMaxSize);

    bnXExt.mpCopyNum(bnX);
    bnYExt.mpCopyNum(bnY);
    bnX.mpCopyNum(bnU);
    bnY.mpCopyNum(bnV);
    bnG.m_pValue[0]= 1;
    bnA.m_pValue[0]= 1;
    bnD.m_pValue[0]= 1;

    // Step 1, 2: Get largest power of 2 divisor       
    i= max2PowerDividing(bnX);
    if(i<0) {
        fprintf(g_logFile, "Zero Arg (X)\n");
        return false;
    }
    j= max2PowerDividing(bnY);
    if(j<0) {
        fprintf(g_logFile, "Zero Arg (Y)\n");
        return false;
    }
    if(i>j)
        i= j;

    mpShiftInPlace(bnX, -i);
    mpShiftInPlace(bnY, -i);
    mpShiftInPlace(bnG, i);

    // Step 3
    if(!bnX.mpCopyNum(bnU)) {
        fprintf(g_logFile, "Bad Copy\n");
        return false;
    }
    if(!bnY.mpCopyNum(bnV)) {
        fprintf(g_logFile, "Bad Copy\n");
        return false;
    }

#ifdef MPTESTEXTENDED
    int nc= 0;
    fprintf(g_logFile, "mpBinaryExtendedGCD: initialized\n");
    LabeledprintNum("X", bnX); LabeledprintNum("Y", bnY);  
    LabeledprintNum("G", bnG);
    LabeledprintNum("A", bnA); LabeledprintNum("B", bnB); 
    LabeledprintNum("C", bnC); LabeledprintNum("D", bnD);
    LabeledprintNum("U", bnU); LabeledprintNum("V", bnV);
#endif

    for(;;) {

#ifdef MPTESTEXTENDED
        fprintf(g_logFile, "mpBinaryExtendedGCD: loop %ld\n", ++nc);
#endif
        mpShortLoop(bnU, bnA, bnB, bnX, bnY);   // Step 4
        mpShortLoop(bnV, bnC, bnD, bnX, bnY);   // Step 5

#ifdef MPTESTEXTENDED
        fprintf(g_logFile, "mpBinaryExtendedGCD: After ShortLoops\n");
        LabeledprintNum("U", bnU);LabeledprintNum("A", bnA); 
        LabeledprintNum("B", bnB); LabeledprintNum("V", bnV);
        LabeledprintNum("C", bnC); LabeledprintNum("D", bnD);
#endif
                        
        // Step 6
        if(mpCompare(bnU, bnV)!=s_iIsLessThan) {
            mpSubFrom(bnU, bnV);
            mpSubFrom(bnA, bnC);
            mpSubFrom(bnB, bnD);
        }
        else {
            mpSubFrom(bnV, bnU);
            mpSubFrom(bnC, bnA);
            mpSubFrom(bnD, bnB);
        }
#ifdef MPTESTEXTENDED
        fprintf(g_logFile, "mpBinaryExtendedGCD: After Reduce\n");
        LabeledprintNum("U", bnU);LabeledprintNum("A", bnA); 
        LabeledprintNum("B", bnB); LabeledprintNum("V", bnV);
        LabeledprintNum("C", bnC); LabeledprintNum("D", bnD);
#endif
        // Step 7
        if(bnU.mpIsZero()) {
            bnC.mpCopyNum(bnAExt);
            bnD.mpCopyNum(bnBExt);
            mpMult(bnG, bnV, bnGExt);
#ifdef MPTESTEXTENDED
            fprintf(g_logFile, "mpBinaryExtendedGCD: Transferring Output\n");
            LabeledprintNum("U", bnU);LabeledprintNum("A", bnA); 
            LabeledprintNum("B", bnB); LabeledprintNum("V", bnV);
            LabeledprintNum("C", bnC); LabeledprintNum("D", bnD);
            LabeledprintNum("bnAExt", bnAExt);
            LabeledprintNum("bnBExt", bnBExt); 
#endif
            break;
            }
    }

    return true;
}


// ----------------------------------------------------------------------------


//
//          Generating Primes and Primality testing
//

//
//              Data: First 512 primes
//
const i32   s_iSizeofFirstPrimes= 512;
u32         rgFirstPrimes[s_iSizeofFirstPrimes]= {
                   2,    3,    5,    7,   11,   13,   17,   19,
                  23,   29,   31,   37,   41,   43,   47,   53,
                  59,   61,   67,   71,   73,   79,   83,   89,
                  97,  101,  103,  107,  109,  113,  127,  131,
                 137,  139,  149,  151,  157,  163,  167,  173,
                 179,  181,  191,  193,  197,  199,  211,  223, 
                 227,  229,  233,  239,  241,  251,  257,  263, 
                 269,  271,  277,  281,  283,  293,  307,  311, 
                 313,  317,  331,  337,  347,  349,  353,  359, 
                 367,  373,  379,  383,  389,  397,  401,  409, 
                 419,  421,  431,  433,  439,  443,  449,  457, 
                 461,  463,  467,  479,  487,  491,  499,  503, 
                 509,  521,  523,  541,  547,  557,  563,  569, 
                 571,  577,  587,  593,  599,  601,  607,  613, 
                 617,  619,  631,  641,  643,  647,  653,  659, 
                 661,  673,  677,  683,  691,  701,  709,  719, 
                 727,  733,  739,  743,  751,  757,  761,  769, 
                 773,  787,  797,  809,  811,  821,  823,  827, 
                 829,  839,  853,  857,  859,  863,  877,  881, 
                 883,  887,  907,  911,  919,  929,  937,  941, 
                 947,  953,  967,  971,  977,  983,  991,  997, 
                1009, 1013, 1019, 1021, 1031, 1033, 1039, 1049,
                1051, 1061, 1063, 1069, 1087, 1091, 1093, 1097,
                1103, 1109, 1117, 1123, 1129, 1151, 1153, 1163,
                1171, 1181, 1187, 1193, 1201, 1213, 1217, 1223,
                1229, 1231, 1237, 1249, 1259, 1277, 1279, 1283,
                1289, 1291, 1297, 1301, 1303, 1307, 1319, 1321,
                1327, 1361, 1367, 1373, 1381, 1399, 1409, 1423,
                1427, 1429, 1433, 1439, 1447, 1451, 1453, 1459,
                1471, 1481, 1483, 1487, 1489, 1493, 1499, 1511,
                1523, 1531, 1543, 1549, 1553, 1559, 1567, 1571,
                1579, 1583, 1597, 1601, 1607, 1609, 1613, 1619,
                1621, 1627, 1637, 1657, 1663, 1667, 1669, 1693,
                1697, 1699, 1709, 1721, 1723, 1733, 1741, 1747,
                1753, 1759, 1777, 1783, 1787, 1789, 1801, 1811,
                1823, 1831, 1847, 1861, 1867, 1871, 1873, 1877,
                1879, 1889, 1901, 1907, 1913, 1931, 1933, 1949,
                1951, 1973, 1979, 1987, 1993, 1997, 1999, 2003,
                2011, 2017, 2027, 2029, 2039, 2053, 2063, 2069,
                2081, 2083, 2087, 2089, 2099, 2111, 2113, 2129,
                2131, 2137, 2141, 2143, 2153, 2161, 2179, 2203,
                2207, 2213, 2221, 2237, 2239, 2243, 2251, 2267,
                2269, 2273, 2281, 2287, 2293, 2297, 2309, 2311,
                2333, 2339, 2341, 2347, 2351, 2357, 2371, 2377,
                2381, 2383, 2389, 2393, 2399, 2411, 2417, 2423,
                2437, 2441, 2447, 2459, 2467, 2473, 2477, 2503,
                2521, 2531, 2539, 2543, 2549, 2551, 2557, 2579,
                2591, 2593, 2609, 2617, 2621, 2633, 2647, 2657,
                2659, 2663, 2671, 2677, 2683, 2687, 2689, 2693,
                2699, 2707, 2711, 2713, 2719, 2729, 2731, 2741,
                2749, 2753, 2767, 2777, 2789, 2791, 2797, 2801,
                2803, 2819, 2833, 2837, 2843, 2851, 2857, 2861,
                2879, 2887, 2897, 2903, 2909, 2917, 2927, 2939,
                2953, 2957, 2963, 2969, 2971, 2999, 3001, 3011,
                3019, 3023, 3037, 3041, 3049, 3061, 3067, 3079,
                3083, 3089, 3109, 3119, 3121, 3137, 3163, 3167,
                3169, 3181, 3187, 3191, 3203, 3209, 3217, 3221,
                3229, 3251, 3253, 3257, 3259, 3271, 3299, 3301,
                3307, 3313, 3319, 3323, 3329, 3331, 3343, 3347,
                3359, 3361, 3371, 3373, 3389, 3391, 3407, 3413,
                3433, 3449, 3457, 3461, 3463, 3467, 3469, 3491,
                3499, 3511, 3517, 3527, 3529, 3533, 3539, 3541,
                3547, 3557, 3559, 3571, 3581, 3583, 3593, 3607,
                3613, 3617, 3623, 3631, 3637, 3643, 3659, 3671
                };


//  Function: bool MRPrimeTestLoop
//  Arguments:
//      bnum bnN --- number to test for primality
//      bnum bnNM1= bnN-1
//      bnNM1= 2**iS bnR, bnR, odd
//      bnum bnS= 2**iS
//      bnum bnA= base to use in test
//      bnum bnR= bnNM1>>iS
//  Description:
//      Miller Rabin Test Step
//      Compute y=a**r (mod n)
//      If y!=1 and y!=n-1 {
//          j=1
//          while(j<iS && y!=(n-1))
//              y= y**2 (mod n)
//              if (y==1)
//                  return(composite)
//              j= j+1
//      }
//                      }
//      if(y!=(n-1))
//          return(composite)
//      return(prime)
bool MRPrimeTestLoop(bnum& bnN, bnum& bnNM1, bnum& bnA, bnum& bnR, i32 iS, bnum& bnS)
{
    int             iMaxSize= bnN.mpSize();
    int             j= 1;
    bnum            bnY(iMaxSize);
    bnum            bnQ(iMaxSize);
    bnum            bnTemp(iMaxSize);
    extern bnum     g_bnOne;
    
    if(!mpModExp(bnA, bnR, bnN, bnY))
        fprintf(g_logFile, "MRPrimeTestLoop: Bad Exponent\n");
    if(mpCompare(bnY, g_bnOne)!=s_iIsEqualTo && mpCompare(bnY, bnNM1)!=s_iIsEqualTo) {
        while(j<iS && mpCompare(bnY, g_bnOne)!=s_iIsEqualTo) {
            // square y mod N
            mpZeroNum(bnTemp);
            mpUMult(bnY, bnY, bnTemp);
            mpZeroNum(bnY);
            mpDiv(bnTemp, bnN, bnQ, bnY);
            if(mpCompare(bnY, g_bnOne)==s_iIsEqualTo) {
                return false;
            }
            j++;
        }
        if(mpCompare(bnY, bnNM1)!=s_iIsEqualTo) {
#ifdef ARITHTEST3
            fprintf(g_logFile, "\tY: "); printNum(bnY); printf("\n");
            fprintf(g_logFile, "\tNM1: "); printNum(bnNM1); printf("\n");
#endif
            return false;
        }
    }

    return true;
}


//      Function: bool MRPrimeTest
//      Arguments:
//          bnum bnN,
//          i32 iT
//          bnum rgbnA[]
//      Description:
//          Miller Rabin Primality Test
//          MR(n, .25, t), n>3, n, odd.  Set n-1= 2sr, r, odd. (t> 3, in practice)
//          for(i=1, i<=t) 
//              Choose a, 1<a<n-1.  2 is a good choice first time
//      BUG: incomplete
bool MRPrimeTest(bnum& bnN, i32 iT, bnum* rgbnA[])
{
    int     i, iS;
    int     iMaxSize= bnN.mpSize();
    bnum    bnR(iMaxSize);                 // odd
    bnum    bnS(iMaxSize);                 // highest power of 2 dividing
    bnum    bnNM1(iMaxSize);
    bnum*   pbNum;
   
    bnN.mpCopyNum(bnNM1);
    mpDec(bnNM1);
    iS= max2PowerDividing(bnNM1);
    bnS.m_pValue[0]= 1;
    mpShiftInPlace(bnS, iS);
    mpShift(bnNM1, -iS, bnR);
    for(i=0; i<iT; i++) {
        pbNum= rgbnA[i];
        if(!MRPrimeTestLoop(bnN, bnNM1, *pbNum, bnR, iS, bnS)) {
            return false;
        }
    }
    return true;
}


//  Function: static bool MakeRandBasisForMR
//  Arguments:
//      int iBitSize
//      bnum bnN
//      int iNumBases
//      bnum* rgbnBases
//  Description:
//      Generate bases for Miller Rabin Test
bool MakeRandBasisForMR(int iBitSize, bnum& bnN, int iNumBases, bnum* rgbnBases[])
{
    int     i;
    bnum*   pbNum;

    // first one is always 2
    pbNum= rgbnBases[0];
    mpZeroNum(*pbNum);
    pbNum->m_pValue[0]= 2;

    for(i=1; i<iNumBases; i++) {
        pbNum= rgbnBases[i];
         mpZeroNum(*pbNum);
         if(!getCryptoRandom(iBitSize, (byte*)pbNum->m_pValue))
             fprintf(g_logFile, "MakeRandBasisForMR: No Random Bits\n");
        // if it's bigger than number, subtract it
        if(mpUCompare(bnN, *pbNum)==s_iIsLessThan)
             mpUSubFrom(*pbNum, bnN);
    }
    return true;
}


#define MAXBASE 50


//  Function: bool mpGenPrime
//  Arguments:
//      i32 iBitSize
//      bnum& bnA
//      int iConfid=20
//  Description:
//      Generate iBitSize Prime, result in bnA
bool mpGenPrime(i32 iBitSize, bnum& bnA, int iConfid)
{
    extern  bnum   g_bnTwo;
    int     i, j;
    int     iNumTries= 0;
    u64     uPossibleDivisor, uCarry;
    i32     iWordSize= ((iBitSize+63)>>6);
    bool    fIsPrime= false;
    u64*    rguA= bnA.m_pValue;
    bnum    bnQ(bnA.mpSize());
    bnum*   rgbnBase[MAXBASE];
    int     iRealSizeA;
    bool    fRet= false;

#ifdef TEST
    fprintf(g_logFile, "mpGenPrime(%d), WordSize= %d\n", iBitSize, iWordSize);
#endif
    if(iConfid>MAXBASE)
        iConfid= MAXBASE;

    for(i=0; i<iConfid; i++)
        rgbnBase[i]= new bnum(iWordSize);

        mpZeroNum(bnA);
        // Get Candidate prime (bnA)
        if(!getCryptoRandom(iBitSize, (byte*)rguA)) {
            fprintf(g_logFile, "No Random Bits\n");
            return false;
        }

        // Set high and low bits
        rguA[0]|= 1ULL;
        j= iBitSize&0x3f;
        if(j==0)
            j= 64;
        j--;
        rguA[iWordSize-1]|= 1ULL<<j;

#ifdef ARITHTEST3
        fprintf(g_logFile, "mpGenPrime trial prime %016lx %016lx\n", 
                (long unsigned int)rguA[1], (long unsigned int)rguA[0]);
#endif
        while(!fIsPrime) {
            iNumTries++;

            // Check for small divisors
            for(i=0; i<s_iSizeofFirstPrimes; i++) {
                uPossibleDivisor= (u64)rgFirstPrimes[i];
                uCarry= 0;                      
                mpSingleUDiv(bnA, uPossibleDivisor, bnQ, &uCarry);
                if(uCarry==0)
                    break;          // uPossibleDivisor is a divisor
            }
            if(i>=s_iSizeofFirstPrimes)
                fIsPrime= true;
            else
                fIsPrime= false;

            // Miller Rabin Test
            if(fIsPrime) {
                // Generate bases for RM, first
                MakeRandBasisForMR(iBitSize, bnA, iConfid, rgbnBase);
                if(MRPrimeTest(bnA, iConfid, rgbnBase)) {
                    fIsPrime= true;
                    break;
                }
                else {
                    fIsPrime= false;
                }
            }

            // Number overflows?, subtract instead
            iRealSizeA= LeadingNonZeroWord(bnA.mpSize(), bnA.m_pValue);
            if(mpUAddTo(bnA, g_bnTwo)!=0 || iRealSizeA*NUMBITSINU64>iBitSize) {
                fprintf(g_logFile, "Prime interval exceeded\n");
                return false;
            }
#ifdef ARITHTEST3
            if((iNumTries%100)==0) {
                fprintf(g_logFile, "mpGenPrime try %d %016lx %016lx\n", iNumTries,
                    (long unsigned int)rguA[1], (long unsigned int)rguA[0]);
            }
#endif
        }

        if(fIsPrime)
            fRet= true;

    // Clean up
    for(i=0; i<iConfid; i++) {
        if(rgbnBase[i]!=NULL)
           delete rgbnBase[i];
        rgbnBase[i]= NULL;
    }

    return fRet;
}


// ----------------------------------------------------------------------------


