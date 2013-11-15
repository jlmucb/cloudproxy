//
//  File: mpRand.cpp
//  Description: Random number support for jmbignum
//
//  Copyright (c) 2011, Intel Corporation. Some contributions 
//    (c) John Manferdelli.  All rights reserved.
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


#include <stdio.h> 
#include <stdlib.h> 
#include <fcntl.h> 
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "bignum.h"
#include "mpFunctions.h"
#include "logging.h"


// ---------------------------------------------------------------------------------


#ifdef NORAND
//  Function: u64 randu
//  Arguments:
//      IN u64 ua
//  Description:
//      Generate 64 bits of entropy
u64 randu(u64 ua)
{
#ifndef STATICTEST
    static bool fInitialized= false;

    if(!fInitialized) {
        srand((unsigned)time(NULL));
        fInitialized= true;
    }
    return(rand());
#else
    return(0x10da3589L);
#endif
}


//  Function: bool GetRandBits
//  Arguments:
//      IN i32      numBits, 
//      OUT u64*    rguBits
//  Description:
//      Generate numBits bits of entropy
bool getCryptoRand(i32 numBits, byte* rguBits)
{
    int     i= 0;
    u64     uM= 1L<<NUMBITSINU64MINUS1;  

    while(numBits>0) {
        rguBits[i]= randu(2L);
        if(numBits<NUMBITSINU64) {
            for(int j=0; j<NUMBITSINU64-numBits;j++) {
                rguBits[i]&= ~uM;
                uM>>= 1;
            }
        break;
        }
        numBits-= NUMBITSINU64;
        i++;
    }
    return(true);
}
#endif


#ifdef UNIXRANDBITS

const int g_iMaxGetRandSize= NUMBITSINU64;


bool getCryptoRandom(i32 numBits, byte* rguBits)
{
    int     iRand= open("/dev/random", O_RDONLY);
    int     iCurrent= 0;
    int     iSize;
    int     iGet;
    int     iNumBytesLeft= (numBits+7)/8;
    int     iExtraBits= iNumBytesLeft*8-numBits;
    byte*   rgBuf= (byte*) rguBits;

    if(iRand<0) {
        fprintf(g_logFile, "Cant open /dev/random");
        return false;
    }

    while(iNumBytesLeft>0) {
        if(iNumBytesLeft<g_iMaxGetRandSize)
            iGet= iNumBytesLeft;
        else
            iGet= g_iMaxGetRandSize;
        iSize= read(iRand, &rgBuf[iCurrent], iGet);
        if(iSize<=0) {
            close(iRand);
            return false;
        }
        iCurrent+= iSize;
        iNumBytesLeft-= iSize;
    }

    if(iExtraBits>0) {
        byte uT= (1<<iExtraBits)-1;
        rgBuf[iCurrent-1]&= uT;
    }
    close(iRand);
    return true;
}
#endif


#ifdef WINDOWSRANDBITS

bool getCryptoRand(i32 numBits, byte* rguBits)
{
    return false;
}
#endif


// ---------------------------------------------------------------------------------------


