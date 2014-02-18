//
//  File: jlmcrypto.cpp
//  Description: common crypto interface
//
//  Copyright (c) 2011, Intel Corporation. All rights reserved.
//  Some contributions (c) John Manferdelli.  All rights reserved.
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "common.h"
#include "jlmcrypto.h"
#include "logging.h"
#include "sha256.h"


// ------------------------------------------------------------------------------


int     iRandDev= -1;


bool initCryptoRand()
{
    iRandDev= open("/dev/urandom", O_RDONLY);
    if(iRandDev<0)
        return false;
    return true;
}


bool closeCryptoRand()
{
    if(iRandDev>=0) {
        close(iRandDev);
    }
    iRandDev= -1;
    return true;
}


bool getCryptoRandom(int iNumBits, byte* buf)
{
    int     iSize= (iNumBits+NBITSINBYTE-1)/NBITSINBYTE;

    if(iRandDev<0) {
        return false;
    }
    int iSize2= read(iRandDev, buf, iSize);
    if(iSize2==iSize) {
        return true;
    }
    fprintf(g_logFile, "getCryptoRandom returning false %d bytes instead of %d\n", 
            iSize2, iSize);
    return false;
}


static bool g_fAllCryptoInit= false;

bool initAllCrypto()
{
    extern void initBigNum();

    if(g_fAllCryptoInit)
        return true;
    // init RNG
    if(!initCryptoRand())
        return false;
    // init bignum
    initBigNum();
    g_fAllCryptoInit= true;
   return true; 
}


bool closeAllCrypto()
{
    closeCryptoRand();
    g_fAllCryptoInit= false;
    return true;
}


// -----------------------------------------------------------------------------


// pad character is '='
static const char* s_transChar= 
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

inline int numbytesfromBase64string(int nc)
{
    return (6*nc+NBITSINBYTE-1)/NBITSINBYTE;
}


inline int numbase64charsfrombytes(int nb)
{
    int k= (NBITSINBYTE*nb+5)/6;
    return ((k+3)/4)*4;
}


inline byte b64value(char a)
{
    if(a>='A'&&a<='Z')
        return (byte) a-'A';
    if(a>='a'&&a<='z')
        return (byte) a-'a'+26;
    if(a>='0'&&a<='9')
        return (byte) a-'0'+52;
    if(a=='+')
        return 0x3e;
    if(a=='/')
        return 0x3f;
    return 0xff;  // error
}


bool toBase64(int inlen, const byte* in, int* poutlen, char* szout, bool dir)
{
    int	    numout= numbase64charsfrombytes(inlen);
    
    if(numout>*poutlen)
	return false;

    int	        n= inlen;
    int         a, b, c, d;
    const byte* pb;

    // s_transChar
    if(dir) {
	// scan from high order byte to low
	// 24 bit chunks
        pb= in+inlen-1;     // start at high order byte (eg-on little endian machine)
	while(n>2) {
	    a= ((*pb)>>2)&0x3f;
	    b= (((*pb)&0x3)<<4)|((*(pb-1)>>4)&0xf);
	    c= (((*(pb-1))&0xf)<<2)|((*(pb-2)>>6)&0x3);
	    d= (*(pb-2))&0x3f;
	    *(szout++)= s_transChar[a];
	    *(szout++)= s_transChar[b];
	    *(szout++)= s_transChar[c];
	    *(szout++)= s_transChar[d];
	    n-= 3;
	    pb-= 3;
	}
	// 16 bits left
	if(n==2) {
	    a= ((*pb)>>2)&0x3f;
	    b= (((*pb)&0x3)<<4)|((*(pb-1)>>4)&0xf);
	    c= (((*(pb-1))&0xf)<<2);
	    *(szout++)= s_transChar[a];
	    *(szout++)= s_transChar[b];
	    *(szout++)= s_transChar[c];
	    *(szout++)= '=';
	    n= 0;
	}
	// 8 bits left
	if(n==1) {
	    a= ((*pb)>>2)&0x3f;
	    b= (((*pb)&0x3)<<4)|((*(pb-1)>>4)&0xf);
	    *(szout++)= s_transChar[a];
	    *(szout++)= s_transChar[b];
	    *(szout++)= '=';
	    *(szout++)= '=';
	    n= 0;
	}
    }
    else {
	// scan from low order byte to high
	// 24 bit chunks
        pb= in;
	while(n>2) {
	    a= ((*pb)>>2)&0x3f;
	    b= (((*pb)&0x3)<<4)|((*(pb+1)>>4)&0xf);
	    c= (((*(pb+1))&0xf)<<2)|((*(pb+2)>>6)&0x3);
	    d= (*(pb+2))&0x3f;
	    *(szout++)= s_transChar[a];
	    *(szout++)= s_transChar[b];
	    *(szout++)= s_transChar[c];
	    *(szout++)= s_transChar[d];
	    n-= 3;
	    pb+= 3;
	}
	// 16 bits left
	if(n==2) {
	    a= ((*pb)>>2)&0x3f;
	    b= (((*pb)&0x3)<<4)|((*(pb+1)>>4)&0xf);
	    c= (((*(pb+1))&0xf)<<2);
	    *(szout++)= s_transChar[a];
	    *(szout++)= s_transChar[b];
	    *(szout++)= s_transChar[c];
	    *(szout++)= '=';
	    n= 0;
	}
	// 8 bits left
	if(n==1) {
	    a= ((*pb)>>2)&0x3f;
	    b= (((*pb)&0x3)<<4)|((*(pb+1)>>4)&0xf);
	    *(szout++)= s_transChar[a];
	    *(szout++)= s_transChar[b];
	    *(szout++)= '=';
	    *(szout++)= '=';
	    n= 0;
	}
    }
    *szout= 0;
    *poutlen= numout;
    return true;
}


bool fromBase64(int inlen, const char* szin, int* poutlen, byte* out, bool dir)
{
    int	    numout= numbytesfromBase64string(inlen);

    if(inlen<4 || (inlen%4)!=0)
        return false;

    // does padding affect output length?
    if(*(szin+inlen-1)=='=')
        numout--;
    if(*(szin+inlen-2)=='=')
        numout--;

    if(numout>*poutlen)
	return false;

    const char* p= szin;
    byte*   pb= out;
    byte    a, b, c, d;
    if(dir) {
        pb+= numout-1;
        while(*p!='\0') {
            a= b64value(*p++);
            if(a==0xff)
                return false;
            b= b64value(*p++);
            if(b==0xff)
                return false;
            if(*(p+1)=='=') {
                *pb--= a<<2|b>>4;
                if(*p!='=') {
                    c= b64value(*p++);
                    if(c==0xff)
                        return false;
                    *pb--= b<<4|(c>>2);
                }
                break;
            }
            c= b64value(*p++);
            if(c==0xff)
                return false;
            d= b64value(*p++);
            if(d==0xff)
                return false;
            *pb--= a<<2|(b>>4);
            *pb--= b<<4|(c>>2);
            *pb--= c<<6|d;
        }
    }
    else {
        while(*p!='\0') {
            a= b64value(*p++);
            if(a==0xff)
                return false;
            b= b64value(*p++);
            if(b==0xff)
                return false;
            if(*(p+1)=='=') {
                *pb++= a<<2|b>>4;
                if(*p!='=') {
                    c= b64value(*p++);
                    if(c==0xff)
                        return false;
                    *pb++= b<<4|c>>2;
                }
                break;
            }
            c= b64value(*p++);
            if(c==0xff)
                return false;
            d= b64value(*p++);
            if(d==0xff)
                return false;
            *pb++= a<<2|(b>>4);
            *pb++= b<<4|(c>>2);
            *pb++= c<<6|d;
        }
    }

    *poutlen= numout;
    return true;
}


bool  getBase64Rand(int iBytes, byte* puR, int* pOutSize, char* szOut)
//  Get random number and base 64 encode it
{
    if(!getCryptoRandom(iBytes*NBITSINBYTE, puR)) {
        return false;
    }
    if(!toBase64(iBytes, puR, pOutSize, szOut)) {
        fprintf(g_logFile, "Bytes: %d, base64 outputsize: %d\n", iBytes, *pOutSize);
        fprintf(g_logFile, "Can't base64 encode generated random number\n");
        return false;
    }
    return true;
}


// ------------------------------------------------------------------------------------


