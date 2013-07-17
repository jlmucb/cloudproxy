//
//  jlmcrypto.cpp
//      John Manferdelli
//
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

#include "jlmTypes.h"
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


// -------------------------------------------------------------------------------------------


//  pad character is '='

static const char* s_transChar= "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const unsigned char s_revTrans[80]= {
    62,  0,  0,  0, 63,
    52, 53, 54, 55, 56,
    57, 58, 59, 60, 61,
     0,  0,  0,  0,  0,
     0,  0,  0,  1,  2,
     3,  4,  5,  6,  7,
     8,  9, 10, 11, 12,
    13, 14, 15, 16, 17,
    18, 19, 20, 21, 22,
    23, 24, 25,  0,  0,
     0,  0,  0,  0, 26,
    27, 28, 29, 30, 31,
    32, 33, 34, 35, 36,
    37, 38, 39, 40, 41,
    42, 43, 44, 45, 46,
    47, 48, 49, 50, 51,
};


inline bool whitespace(char b)
{
    return (b==' ' || b=='\t' || b=='\r' || b=='\n');
}


// ------------------------------------------------------------------------------------------


bool toBase64(int inLen, const byte* pbIn, int* poutLen, char* szOut, bool fDirFwd)
//
//      Lengths are in characters
//
{
    int             numOut= ((inLen*4)+2)/3;
    int             i= 0;
    int             a, b, c, d;
    const byte*     pbC;

    // enough room?
    if(numOut>*poutLen)
        return false;

    if(fDirFwd) {
        pbC= pbIn+inLen-1;
        while(inLen>2) {
            a= (*pbC>>2)&0x3f;
            b= ((*pbC&0x3)<<4) | ((*(pbC-1)>>4)&0xf);
            c= ((*(pbC-1)&0xf)<<2) | ((*(pbC-2)>>6)&0x3);
            d= (*(pbC-2)&0x3f);
            szOut[i++]= s_transChar[a];
            szOut[i++]= s_transChar[b];
            szOut[i++]= s_transChar[c];
            szOut[i++]= s_transChar[d];
            pbC-= 3;
            inLen-= 3;
        }
        // 8 bits left
        if(inLen==1) {
            a= (*pbC>>2)&0x3f;
            b= ((*pbC&0x3)<<4) | ((*(pbC-1)>>4)&0xf);
            szOut[i++]= s_transChar[a];
            szOut[i++]= s_transChar[b];
            szOut[i++]= '=';
            szOut[i++]= '=';
        }
        // 16 bits left
        if(inLen==2) {
            a= (*pbC>>2)&0x3f;
            b= ((*pbC&0x3)<<4) | ((*(pbC-1)>>4)&0xf);
            c= ((*(pbC-1)&0xf)<<2);
            szOut[i++]= s_transChar[a];
            szOut[i++]= s_transChar[b];
            szOut[i++]= s_transChar[c];
            szOut[i++]= '=';
        }
    }
    else {
        pbC= pbIn;
        while(inLen>2) {
            a= (*pbC>>2)&0x3f;
            b= ((*pbC&0x3)<<4) | ((*(pbC+1)>>4)&0xf);
            c= ((*(pbC+1)&0xf)<<2) | ((*(pbC+2)>>6)&0x3);
            d= (*(pbC+2)&0x3f);
            szOut[i++]= s_transChar[a];
            szOut[i++]= s_transChar[b];
            szOut[i++]= s_transChar[c];
            szOut[i++]= s_transChar[d];
            pbC+= 3;
            inLen-= 3;
        }
        // 8 bits left
        if(inLen==1) {
            a= (*pbC>>2)&0x3f;
            b= ((*pbC&0x3)<<4) | ((*(pbC+1)>>4)&0xf);
            szOut[i++]= s_transChar[a];
            szOut[i++]= s_transChar[b];
            szOut[i++]= '=';
            szOut[i++]= '=';
        }
        // 16 bits left
        if(inLen==2) {
            a= (*pbC>>2)&0x3f;
            b= ((*pbC&0x3)<<4) | ((*(pbC+1)>>4)&0xf);
            c= ((*(pbC+1)&0xf)<<2);
            szOut[i++]= s_transChar[a];
            szOut[i++]= s_transChar[b];
            szOut[i++]= s_transChar[c];
            szOut[i++]= '=';
        }
    }
    *poutLen= i;
    szOut[i++]= 0;
    return true;
}


bool fromBase64(int inLen, const char* szIn, int* poutLen, unsigned char* puOut, bool fDirFwd)
//
//      Lengths are in characters
//
{
    int             numOut= ((inLen*3)+3)/4;
    unsigned char*  puW;
    unsigned char   a,b,c,d;
    int             numLeft= inLen;

    if(inLen>2 && *(szIn+inLen-1)=='=')
        numOut--;
    if(inLen>2 && *(szIn+inLen-2)=='=')
        numOut--;
    puW= puOut+numOut-1;

    // enough room?
    if(numOut>*poutLen) {
        return false;
    }

    while(numLeft>3) {
        while(whitespace(*szIn) && numLeft>0) {
            szIn++; numLeft--;
        }
        if(*szIn<43 || *szIn>122) {
            return false;
        }
        a= s_revTrans[*szIn-43];
        szIn++; numLeft--;
        while(whitespace(*szIn) && numLeft>0) {
            szIn++; numLeft--;
        }
        if(*szIn<43 || *szIn>122) {
            return false;
        }
        b= s_revTrans[*szIn-43];
        szIn++; numLeft--;
        while(whitespace(*szIn) && numLeft>0) {
            szIn++; numLeft--;
        }
        if(*szIn=='=') {
            if(!fDirFwd) {
                *(puOut)= (a<<2) | (b>>4);
                puOut+= 1;
            }
            else {
                *(puW)= (a<<2) | (b>>4);
                puW-= 1;
            }
            numLeft-= 2;
            continue;
        }
        if(*szIn<43 || *szIn>122) {
            return false;
        }
        c= s_revTrans[*szIn-43];
        szIn++; numLeft--;
        while(whitespace(*szIn) && numLeft>0) {
            szIn++; numLeft--;
        }
        if(*szIn=='=') {
            if(!fDirFwd) {
                *(puOut)= (a<<2) | (b>>4);
                *(puOut+1)= ((b&0xf)<<4) | (c>>2);
                puOut+= 2;
            }
            else {
                *(puW)= (a<<2) | (b>>4);
                *(puW-1)= ((b&0xf)<<4) | (c>>2);
                puW-= 2;
            }
            numLeft-= 1;
            continue;
        }
        if(*szIn<43 || *szIn>122) {
            return false;
        }
        d= s_revTrans[*szIn-43];
        szIn++; numLeft--;
        if(!fDirFwd) {
            *(puOut)= (a<<2) | (b>>4);
            *(puOut+1)= ((b&0xf)<<4) | (c>>2);
            *(puOut+2)= ((c&0x3)<<6) | d;
            puOut+= 3;
        }
        else {
            *(puW)= (a<<2) | (b>>4);
            *(puW-1)= ((b&0xf)<<4) | (c>>2);
            *(puW-2)= ((c&0x3)<<6) | d;
            puW-= 3;
        }
    }

    while(whitespace(*szIn) && numLeft>0) {
        szIn++; numLeft--;
        }
    if(numLeft>0) {
        return false;
    }

    *poutLen= numOut;
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


bool AES128CBCHMACSHA256SYMPADEncryptBlob(int insize, byte* in, int* poutsize, byte* out,
                        byte* enckey, byte* intkey)
{
    cbc     oCBC;
    int     inLeft= insize;
    byte    iv[AES128BYTEBLOCKSIZE];
    byte*   curIn= in;
    byte*   curOut= out;

#ifdef CRYPTOTEST
    memset(out, 0, *poutsize);
    fprintf(g_logFile, "*****AES128CBCHMACSHA256SYMPADEncryptBlob. insize: %d\n", insize);
    PrintBytes( "encKey: ", enckey, AES128BYTEBLOCKSIZE);
    PrintBytes( "intKey: ", intkey, AES128BYTEBLOCKSIZE);
    PrintBytes( "input:\n", in, insize);
#endif
    // init iv
    if(!getCryptoRandom(AES128BYTEBLOCKSIZE*NBITSINBYTE, iv)) {
        fprintf(g_logFile, "Cant generate iv\n");
        return false;
    }

    // init 
    if(!oCBC.initEnc(AES128, SYMPAD, HMACSHA256, 
                     AES128BYTEKEYSIZE, enckey, AES128BYTEKEYSIZE, 
                     intkey, insize, AES128BYTEBLOCKSIZE, iv)) {
        fprintf(g_logFile, "AES128CBCHMACSHA256SYMPADEncryptBlob false return 1\n");
        return false;
    }

    if(!oCBC.computeCipherLen()) {
        fprintf(g_logFile, "AES128CBCHMACSHA256SYMPADEncryptBlob false return 2\n");
        return false;
    }

    // outputbuffer big enough?
    if(oCBC.m_iNumCipherBytes>*poutsize) {
        fprintf(g_logFile, "AES128CBCHMACSHA256SYMPADEncryptBlob false return 3\n");
        return false;
    }
    *poutsize= oCBC.m_iNumCipherBytes;

    // first cipher block
    oCBC.firstCipherBlockOut(curOut);
    curOut+= AES128BYTEBLOCKSIZE;

    while(inLeft>AES128BYTEBLOCKSIZE) {
        oCBC.nextPlainBlockIn(curIn, curOut);
        curIn+= AES128BYTEBLOCKSIZE;
        curOut+= AES128BYTEBLOCKSIZE;
        inLeft-= AES128BYTEBLOCKSIZE;
    }

    // final block
    int n= oCBC.lastPlainBlockIn(inLeft, curIn, curOut);
    if(n<0) {
        fprintf(g_logFile, "AES128CBCHMACSHA256SYMPADEncryptBlob false return 4\n");
        return false;
    }
#ifdef CRYPTOTEST
    PrintBytes( "output:\n", out, *poutsize);
    fprintf(g_logFile, "\n%d, out\n", *poutsize);
#endif
    return true;
}


bool AES128CBCHMACSHA256SYMPADDecryptBlob(int insize, byte* in, int* poutsize, byte* out,
                         byte* enckey, byte* intkey)
{
    cbc     oCBC;
    int     inLeft= insize;
    byte*   curIn= in;
    byte*   curOut= out;

#ifdef CRYPTOTEST
    memset(out, 0, *poutsize);
    fprintf(g_logFile, "AES128CBCHMACSHA256SYMPADDecryptBlob, insize: %d\n", insize);
    PrintBytes("encKey: ", enckey, AES128BYTEBLOCKSIZE);
    PrintBytes("intKey: ", intkey, AES128BYTEBLOCKSIZE);
    PrintBytes("input:\n", in, insize);
#endif
    // init 
    if(!oCBC.initDec(AES128, SYMPAD, HMACSHA256, AES128BYTEKEYSIZE, enckey, 
                             AES128BYTEKEYSIZE, intkey, insize)) {
    	fprintf(g_logFile, "AES128CBCHMACSHA256SYMPADDecryptBlob: cant init decryption alg\n");
        return false;
    }

    if(!oCBC.computePlainLen()) {
    	fprintf(g_logFile, "AES128CBCHMACSHA256SYMPADDecryptBlob: cant compute plain text length\n");
        return false;
    }

    // outputbuffer big enough?
    if(oCBC.m_iNumPlainBytes>*poutsize) {
    	fprintf(g_logFile, "AES128CBCHMACSHA256SYMPADDecryptBlob: output buffer too small\n");
        return false;
    }
    *poutsize= oCBC.m_iNumPlainBytes;
#ifdef CRYPTOTEST
    fprintf(g_logFile, "Initial computed plaintext size: %d\n", 
            oCBC.m_iNumPlainBytes);
#endif

    // first block
    oCBC.firstCipherBlockIn(curIn);
    inLeft-= AES128BYTEBLOCKSIZE;
    curIn+= AES128BYTEBLOCKSIZE;

    while(inLeft>(AES128BYTEBLOCKSIZE+SHA256DIGESTBYTESIZE)) {
        oCBC.nextCipherBlockIn(curIn, curOut);
        curIn+= AES128BYTEBLOCKSIZE;
        curOut+= AES128BYTEBLOCKSIZE;
        inLeft-= AES128BYTEBLOCKSIZE;
    }

    // final blocks
    int n= oCBC.lastCipherBlockIn(inLeft, curIn, curOut);
    if(n<0) {
    	fprintf(g_logFile, "AES128CBCHMACSHA256SYMPADDecryptBlob: bad lastCipherin %d\n", inLeft);
        return false;
    }
    *poutsize= oCBC.m_iNumPlainBytes;
#ifdef CRYPTOTEST
    PrintBytes("output:\n", out, *poutsize);
    fprintf(g_logFile, "\n%d, out\n", *poutsize);
    bool fValid= oCBC.validateMac();
    if(!fValid) 
    	fprintf(g_logFile, "AES128CBCHMACSHA256SYMPADDecryptBlob: validation failed\n");
    return fValid;
#else
    return oCBC.validateMac();
#endif
}


// -----------------------------------------------------------------------------


