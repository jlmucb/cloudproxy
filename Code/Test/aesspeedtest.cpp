//
//  File: aesspeedtest.cpp
//
//  Description: aesspeedtest
//
//  Copyright (c) John Manferdelli.  All rights reserved.
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

#include "jlmTypes.h"
#include "jlmcrypto.h"
#include "jlmUtility.h"
#include "sha256.h"
#include "aes.h"
#include "aesni.h"
#include "modesandpadding.h"
#include "logging.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <time.h>


#define MAXREQUESTSIZE          2048
#define MAXADDEDSIZE              64
#define MAXREQUESTSIZEWITHPAD   (MAXREQUESTSIZE+MAXADDEDSIZE)


#define BYTEKEYSIZE    16
#define BYTEBLOCKSIZE  16

// --------------------------------------------------------------------- 


bool EncryptECBNITest(int numBlocks)

{
    aesni   oAes;
    u8      enckey[BYTEKEYSIZE];
    u8      bufIn[4*BYTEBLOCKSIZE];
    u8      bufOut[4*BYTEBLOCKSIZE];
    int     togo= numBlocks;
    time_t  start, finish;
    double  elapsedseconds= 0.0;
    double  totalbytes= 0.0;
    double  bytespersecond= 0.0;
    u32*    puIn= (u32*) bufIn;

    // init keys
    if(!getCryptoRandom(BYTEKEYSIZE*NBITSINBYTE, enckey)) {
        printf("Cant enc key\n");
        return false;
    }
    memset(bufIn,0, BYTEBLOCKSIZE);

    // init 
    if(oAes.KeySetupEnc(enckey, BYTEKEYSIZE*NBITSINBYTE)<0) {
        printf("Cant setup key\n");
        return false;
    }

    time(&start);
    // read, encrypt, and copy bytes
    while(togo-->0) {
        (*puIn)++;
        oAes.Encrypt(bufIn, bufOut);
    }
    time(&finish);

    elapsedseconds= difftime(finish, start);
    totalbytes= (double) (numBlocks*BYTEBLOCKSIZE);
    bytespersecond= totalbytes/elapsedseconds;
    printf("%10.4lf seconds %10.4lf bytes %10.4lf bytes per second\n", 
        elapsedseconds, totalbytes, bytespersecond);
    return true;
}


bool EncryptECBTest(int numBlocks)

{
    aes     oAes;
    u8      enckey[BYTEKEYSIZE];
    u8      bufIn[4*BYTEBLOCKSIZE];
    u8      bufOut[4*BYTEBLOCKSIZE];
    int     togo= numBlocks;
    time_t  start, finish;
    double  elapsedseconds= 0.0;
    double  totalbytes= 0.0;
    double  bytespersecond= 0.0;
    u32*    puIn= (u32*) bufIn;

    // init keys
    if(!getCryptoRandom(BYTEKEYSIZE*NBITSINBYTE, enckey)) {
        printf("Cant enc key\n");
        return false;
    }
    memset(bufIn,0, BYTEBLOCKSIZE);

    // init 
    if(oAes.KeySetupEnc(enckey, BYTEKEYSIZE*NBITSINBYTE)<0) {
        printf("Cant setup key\n");
        return false;
    }

    printf("Start Test %d blocks\n", togo);
    time(&start);
    // read, encrypt, and copy bytes
    while(togo-->0) {
        (*puIn)++;
        oAes.Encrypt(bufIn, bufOut);
    }
    time(&finish);
    printf("End Test\n");

    elapsedseconds= difftime(finish, start);
    totalbytes= (double) (numBlocks*BYTEBLOCKSIZE);
    bytespersecond= totalbytes/elapsedseconds;
    printf("%10.4lf seconds %10.4lf bytes %10.4lf bytes per second\n", 
        elapsedseconds, totalbytes, bytespersecond);
    return true;
}


bool EncryptCBCTest(int numBlocks)

{
    u8      enckey[BYTEKEYSIZE];
    u8      intkey[BYTEKEYSIZE];
    u8      iv[BYTEBLOCKSIZE];
    cbc     oCBC;
    u8      bufIn[4*BYTEBLOCKSIZE];
    u8      bufOut[4*BYTEBLOCKSIZE];
    int     togo= numBlocks;
    time_t  start, finish;
    double  elapsedseconds= 0.0;
    double  totalbytes= 0.0;
    double  bytespersecond= 0.0;

    // init iv and keys
    if(!getCryptoRandom(BYTEBLOCKSIZE*NBITSINBYTE, iv)) {
        printf("Cant generate iv\n");
        return false;
    }
    if(!getCryptoRandom(BYTEKEYSIZE*NBITSINBYTE, intkey)) {
        printf("Cant generate int key\n");
        return false;
    }
    if(!getCryptoRandom(BYTEKEYSIZE*NBITSINBYTE, enckey)) {
        printf("Cant enc key\n");
        return false;
    }
    memset(bufIn,0, BYTEBLOCKSIZE);

    // init 
    if(!oCBC.initEnc(AES128, SYMPAD, HMACSHA256, BYTEKEYSIZE, enckey, BYTEKEYSIZE, 
                     intkey, numBlocks*BYTEBLOCKSIZE, BYTEBLOCKSIZE, iv))
        return false;

    time(&start);
    // get and send first cipher block
    oCBC.firstCipherBlockOut(bufOut);

    // read, encrypt, and copy bytes
    while(--togo>0) {
        oCBC.nextPlainBlockIn(bufIn, bufOut);
    }

    // final block
    int n= oCBC.lastPlainBlockIn(BYTEBLOCKSIZE, bufIn, bufOut);
    if(n<0)
        return false;
    time(&finish);
    elapsedseconds= difftime(finish, start);
    totalbytes= (double) (numBlocks*BYTEBLOCKSIZE);
    bytespersecond= totalbytes/elapsedseconds;
    printf("%10.4lf seconds %10.4lf bytes %10.4lf bytes per second\n", 
        elapsedseconds, totalbytes, bytespersecond);
    return true;
}


u8 tkey[16] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};


u8 tplain[16]= {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};

/*
The Cipher Key:
[0x2b7e151628aed2a6abf7158809cf4f3c]

The Key Schedule:
[0x2b7e151628aed2a6abf7158809cf4f3c]
[0xa0fafe1788542cb123a339392a6c7605]
[0xf2c295f27a96b9435935807a7359f67f]
[0x3d80477d4716fe3e1e237e446d7a883b]
[0xef44a541a8525b7fb671253bdb0bad00]
[0xd4d1c6f87c839d87caf2b8bc11f915bc]
[0x6d88a37a110b3efddbf98641ca0093fd]
[0x4e54f70e5f5fc9f384a64fb24ea6dc4f]
[0xead27321b58dbad2312bf5607f8d292f]
[0xac7766f319fadc2128d12941575c006e]

The PLAINTEXT:
[0x6bc1bee22e409f96e93d7e117393172a]
[0xae2d8a571e03ac9c9eb76fac45af8e51]
[0x30c81c46a35ce411e5fbc1191a0a52ef]
[0xf69f2445df4f9b17ad2b417be66c3710]
The CIPHERTEXT:
[0x7649abac8119b246cee98e9b12e9197d]
[0x5086cb9b507219ee95db113a917678b2]
[0x73bed6b8e3c1743b7116e69e22229516]
*/

void initBigNum()
{
}


void initest()
{
    aesni   oAesEnc;
    aesni   oAesDec;
    u8      enckey[BYTEKEYSIZE];
    u8      bufIn[4*BYTEBLOCKSIZE];
    u8      bufOut[4*BYTEBLOCKSIZE];
    u8      bufCheck[4*BYTEBLOCKSIZE];

    printf("aesni test\n");
    memcpy(enckey, tkey, 16);
    memcpy(bufIn, tplain, 16);
    memset(bufOut, 0, 16);
    memset(bufCheck, 0, 16);

    if(!supportsni()) {
        printf("aesni not supported\n");
        return;
    }
    printf("aesni supported\n\n");
    PrintBytes("Key   " ,  enckey, 16);
    PrintBytes("In    " ,  bufIn, 16);

    // init 
    if(oAesEnc.KeySetupEnc(enckey, BYTEKEYSIZE*NBITSINBYTE)<0) {
        printf("Bad encrypt initialization\n");
        return;
    }
    if(oAesDec.KeySetupDec(enckey, BYTEKEYSIZE*NBITSINBYTE)<0) {
        printf("Bad decrypt initialization\n");
        return;
    }

    oAesEnc.Encrypt(bufIn, bufOut);
    PrintBytes("Out   " ,  bufOut, 16);
    oAesDec.Decrypt(bufOut, bufCheck);
    PrintBytes("Check " ,  bufCheck, 16);

    printf("\nEncrypt Key schedule\n");
    PrintBytes("\tRound  0" ,  (u8*)&oAesEnc.m_rk[0], 16);
    PrintBytes("\tRound  1" ,  (u8*)&oAesEnc.m_rk[4], 16);
    PrintBytes("\tRound  2" ,  (u8*)&oAesEnc.m_rk[8], 16);
    PrintBytes("\tRound  3" ,  (u8*)&oAesEnc.m_rk[12], 16);
    PrintBytes("\tRound  4" ,  (u8*)&oAesEnc.m_rk[16], 16);
    PrintBytes("\tRound  5" ,  (u8*)&oAesEnc.m_rk[20], 16);
    PrintBytes("\tRound  6" ,  (u8*)&oAesEnc.m_rk[24], 16);
    PrintBytes("\tRound  7" ,  (u8*)&oAesEnc.m_rk[28], 16);
    PrintBytes("\tRound  8" ,  (u8*)&oAesEnc.m_rk[32], 16);
    PrintBytes("\tRound  9" ,  (u8*)&oAesEnc.m_rk[36], 16);
    PrintBytes("\tRound 10" ,  (u8*)&oAesEnc.m_rk[40], 16);
    printf("Decrypt Key schedule\n");
    PrintBytes("\tRound  0" ,  (u8*)&oAesDec.m_rk[0], 16);
    PrintBytes("\tRound  1" ,  (u8*)&oAesDec.m_rk[4], 16);
    PrintBytes("\tRound  2" ,  (u8*)&oAesDec.m_rk[8], 16);
    PrintBytes("\tRound  3" ,  (u8*)&oAesDec.m_rk[12], 16);
    PrintBytes("\tRound  4" ,  (u8*)&oAesDec.m_rk[16], 16);
    PrintBytes("\tRound  5" ,  (u8*)&oAesDec.m_rk[20], 16);
    PrintBytes("\tRound  6" ,  (u8*)&oAesDec.m_rk[24], 16);
    PrintBytes("\tRound  7" ,  (u8*)&oAesDec.m_rk[28], 16);
    PrintBytes("\tRound  8" ,  (u8*)&oAesDec.m_rk[32], 16);
    PrintBytes("\tRound  9" ,  (u8*)&oAesDec.m_rk[36], 16);
    PrintBytes("\tRound 10" ,  (u8*)&oAesDec.m_rk[40], 16);
    printf("\n\nDone\n");
}

// --------------------------------------------------------------------- 


int main(int an, char** av)
{
    int     mode= CBCMODE;
    int     numBlocks= 1024;
    bool    fUseNI= false;

    initLog(NULL);
    for(int i=0; i<an; i++) {
        if(strcmp(av[i], "-help")==0) {
            printf("\nUsage: aesspeedtest -Simple blocks\n");
            return 0;
        }
        if(strcmp(av[i], "-Simple")==0) {
            if(an>(i+1)) {
                numBlocks= atoi(av[++i]);
            }
        }
        if(strcmp(av[i], "-Nitest")==0) {
            initest();
            return 0;
        }
        if(strcmp(av[i], "-GCM")==0) {
            mode= GCMMODE;
            if(an>(i+1)) {
                numBlocks= atoi(av[++i]);
            }
        }
        if(strcmp(av[i], "-ECB")==0) {
            mode= ECBMODE;
            if(an>(i+1)) {
                numBlocks= atoi(av[++i]);
            }
        }
        if(strcmp(av[i], "-ECBNI")==0) {
            mode= ECBMODE;
            fUseNI= true;
            if(an>(i+1)) {
                numBlocks= atoi(av[++i]);
            }
        }
    }

    if(mode==CBCMODE)
        printf("CBC Mode test, %d blocks\n", numBlocks);
    if(mode==GCMMODE)
        printf("GCM Mode test, %d blocks\n", numBlocks);
    if(mode==ECBMODE)
        printf("ECB Mode test, %d blocks\n", numBlocks);

    initCryptoRand();
    if(mode==CBCMODE) {
        if(!EncryptCBCTest(numBlocks))
            printf("Test failed\n");
    }
    if(mode==ECBMODE) {
        if(fUseNI) {
            if(!EncryptECBNITest(numBlocks))
                printf("Test failed\n");
        }
        else {
            if(!EncryptECBTest(numBlocks))
                printf("Test failed\n");
        }
    }
    closeCryptoRand();
   
    return 0;
}


// -------------------------------------------------------------------------


