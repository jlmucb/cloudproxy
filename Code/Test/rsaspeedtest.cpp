//
//  File: rsaspeedtest.cpp
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
#include "bignum.h"
#include "mpFunctions.h"
#include "modesandpadding.h"
#include "rsaHelper.h"

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


#define DEBUG4


// --------------------------------------------------------------------- 


KeyInfo* ReadKeyfromFile(const char* szKeyFile)
{
    KeyInfo*    pParseKey= new KeyInfo;
    RSAKey*     pRSAKey= NULL;
    symKey*     pAESKey= NULL;
    KeyInfo*    pRetKey= NULL;
    int         iKeyType;

    TiXmlDocument* pDoc= new TiXmlDocument();
    if(pDoc==NULL) {
        printf("Cant get new an Xml Document\n");
        return NULL;
    }

    if(!pDoc->LoadFile(szKeyFile)) {
        printf("Cant load keyfile\n");
        return NULL;
    }
    iKeyType= pParseKey->getKeyType(pDoc);

    switch(iKeyType) {
      case AESKEYTYPE:
        pAESKey= new symKey();
        if(pAESKey==NULL) {
            printf("Cant new symKey\n");
            break;
        }
        else
            pAESKey->m_pDoc= pDoc;
        pAESKey->getDataFromDoc();
        pRetKey= (KeyInfo*) pAESKey;
        break;
      case RSAKEYTYPE:
        pRSAKey= new RSAKey();
        if(pRSAKey==NULL) {
            printf("Cant new RSAKey\n");
            break;
        }
        else
            pRSAKey->m_pDoc= pDoc;
        pRSAKey->getDataFromDoc();
        pRetKey= (KeyInfo*) pRSAKey;
        break;
      default:
       printf("Unknown key type in ReadFromFile\n");
       break;
    }
    delete pParseKey;
    // Dont forget to delete pDoc;

    return pRetKey;
}


bool EncryptTest(RSAKey* pKey, int numBlocks, bool fEncrypt=true)
{
    int     i;
    time_t  start, finish;
    double  elapsedseconds= 0.0;
    double  ops= 0.0;
    double  opspersecond= 0.0;

    //printf("\n");
    //pKey->printMe();
    //printf("\n");

    bnum    bnIn(pKey->m_iByteSizeM);
    bnum    bnEncrypted(pKey->m_iByteSizeM);
    bnum    bnDecrypted(pKey->m_iByteSizeM);
    bnum    R(256);

    memset(bnIn.m_pValue, 0, pKey->m_iByteSizeM);
    memset(bnEncrypted.m_pValue, 0, pKey->m_iByteSizeM);
    memset(bnDecrypted.m_pValue, 0, pKey->m_iByteSizeM);
    u64*    puIn= (u64*) bnIn.m_pValue;
    *puIn= 237ULL;

    time(&start);
    if(fEncrypt) {
        for(i=0; i<numBlocks; i++) {
            if(!mpRSAENC(bnIn, *(pKey->m_pbnE), *(pKey->m_pbnM), bnEncrypted)) {
                printf("Can't encrypt\n");
                return false;
            }
            (*puIn)++;
        }
    }
    else {
        for(i=0; i<numBlocks; i++) {
            if(!mpRSAENC(bnIn, *(pKey->m_pbnD), *(pKey->m_pbnM), bnDecrypted)) {
                printf("Can't decrypt\n");
                return false;
            }
            (*puIn)++;
        }
    }
    time(&finish);

    elapsedseconds= difftime(finish, start);
    ops= (double)numBlocks;
    opspersecond= ops/elapsedseconds;
    printf("%10.4lf seconds %d operations %10.4lf operations per second\n", 
        elapsedseconds, numBlocks, opspersecond);

    return true;
}


// --------------------------------------------------------------------- 


#define ENCRYPT 1
#define DECRYPT 2


int main(int an, char** av)
{
    int         i;
    int         mode= ENCRYPT;
    int         numBlocks= 1024;
    RSAKey*     pKey= NULL;
    char*       szKeyFile= NULL;

    for(i=0; i<an; i++) {
        if(strcmp(av[i], "-help")==0 || an<3) {
            printf("\nUsage: rsaspeedtest keyfile -Encrypt blocks\n");
            printf("         rsaspeedtest keyfile -Decrypt blocks\n");
            return 0;
        }

        if(i<2) {
            szKeyFile= av[1];
            i= 2;
        }
        
        if(strcmp(av[i], "-Encrypt")==0) {
            mode= ENCRYPT;
            if(an>(i+1)) {
                numBlocks= atoi(av[++i]);
            }
        }
        if(strcmp(av[i], "-Decrypt")==0) {
            mode= DECRYPT;
            if(an>(i+1)) {
                numBlocks= atoi(av[++i]);
            }
        }
    }

    if(mode==ENCRYPT)
        printf("RSA Encrypt, Key file %s %d blocks\n", szKeyFile, numBlocks);
    if(mode==DECRYPT)
        printf("RSA Decrypt, Key file %s %d blocks\n", szKeyFile, numBlocks);

    pKey= (RSAKey*) ReadKeyfromFile(szKeyFile);
    if(pKey==NULL) {
        printf("Cant read key file\n");
        return 1;
    }

    initCryptoRand();
    initBigNum();
    if(mode==ENCRYPT)
        EncryptTest(pKey, numBlocks, true);
    if(mode==DECRYPT)
        EncryptTest(pKey, numBlocks, false);
    closeCryptoRand();
   
    return 0;
}


// -------------------------------------------------------------------------

