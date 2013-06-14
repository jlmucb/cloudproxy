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
#include "cryptoHelper.h"

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


bool EncryptTest(RSAKey* pKey, int numBlocks, bool fFast= false, bool fEncrypt=true)
{
    int     i;
    time_t  start, finish;
    double  elapsedseconds= 0.0;
    double  ops= 0.0;
    double  opspersecond= 0.0;

    bnum    bnIn(pKey->m_iByteSizeM);
    bnum    bnEncrypted(pKey->m_iByteSizeM);
    bnum    bnDecrypted(pKey->m_iByteSizeM);
    bnum    R(256);
    bnum    bnDP(pKey->m_iByteSizeM/2);
    bnum    bnDQ(pKey->m_iByteSizeM/2);
    bnum    bnPM1(pKey->m_iByteSizeM/2);
    bnum    bnQM1(pKey->m_iByteSizeM/2);

    memset(bnIn.m_pValue, 0, pKey->m_iByteSizeM);
    memset(bnEncrypted.m_pValue, 0, pKey->m_iByteSizeM);
    memset(bnDecrypted.m_pValue, 0, pKey->m_iByteSizeM);
    u64*    puIn= (u64*) bnIn.m_pValue;
    *puIn= 237ULL;

#ifdef FAST
    if(fFast) {
        if(!mpRSACalculateFastRSAParameters(*(pKey->m_pbnE), *(pKey->m_pbnP),
                    *(pKey->m_pbnQ), bnPM1, bnDP, bnQM1, bnDQ)) {
            printf("Can't calculate RSA fast decrypt parameters\n");
            return false;
        }
    }
#endif

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
#ifdef FAST
    else if(fFast) {
        for(i=0; i<numBlocks; i++) {
            if(!mpRSADEC(bnIn, *(pKey->m_pbnP), bnPM1, bnDP, *(pKey->m_pbnQ), 
                           bnQM1, bnDQ, *(pKey->m_pbnM), bnDecrypted)) {
                printf("Can't decrypt\n");
                return false;
            }
            (*puIn)++;
        }
    }
#endif
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


bool RSASanityCheck(RSAKey* key, int file, bool fPrint, bool fFast)
{
    bool        fRet= true;
    int         numBytes= 0;
    byte        buf[4096];
    int         blockSize= key->m_iByteSizeM;
    int         numBlocks= 0;
    bool        fFailed= false;

    time_t      start, finish;
    double      elapsedseconds= 0.0;
    double      ops= 0.0;
    double      opspersecond= 0.0;

    bnum        bnMsg(key->m_iByteSizeM/sizeof(u64)+1);
    bnum        bnEncrypted(key->m_iByteSizeM/sizeof(u64)+1);
    bnum        bnDecrypted(key->m_iByteSizeM/sizeof(u64)+1);
    bnum        bnPM1(key->m_iByteSizeM/sizeof(u64)+1);
    bnum        bnQM1(key->m_iByteSizeM/sizeof(u64)+1);
    bnum        bnDP(key->m_iByteSizeM/sizeof(u64)+1);
    bnum        bnDQ(key->m_iByteSizeM/sizeof(u64)+1);

#ifdef FAST
    if(fFast) {
        printf("Fast RSA sanity check, block size is %d\n", blockSize);
        if(!mpRSACalculateFastRSAParameters(*(key->m_pbnE), *(key->m_pbnP),
                    *(key->m_pbnQ), bnPM1, bnDP, bnQM1, bnDQ)) {
            printf("Can't calculate RSA fast decrypt parameters\n");
            return false;
        }
        printf("mpRSACalculateFastRSAParameters\n"); 
        printf("P  : "); printNum(*(key->m_pbnP)); printf("\n");
        printf("PM1: "); printNum(bnPM1); printf("\n");
        printf("DP : "); printNum(bnDP); printf("\n");
        printf("Q  : "); printNum(*(key->m_pbnQ)); printf("\n");
        printf("QM1: "); printNum(bnQM1); printf("\n");
        printf("DQ : "); printNum(bnDQ); printf("\n");
    }
    else 
#endif
    printf("RSA sanity check, block size is %d\n", blockSize);
 

    time(&start);
    for(;;) {
        numBytes= read(file, buf, blockSize);
        if(numBytes<blockSize)
            break;

        ZeroWords(bnMsg.mpSize(), bnMsg.m_pValue);
        ZeroWords(bnEncrypted.mpSize(), bnEncrypted.m_pValue);
        ZeroWords(bnDecrypted.mpSize(), bnDecrypted.m_pValue);

        fFailed= false;
        memcpy(bnMsg.m_pValue, buf, blockSize);
        bnMsg.m_pValue[blockSize/sizeof(u64)-1]&= 0xffffffffULL;

        if(!mpRSAENC(bnMsg, *(key->m_pbnE), *(key->m_pbnM), bnEncrypted)) {
            printf("Can't encrypt\n");
            fFailed= true;
            fRet= false;
        }
#ifdef FAST
        if(fFast) {
            if(!mpRSADEC(bnEncrypted, *(key->m_pbnP), bnPM1, bnDP, *(key->m_pbnQ), 
                           bnQM1, bnDQ, *(key->m_pbnM), bnDecrypted)) {
                printf("Can't decrypt\n");
                fFailed= true;
                fRet= false;
            }
        }
        else {
            if(!mpRSAENC(bnEncrypted, *(key->m_pbnD), *(key->m_pbnM), bnDecrypted)) {
                printf("Can't decrypt\n");
                fFailed= true;
                fRet= false;
            }
        }
#else
        if(!mpRSAENC(bnEncrypted, *(key->m_pbnD), *(key->m_pbnM), bnDecrypted)) {
            printf("Can't decrypt\n");
            fFailed= true;
            fRet= false;
        }
#endif
        numBlocks++;

        if(memcmp(bnMsg.m_pValue, bnDecrypted.m_pValue, blockSize)!=0) {
            fFailed= true;
            fRet= false;
        }

        if(fPrint || fFailed) {
            if(fFailed) {
                printf("\nFAILED\n");
            }
            else {
                printf("\nPASSED\n");
            }
            printf("Message\n"); printNum(bnMsg); printf("\n");
            printf("Encrypted\n"); printNum(bnEncrypted); printf("\n");
            printf("Decrypted\n"); printNum(bnDecrypted); printf("\n");
        }
    }
    time(&finish);

    elapsedseconds= difftime(finish, start);
    ops= (double)numBlocks;
    opspersecond= ops/elapsedseconds;
    printf("%10.4lf seconds %d operations %10.4lf operations per second\n", 
        elapsedseconds, numBlocks, opspersecond);
    return fRet;
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
    char*       szBlockFile= NULL;
    bool        fFast= false;
    bool        fSanityOnly= false;
    int         file= -1;

    for(i=0; i<an; i++) {
        if(strcmp(av[i], "-help")==0 || an<3) {
            printf("\nUsage: rsaspeedtest keyfile -Encrypt blocks\n");
            printf("         rsaspeedtest keyfile -Decrypt blocks\n");
            printf("         rsaspeedtest keyfile -sanity file\n");
            printf("         rsaspeedtest -fast (other args)\n");
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
        if(strcmp(av[i], "-fast")==0) {
            fFast= true;
        }
        if(strcmp(av[i], "-sanity")==0) {
            fSanityOnly= true;
            if(an>(i+1)) {
                szBlockFile= av[++i];
            }
        }
    }

    pKey= (RSAKey*) ReadKeyfromFile(szKeyFile);
    if(pKey==NULL) {
        printf("Cant read key file\n");
        return 1;
    }

    initCryptoRand();
    initBigNum();

    if(fSanityOnly) {
        if(szBlockFile==NULL) {
            printf("No block file\n");
            return 1;
        }
        file= open(szBlockFile, O_RDONLY);
        if(file<0) {
            printf("Cant open block file\n");
            return 1;
        }
        if(RSASanityCheck(pKey, file, false, fFast)) {
            printf("PASSED all sanity check operations\n");
        }
        else {
            printf("FAILED some sanity check operations\n");
        }
    }
    else {

        if(mode==ENCRYPT)
            printf("RSA Encrypt, Key file %s %d blocks\n", szKeyFile, numBlocks);
        if(mode==DECRYPT) {
            if(fFast)
                printf("RSA Fast Decrypt, Key file %s %d blocks\n", szKeyFile, numBlocks);
            else
                printf("RSA Decrypt, Key file %s %d blocks\n", szKeyFile, numBlocks);
        }
        if(mode==ENCRYPT)
            EncryptTest(pKey, numBlocks, fFast, true);
        if(mode==DECRYPT)
            EncryptTest(pKey, numBlocks, fFast, false);
    }
    closeCryptoRand();
   
    return 0;
}


// -------------------------------------------------------------------------

