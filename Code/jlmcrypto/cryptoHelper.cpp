
//  File: cryptoHelper.cpp
//      John Manferdelli
//
//  Description:  Crypto Helper functions
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


#include "jlmTypes.h"
#include "logging.h"
#include "keys.h"
#include "tinyxml.h"
#include "modesandpadding.h"
#include "jlmcrypto.h"
#include "jlmUtility.h"
#include "sha256.h"
#include "sha1.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "cryptoHelper.h"

#include <stdio.h>
#include <string.h>
#include <time.h>


// ----------------------------------------------------------------------------


bool  RSADecrypt(RSAKey& key, int sizein, byte* in, int* psizeout, 
                 byte* out, bool fFast)
{
    bnum    bnMsg(GLOBALMAXPUBKEYSIZE/sizeof(u64));
    bnum    bnOut(GLOBALMAXPUBKEYSIZE/sizeof(u64));

#ifdef TEST1
    PrintBytes((char*)"RSADecrypt in: ", in, sizein);
#endif
    mpZeroNum(bnMsg);
    mpZeroNum(bnOut);

    revmemcpy((byte*)bnMsg.m_pValue, in, key.m_iByteSizeM);
    if(fFast && key.m_pbnDP!=NULL && key.m_pbnDQ!=NULL &&
                key.m_pbnPM1!=NULL && key.m_pbnQM1!=NULL) {
        if(!mpRSADEC(bnMsg, *key.m_pbnP, *key.m_pbnPM1, *key.m_pbnDP, 
                     *key.m_pbnQ, *key.m_pbnQM1, 
                     *key.m_pbnDQ, *key.m_pbnM, bnOut)) {
            fprintf(g_logFile, "RSADecrypt: can't mpRSADEC\n");
            return false;
        }
    }
    else {
        if(!mpRSAENC(bnMsg, *key.m_pbnD, *key.m_pbnM, bnOut)) {
            fprintf(g_logFile, "RSADecrypt: can't mpRSAENC\n");
            return false;
        }
    }
    revmemcpy(out, (byte*)bnOut.m_pValue, key.m_iByteSizeM);
    *psizeout= key.m_iByteSizeM;

#ifdef TEST1
    PrintBytes((char*)"RSAEncrypt out: ", out, *psizeout);
#endif
    return true;
}


bool  RSAEncrypt(RSAKey& key, int sizein, byte* in, int* psizeout, byte* out)
{
    bnum    bnMsg(GLOBALMAXPUBKEYSIZE/sizeof(u64));
    bnum    bnOut(GLOBALMAXPUBKEYSIZE/sizeof(u64));

    mpZeroNum(bnMsg);
    mpZeroNum(bnOut);

#ifdef TEST1
    PrintBytes((char*)"RSAEncrypt in: ", in, sizein);
#endif
    revmemcpy((byte*)bnMsg.m_pValue, in, key.m_iByteSizeM);
    if(!mpRSAENC(bnMsg, *key.m_pbnE, *key.m_pbnM, bnOut)) {
        fprintf(g_logFile, "RSADecrypt: can't mpRSAENC\n");
        return false;
    }
    revmemcpy(out, (byte*)bnOut.m_pValue, key.m_iByteSizeM);
    *psizeout= key.m_iByteSizeM;

#ifdef TEST1
    PrintBytes((char*)"RSAEncrypt out: ", out, *psizeout);
#endif
    return true;
}


bool  RSASign(RSAKey& key, int hashType, byte* hash, 
                           int* psizeout, byte* out)
{
    byte    padded[GLOBALMAXPUBKEYSIZE];

#ifdef TEST1
    PrintBytes((char*)"RSASign in: ", hash, 32);
#endif
    if(*psizeout<key.m_iByteSizeM) {
        fprintf(g_logFile, "RSASign: output buffer too small\n");
        return false;
    }
    if(!emsapkcspad(hashType, hash, key.m_iByteSizeM, padded)) {
        fprintf(g_logFile, "RSASign: padding failed\n");
        return false;
    }
#ifdef TEST1
    PrintBytes((char*)"RSASign padded: ", padded, key.m_iByteSizeM);
#endif
    if(!RSADecrypt(key, key.m_iByteSizeM, padded, psizeout, out))
        return false;

#ifdef TEST1
    PrintBytes((char*)"RSASign out: ", out, *psizeout);
#endif
    return true;
}


bool  RSAVerify(RSAKey& key, int hashType, byte* hash, byte* in)
{
    byte    padded[GLOBALMAXPUBKEYSIZE];
    int     size= GLOBALMAXPUBKEYSIZE;

#ifdef TEST
    if(hashType==SHA1HASH)
        PrintBytes((char*)"RSAVerify hash (sha1): ", hash, 20);
    else if(hashType==SHA256HASH)
        PrintBytes((char*)"RSAVerify hash (sha256): ", hash, 32);
#endif
    if(!RSAEncrypt(key, key.m_iByteSizeM, in, &size, padded)) {
        fprintf(g_logFile, "RSAVerify: encryption failed\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "RSAVerify modulus size %d\n", key.m_iByteSizeM);
    PrintBytes((char*)"RSAVerify decrypted: ", padded, key.m_iByteSizeM);
#endif
    if(!emsapkcsverify(hashType, hash, key.m_iByteSizeM, padded))
        return false;
#ifdef TEST
    fprintf(g_logFile, "RSAVerify returns true\n");
#endif
    return true;
}


bool  RSASeal(RSAKey& key, u32 keyuse, int sizein, byte* in, 
              int* psizeout, byte* out)
{
    byte    padded[GLOBALMAXPUBKEYSIZE];
    
#ifdef TEST1
    PrintBytes((char*)"RSASeal in: ", in, sizein);
#endif
    if(!pkcsmessagepad(sizein, in, key.m_iByteSizeM, padded)) {
        fprintf(g_logFile, "RSASeal: padding failed\n");
        return false;
    }
#ifdef TEST1
    PrintBytes((char*)"RSASeal padded: ", padded, key.m_iByteSizeM);
#endif
    switch(keyuse) {
      default:
      case USEPUBLIC:
        if(!RSAEncrypt(key, key.m_iByteSizeM, padded, psizeout, out)) {
            fprintf(g_logFile, "RSASeal: encryption failed\n");
            return false;
        }
        break;
      case USEPRIVATE:
        if(!RSADecrypt(key, key.m_iByteSizeM, padded, psizeout, out, false)) {
            fprintf(g_logFile, "RSASeal: encryption failed\n");
            return false;
        }
        break;
      case USEPRIVATEFAST:
        if(!RSADecrypt(key, key.m_iByteSizeM, padded, psizeout, out, true)) {
            fprintf(g_logFile, "RSASeal: encryption failed\n");
            return false;
        }
        break;
    }
#ifdef TEST1
    PrintBytes((char*)"RSASeal out: ", out, *psizeout);
#endif
    return true;
}


bool  RSAUnseal(RSAKey& key, u32 keyuse, int sizein, byte* in, 
                int* psizeout, byte* out)
{
    byte    padded[GLOBALMAXPUBKEYSIZE];
    int     size= GLOBALMAXPUBKEYSIZE;
    
#ifdef TEST1
    fprintf(g_logFile, "RSAUnseal direction %d\n", keyuse);
    PrintBytes((char*)"RSAUnseal in: ", in, sizein);
#endif
    switch(keyuse) {
      default:
      case USEPUBLIC:
        if(!RSAEncrypt(key, key.m_iByteSizeM, in, &size, padded)) {
            fprintf(g_logFile, "RSASeal: encryption failed\n");
            return false;
        }
        break;
      case USEPRIVATE:
        if(!RSADecrypt(key, key.m_iByteSizeM, in, &size, padded, false)) {
            fprintf(g_logFile, "RSASeal: encryption failed\n");
            return false;
        }
        break;
      case USEPRIVATEFAST:
        if(!RSADecrypt(key, key.m_iByteSizeM, in, &size, padded, true)) {
            fprintf(g_logFile, "RSASeal: encryption failed\n");
            return false;
        }
        break;
    }
#ifdef TEST1
    PrintBytes((char*)"RSAUnseal decrypted: ", padded, key.m_iByteSizeM);
#endif
    if(!pkcsmessageextract(psizeout, out, key.m_iByteSizeM, padded)) {
        fprintf(g_logFile, "RSAUnseal: padding failed\n");
        return false;
    }
#ifdef TEST1
    PrintBytes((char*)"RSAUnseal extracted: ", out, *psizeout);
#endif
    return true;
}


// -----------------------------------------------------------------------------------


#ifndef MAXTRY
#define MAXTRY 30
#endif


RSAKey* RSAGenerateKeyPair(int keySize)
{
    int     iTry= 0;
    int     ikeyByteSize= 0;
    int     ikeyu64Size= 0;
    bool    fGotKey= false;

#ifdef TEST1
    fprintf(g_logFile, "generateRSAKeypair(%d)\n", keySize);
#endif
    if(keySize==1024) {
        ikeyu64Size= 16;
        ikeyByteSize= 128;
    }
    else if(keySize==2048) {
        ikeyu64Size= 32;
        ikeyByteSize= 256;
    }
    else
        return NULL;

    bnum       bnPhi(GLOBALMAXPUBKEYSIZE/sizeof(u64));
    bnum       bnE(4);
    bnum       bnP(GLOBALMAXPUBKEYSIZE/sizeof(u64));
    bnum       bnQ(GLOBALMAXPUBKEYSIZE/sizeof(u64));
    bnum       bnD(GLOBALMAXPUBKEYSIZE/sizeof(u64));
    bnum       bnM(GLOBALMAXPUBKEYSIZE/sizeof(u64));
    bnum       bnDP(GLOBALMAXPUBKEYSIZE/sizeof(u64));
    bnum       bnDQ(GLOBALMAXPUBKEYSIZE/sizeof(u64));
    bnum       bnPM1(GLOBALMAXPUBKEYSIZE/sizeof(u64));
    bnum       bnQM1(GLOBALMAXPUBKEYSIZE/sizeof(u64));

    bnE.m_pValue[0]= (1ULL<<16)+1ULL;
    while(iTry++<MAXTRY) {
        fGotKey= mpRSAGen(keySize, bnE, bnP, bnQ, bnM, bnD, bnPhi);
        if(fGotKey)
            break;
    }
    if(!fGotKey) {
        fprintf(g_logFile, "Cant generate key\n");
        return NULL;
    }
#ifdef TEST1
    fprintf(g_logFile, "generateRSAKeypair: RSA Key generated\n");
#endif

    RSAKey*  pKey= new RSAKey();
    if(keySize==1024) {
        pKey->m_ukeyType= RSAKEYTYPE;
        pKey->m_uAlgorithm= RSA1024;
        pKey->m_ikeySize= 1024;
    }
    else if(keySize==2048) {
        pKey->m_ukeyType= RSAKEYTYPE;
        pKey->m_uAlgorithm= RSA2048;
        pKey->m_ikeySize= 2048;
    }
#ifdef TEST1
    fprintf(g_logFile, "generateRSAKeypair: ikeyByteSize= %d\n", 
            ikeyByteSize);
#endif

    pKey->m_ikeyNameSize= 0;
    pKey->m_iByteSizeM= ikeyByteSize;
    pKey->m_iByteSizeD= ikeyByteSize;
    pKey->m_iByteSizeE= 4*sizeof(u64);
    pKey->m_iByteSizeP= ikeyByteSize/2;
    pKey->m_iByteSizeQ= ikeyByteSize/2;

    memcpy(pKey->m_rgbM,(byte*)bnM.m_pValue, pKey->m_iByteSizeM);
    memcpy(pKey->m_rgbP,(byte*)bnP.m_pValue, pKey->m_iByteSizeP);
    memcpy(pKey->m_rgbQ,(byte*)bnQ.m_pValue, pKey->m_iByteSizeQ);
    memcpy(pKey->m_rgbE,(byte*)bnE.m_pValue, pKey->m_iByteSizeE);
    memcpy(pKey->m_rgbD,(byte*)bnD.m_pValue, pKey->m_iByteSizeD);

    pKey->m_pbnM= new bnum(ikeyu64Size);
    pKey->m_pbnP= new bnum(ikeyu64Size/2);
    pKey->m_pbnQ= new bnum(ikeyu64Size/2);
    pKey->m_pbnE= new bnum(4);
    pKey->m_pbnD= new bnum(ikeyu64Size);

    memcpy(pKey->m_pbnM->m_pValue,(byte*)bnM.m_pValue, pKey->m_iByteSizeM);
    memcpy(pKey->m_pbnP->m_pValue,(byte*)bnP.m_pValue, pKey->m_iByteSizeP);
    memcpy(pKey->m_pbnQ->m_pValue,(byte*)bnQ.m_pValue, pKey->m_iByteSizeQ);
    memcpy(pKey->m_pbnE->m_pValue,(byte*)bnE.m_pValue, pKey->m_iByteSizeE);
    memcpy(pKey->m_pbnD->m_pValue,(byte*)bnD.m_pValue, pKey->m_iByteSizeD);
    pKey->m_pbnPM1= new bnum(ikeyu64Size/2);
    pKey->m_pbnQM1= new bnum(ikeyu64Size/2);

    if(!mpRSACalculateFastRSAParameters(bnE, bnP, bnQ, bnPM1, bnDP, bnQM1, bnDQ)) {
        fprintf(g_logFile, "Cant generate fast rsa parameters\n");
    }
    else {
        pKey->m_iByteSizeDP= ikeyByteSize/2;
        pKey->m_iByteSizeDQ= ikeyByteSize/2;
        pKey->m_pbnDP= new bnum(ikeyu64Size/2);
        pKey->m_pbnDQ= new bnum(ikeyu64Size/2);

        memcpy(pKey->m_pbnDP->m_pValue,(byte*)bnDP.m_pValue, pKey->m_iByteSizeDP);
        memcpy(pKey->m_pbnDQ->m_pValue,(byte*)bnDQ.m_pValue, pKey->m_iByteSizeDQ);

        memcpy(pKey->m_rgbDP,(byte*)bnDP.m_pValue, pKey->m_iByteSizeDP);
        memcpy(pKey->m_rgbDQ,(byte*)bnDQ.m_pValue, pKey->m_iByteSizeDQ);
        memcpy(pKey->m_rgbDP,(byte*)bnDP.m_pValue, pKey->m_iByteSizeDP);
        memcpy(pKey->m_rgbDQ,(byte*)bnDQ.m_pValue, pKey->m_iByteSizeDQ);

        if(pKey->m_iByteSizeDP>0 &&  pKey->m_iByteSizeDQ>0 && 
                   pKey->m_pbnPM1!=NULL && pKey->m_pbnQM1!=NULL) {
            mpSub(*(pKey->m_pbnP), g_bnOne, *(pKey->m_pbnPM1));
            mpSub(*(pKey->m_pbnQ), g_bnOne, *(pKey->m_pbnQM1));
        }

    }

    return pKey;
}


// -----------------------------------------------------------------------------------


RSAKey* RSAKeyfromKeyInfoNode(TiXmlNode* pNode)
{
    RSAKey* pKey= NULL;
    char*   szDoc= NULL;

    try {
        pKey= new RSAKey();
    
        szDoc = canonicalize(pNode);
        if(szDoc==NULL)
            throw("Cant canonicalize keyinfo\n");

        if(!pKey->ParsefromString(szDoc)) 
            throw("Cant parse KeyInfo\n");

        if(!pKey->getDataFromDoc())
            throw("Cant get data from KeyInfo\n");
        }
    catch(const char* szError) {
        fprintf(g_logFile, "RSAKeyFromParsedKeyInfo: %s\n", szError);
        if(pKey!=NULL) {
            delete pKey;
            pKey= NULL;
        }
        if(szDoc!=NULL) {
            free(szDoc);
            szDoc= NULL;
        }
    }
    return pKey;
}


char* RSAKeyInfofromKey(RSAKey& key)
{
    return key.SerializePublictoString();
}


char* RSAPublicKeyInfofromKey(RSAKey& key)
{
    return key.SerializePublictoString();
}


RSAKey* RSAKeyfromkeyInfo(const char* szKeyInfo)
{
    RSAKey*         pKey= new RSAKey();
    TiXmlElement*   pRootElement= NULL;

    if(pKey==NULL)
        return NULL;
#ifdef QUOTETEST
    fprintf(g_logFile, "keyfromkeyInfo, Keyinfo\n%s\n", szKeyInfo);
#endif
    if(!pKey->ParsefromString(szKeyInfo)) {
        fprintf(g_logFile, "keyfromkeyInfo: cant get key from keyInfo\n");
        goto cleanup;
    }
    pRootElement= pKey->m_pDoc->RootElement();
    if(pRootElement==NULL) {
        fprintf(g_logFile, "keyfromkeyInfo: cant get root element\n");
        goto cleanup;
    }

    if(!pKey->getDataFromRoot(pRootElement)) {
        fprintf(g_logFile, "keyfromkeyInfo: cant getDataFromRoot\n");
        goto cleanup;
    }

cleanup:
    return pKey;
}


bool sameRSAKey(RSAKey* pKey1, RSAKey* pKey2)
{
    if(pKey1->m_iByteSizeM!=pKey2->m_iByteSizeM)
        return false;
    if(memcmp(pKey1->m_rgbM, pKey2->m_rgbM, pKey1->m_iByteSizeM)!=0)
        return false;
    if(pKey1->m_iByteSizeE!=pKey2->m_iByteSizeE)
        return false;
    if(memcmp(pKey1->m_rgbE, pKey2->m_rgbE, pKey1->m_iByteSizeE)!=0)
        return false;
    return true;
}


char* XMLCanonicalizedString(const char* szXML)
{
    TiXmlDocument doc;

    if(!doc.Parse(szXML)) {
        fprintf(g_logFile, "XMLCanonicalizedString: Cant parse Xml Document\n");
        return NULL;
    }
    if(doc.RootElement()==NULL) {
        fprintf(g_logFile, "XMLCanonicalizedString: Cant get root element\n");
        return NULL;
    }
    return canonicalize((TiXmlNode*) doc.RootElement());
}


KeyInfo* ReadKeyfromFile(const char* szKeyFile)
{
    KeyInfo*    pParseKey= new KeyInfo;
    RSAKey*     pRSAKey= NULL;
    symKey*     pAESKey= NULL;
    KeyInfo*    pRetKey= NULL;
    int         iKeyType;

    TiXmlDocument* pDoc= new TiXmlDocument();
    if(pDoc==NULL) {
        fprintf(g_logFile, "Cant get new an Xml Document\n");
        return NULL;
    }

    if(!pDoc->LoadFile(szKeyFile)) {
        fprintf(g_logFile, "Cant load keyfile\n");
        return NULL;
    }
    iKeyType= pParseKey->getKeyType(pDoc);

    switch(iKeyType) {
      case AESKEYTYPE:
        pAESKey= new symKey();
        if(pAESKey==NULL) {
            fprintf(g_logFile, "Cant new symKey\n");
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
            fprintf(g_logFile, "Cant new RSAKey\n");
            break;
        }
        else
            pRSAKey->m_pDoc= pDoc;
        pRSAKey->getDataFromDoc();
        pRetKey= (KeyInfo*) pRSAKey;
        break;
      default:
       fprintf(g_logFile, "Unknown key type in ReadFromFile\n");
       break;
    }
    delete pParseKey;
    // Dont forget to delete pDoc;

    return pRetKey;
}


// -------------------------------------------------------------------------------


int timeCompare(struct tm& time1, struct tm& time2)
{
    if(time1.tm_year>time2.tm_year)
        return 1;
    if(time1.tm_year<time2.tm_year)
        return -1;
    if(time1.tm_mon>time2.tm_mon)
        return 1;
    if(time1.tm_mon<time2.tm_mon)
        return -1;
    if(time1.tm_mday>time2.tm_mday)
        return 1;
    if(time1.tm_mday<time2.tm_mday)
        return -1;
    if(time1.tm_hour>time2.tm_hour)
        return 1;
    if(time1.tm_hour<time2.tm_hour)
        return -1;
    if(time1.tm_min>time2.tm_min)
        return 1;
    if(time1.tm_min<time2.tm_min)
        return -1;
    if(time1.tm_sec>time2.tm_sec)
        return 1;
    if(time1.tm_sec<time2.tm_sec)
        return -1;

    return 0;
}


#ifdef TEST
void printTime(struct tm* timeinfo)
{
    if(timeinfo==NULL) {
    fprintf(g_logFile, "NULL\n");
    }
    fprintf(g_logFile, "%04d-%02d-%02dZ%02d:%02d.%02d\n",
                1900+timeinfo->tm_year, timeinfo->tm_mon+1,
                timeinfo->tm_mday, timeinfo->tm_hour,
                timeinfo->tm_min, timeinfo->tm_sec);
}
#endif


char* stringtimefromtimeInfo(struct tm* timeinfo)
{
    char    szTime[128];

    sprintf(szTime, "%04d-%02d-%02dZ%02d:%02d.%02d",
                1900+timeinfo->tm_year, timeinfo->tm_mon+1,
                timeinfo->tm_mday, timeinfo->tm_hour,
                timeinfo->tm_min, timeinfo->tm_sec);
    return strdup(szTime);
}

struct tm* timeNow()
{
    time_t      now;

    time(&now);
    return gmtime(&now);
}


bool timeInfofromstring(const char* szTime, struct tm& thetime)
{
    sscanf(szTime, "%04d-%02d-%02dZ%02d:%02d.%02d",
            &thetime.tm_year, &thetime.tm_mon,
            &thetime.tm_mday, &thetime.tm_hour,
            &thetime.tm_min, &thetime.tm_sec);
    thetime.tm_year-= 1900;
    thetime.tm_mon-= 1;
    return true;
}


bool checktimeinInterval(tm& time, tm& begin, tm& end)
// is time less than or equal to endtime and greater than or equal to begin time
{
    return timeCompare(end, time)!=(-1) && timeCompare(begin, time)!=1;
}



// -------------------------------------------------------------------------------


int maxbytesfromBase64string(int nc)
{
    return (6*nc+NBITSINBYTE-1)/NBITSINBYTE;
}


int maxcharsinBase64stringfrombytes(int nb)
{
    return (NBITSINBYTE*nb+5)/6;
}


bool base64frombytes(int nb, byte* in, int* pnc, char* out)
{
    int     size= *pnc;

    if(size<maxcharsinBase64stringfrombytes(nb)) {
        fprintf(g_logFile, "base64frombytes: base64 output buffer too small\n");
        return false;
    }

    if(!toBase64(nb, in, &size, out)) {
        fprintf(g_logFile, "base64frombytes: conversion failed\n");
        return false;
    }
    *pnc= size;
    return true;
}


bool bytesfrombase64(char* in, int* pnb, byte* out)
{
    int     size= *pnb;
    int     n= strlen(in);

    if(size<maxbytesfromBase64string(n)) {
        fprintf(g_logFile, "bytesfrombase64: output buffer too small\n");
        return false;
    }
    if(!fromBase64(n, in, &size, out)) {
        fprintf(g_logFile, "bytesfrombase64: conversion failed\n");
        return false;
    }
    *pnb= size;
    return true;
}


bool  XMLenclosingtypefromelements(const char* tag, int numAttr, 
                                   const char** attrName, const char** attrValues, 
                                   int numElts, const char** elts, 
                                   int* psize, char* buf)
{
    int     size;
    int     n= 0;
    int     i;

    n= 2*strlen(tag)+8;
    for(i=0; i<numAttr; i++)
        n+= strlen(attrName[i])+strlen(attrValues[i])+4;
    for(i=0; i<numElts; i++)
        n+= strlen(elts[i])+3;
    if(n>*psize) {
        fprintf(g_logFile, "XMLenclosingtypefromelements: output buffer too small\n");
        return false;
    }

    n= 0;
    sprintf(&buf[n], "<%s", tag);
    for(i=0; i<numAttr; i++) {
        n= strlen(buf);
        sprintf(&buf[n], " %s=\"%s\"", attrName[i], attrValues[i]);
    }
    n= strlen(buf);
    sprintf(&buf[n], ">\n");
    for(i=0;i<numElts;i++) {
        n= strlen(buf);
        sprintf(&buf[n], "  %s\n", elts[i]);
    }
    n= strlen(buf);
    sprintf(&buf[n], "</%s>\n", tag);
    size= strlen(buf);
    if(size>*psize) {
        fprintf(g_logFile, "bytesfrombase64: conversion failed\n");
        return false;
    }
    *psize= size;
    return true;
}


// -------------------------------------------------------------------------------


bool VerifyRSASha1SignaturefromSignedInfoandKey(RSAKey& key, 
                                                  char* szsignedInfo, 
                                                  char* szSigValue)
{
    Sha1        oHash;
    byte        rgComputedHash[SHA256_DIGESTSIZE_BYTES];
    byte        rgSigValue[GLOBALMAXPUBKEYSIZE];
    int         size;
    int         n;

    // hash  signedInfo
    oHash.Init();
    oHash.Update((byte*)szsignedInfo, strlen(szsignedInfo));
    oHash.Final();
    oHash.getDigest(rgComputedHash);

    UNUSEDVAR(n);
    n= strlen(szSigValue);
    if(GLOBALMAXPUBKEYSIZE<maxbytesfromBase64string(strlen(szSigValue))) {
        fprintf(g_logFile, 
             "VerifyRSASha1SignaturefromSignedInfoandKey: buffer too small\n");
        return false;
    }
    size= GLOBALMAXPUBKEYSIZE;
    if(!bytesfrombase64(szSigValue, &size, rgSigValue)) {
        fprintf(g_logFile, 
             "VerifyRSASha1SignaturefromSignedInfoandKey: cant base64 decode\n");
        return false;
    }

    return RSAVerify(key, SHA1HASH, rgComputedHash, rgSigValue);
}


bool VerifyRSASha256SignaturefromSignedInfoandKey(RSAKey& key, 
                                                  char* szsignedInfo, 
                                                  char* szSigValue)
{
    Sha256      oHash;
    byte        rgComputedHash[SHA256_DIGESTSIZE_BYTES];
    byte        rgSigValue[GLOBALMAXPUBKEYSIZE];
    int         size;
    int         n;

    // hash  signedInfo
    oHash.Init();
    oHash.Update((byte*)szsignedInfo, strlen(szsignedInfo));
    oHash.Final();
    oHash.GetDigest(rgComputedHash);

    UNUSEDVAR(n);
    n= strlen(szSigValue);
    if(GLOBALMAXPUBKEYSIZE<maxbytesfromBase64string(strlen(szSigValue))) {
        fprintf(g_logFile, 
             "VerifyRSASha256SignaturefromSignedInfoandKey: buffer too small\n");
        return false;
    }
    size= GLOBALMAXPUBKEYSIZE;
    if(!bytesfrombase64(szSigValue, &size, rgSigValue)) {
        fprintf(g_logFile, 
             "VerifyRSASha256SignaturefromSignedInfoandKey: cant base64 decode\n");
        return false;
    }

    return RSAVerify(key, SHA256HASH, rgComputedHash, rgSigValue);
}


char* XMLRSASha256SignaturefromSignedInfoandKey(RSAKey& key, 
                                                const char* szsignedInfo)
{
    Sha256      oHash;
    byte        rgComputedHash[SHA256_DIGESTSIZE_BYTES];
    byte        rgSigValue[GLOBALMAXPUBKEYSIZE];
    int         size;
    int         n;
    char        szSigValue[4*GLOBALMAXPUBKEYSIZE];

    // hash  signedInfo
    n= strlen(szsignedInfo);
    oHash.Init();
    oHash.Update((byte*)szsignedInfo, n);
    oHash.Final();
    oHash.GetDigest(rgComputedHash);

    size= GLOBALMAXPUBKEYSIZE;
    if(!RSASign(key, SHA256HASH, rgComputedHash, 
                                 &size, rgSigValue)) {
        fprintf(g_logFile, 
             "XMLRSASha256SignaturefromSignedInfoandKey: sign fails\n");
        return (char *)NULL;
    }

    n= 2048;
    if(!base64frombytes(size, rgSigValue, &n, szSigValue)) {
        fprintf(g_logFile, 
             "XMLRSASha256SignaturefromSignedInfoandKey: base64 encode fails\n");
        return (char *) NULL;
    }
    return strdup(szSigValue);
}


char* XMLRSASha256SignaturefromSignedInfoNodeandKey(RSAKey& key, 
                                                    TiXmlNode* signedInfo)
{
    char*   szsignedInfo= canonicalize(signedInfo);
    char*   szSig= XMLRSASha256SignaturefromSignedInfoandKey(key,
                                                szsignedInfo);

    if(szsignedInfo!=NULL) {
        free(szsignedInfo);
        szsignedInfo= NULL;
    }
    return szSig;
}


char* constructXMLRSASha256SignaturefromSignedInfoandKey(RSAKey& key, 
                                                const char* id, 
                                                const char* szsignedInfo)
{
    const char* attrName[2]= {"xmlns", "Id"};
    const char* attrValue[2]= {"http://www.w3.org/2000/09/xmldsig#", NULL};
    const char* elts[3];
    int         size= 16*GLOBALMAXPUBKEYSIZE;
    char        szSignature[16*GLOBALMAXPUBKEYSIZE];
    char*       szKeyInfo= NULL;
    char        szSignatureElement[8*GLOBALMAXPUBKEYSIZE];
    char*       szSig= XMLRSASha256SignaturefromSignedInfoandKey(key,
                                                szsignedInfo);
    bool        fRet= true;

    if(szSig==NULL) {
        return NULL;
    }
    szKeyInfo= RSAPublicKeyInfofromKey(key);
    if(szKeyInfo==NULL) 
        return NULL;
    sprintf(szSignatureElement, "  <ds:SignatureValue> %s </ds:SignatureValue>\n",
            szSig);

    attrValue[1]= id;
    elts[0]= szsignedInfo;
    elts[1]= szSignatureElement;
    elts[2]= szKeyInfo;

    size= 16*GLOBALMAXPUBKEYSIZE;
    fRet= XMLenclosingtypefromelements("ds:Signature", 2, attrName, attrValue, 
                                   3, elts, &size, szSignature);

    if(szKeyInfo!=NULL) {
        free(szKeyInfo);
        szKeyInfo= NULL;
    }
    if(fRet)
        return strdup(szSignature);
    return NULL;
}


// -------------------------------------------------------------------------------


