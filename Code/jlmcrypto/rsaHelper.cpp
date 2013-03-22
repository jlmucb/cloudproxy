//
//  File: rsaHelper.cpp
//      John Manferdelli
//
//  Description:  RSA Helper functions
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
#include "jlmcrypto.h"
#include "jlmUtility.h"
#include "sha256.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "rsaHelper.h"
#include "modesandpadding.h"

#include <string.h>


extern const char*  szAESKeyProto;
extern const char*  szRSAKeyProto;


// -----------------------------------------------------------------------------------


#ifndef MAXTRY
#define MAXTRY 30
#endif


RSAKey* generateRSAKeypair(int keySize)
{
    int     iTry= 0;
    int     ikeyByteSize= 0;
    int     ikeyu64Size= 0;
    bool    fGotKey= false;

#ifdef TEST
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

    bnum       bnPhi(128);
    bnum       bnE(4);
    bnum       bnP(ikeyu64Size);
    bnum       bnQ(ikeyu64Size);
    bnum       bnD(ikeyu64Size);
    bnum       bnM(ikeyu64Size);

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
#ifdef TEST
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

    pKey->m_rgkeyName[0]= 0;
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

    return pKey;
}


// -----------------------------------------------------------------------------------


bool initRSAKeyFromKeyInfo(RSAKey** ppKey, TiXmlNode* pNode)
{
    *ppKey= new RSAKey();
    if((*ppKey)==NULL) {
         fprintf(g_logFile, "Cant allocate key\n");
         return false;
    }
    
    char* szDoc = canonicalize(pNode);
    if(szDoc==NULL) {
         fprintf(g_logFile, "Cant canonicalize keyinfo\n");
         return false;
    }

    if(!(*ppKey)->ParsefromString(szDoc)) {
         fprintf(g_logFile, "Cant parse KeyInfor\n");
         return false;
    }

    if(!(*ppKey)->getDataFromDoc()) {
         fprintf(g_logFile, "Cant get data from KeyInfo\n");
         return false;
    }

    return true;
}


bool initRSAKeyFromStringRSAKey(RSAKey** ppKey, const char* szXml, const char* szLoc)
{
    if(ppKey==NULL || szXml==NULL)
        return false;

    if(szLoc==NULL)
        szLoc= "unknown";

    *ppKey= new RSAKey();
    if((*ppKey)==NULL) {
         fprintf(g_logFile, "Cant %s key (1)\n", szLoc);
         return false;
    }
    
    (*ppKey)->m_pDoc= new TiXmlDocument();  
    if((*ppKey)->m_pDoc==NULL) {
         fprintf(g_logFile, "Cant init %s key document\n", szLoc);
         return false;
    }

    if(!(*ppKey)->ParsefromString(szXml)) {
         fprintf(g_logFile, "Cant parse %s key\n%s\n", szLoc,szXml);
         return false;
    }

    if(!(*ppKey)->getDataFromDoc()) {
         fprintf(g_logFile, "Cant get data from %s key document\n", szLoc);
         return false;
    }

    return true;
}


// -------------------------------------------------------------------------------


bool bumpChallenge(int iSize, byte* puChallenge)
{
    int     ibnSize= ((iSize+sizeof(u64)-1)/sizeof(u64))*sizeof(u64);
    bnum    bnN(ibnSize);

    memcpy(bnN.m_pValue, puChallenge, iSize);
    mpInc(bnN);
    memcpy(puChallenge, bnN.m_pValue, iSize);
    
    return true;
}


bool rsaXmlDecryptandGetNonce(bool fEncrypt, RSAKey& rgKey, int sizein, byte* rgIn,
                int sizeNonce, byte* rgOut)

{
    byte    rgPadded[4096];
    bnum    bnMsg(rgKey.m_iByteSizeM/2);
    bnum    bnOut(rgKey.m_iByteSizeM/2);

    if(sizeNonce>(rgKey.m_iByteSizeM-11)) {
        fprintf(g_logFile, "rsaXmlDecryptandGetNonce: bad sealed nonce size\n");
        return false;
    }
    mpZeroNum(bnMsg);
    mpZeroNum(bnOut);
    memset(rgPadded, 0, rgKey.m_iByteSizeM);
    memcpy((byte*)bnMsg.m_pValue, rgIn, rgKey.m_iByteSizeM);
    if(fEncrypt) {
        if(!mpRSAENC(bnMsg, *(rgKey.m_pbnE), *(rgKey.m_pbnM), bnOut)) {
            fprintf(g_logFile, "rsaXmlDecryptandGetNonce: decrypt failure\n");
            return false;
        }
        revmemcpy(rgPadded, (byte*)bnOut.m_pValue, rgKey.m_iByteSizeM);
    }
    else {
        if(!mpRSAENC(bnMsg, *(rgKey.m_pbnD), *(rgKey.m_pbnM), bnOut)) {
            fprintf(g_logFile, "rsaXmlDecryptandGetNonce: decrypt failure\n");
            return false;
        }
        revmemcpy(rgPadded, (byte*)bnOut.m_pValue, rgKey.m_iByteSizeM);
    }
#ifdef TEST
    PrintBytes("rsaXmlDecryptandGetNonce:: padded\n", rgPadded, 
                rgKey.m_iByteSizeM);
#endif
    memcpy((void*)rgOut, (void*)&rgPadded[rgKey.m_iByteSizeM-sizeNonce], sizeNonce);
    return true;
}


bool rsaXmlDecodeandVerifyChallenge(bool fEncrypt, RSAKey& rgKey, const char* szSig,
                int sizeChallenge, byte* puOriginal)

{
    int     iOut;
    byte    rgPadded[1024];
    byte    rgBase64Decoded[1024];
    bnum    bnMsg(rgKey.m_iByteSizeM/2);
    bnum    bnOut(rgKey.m_iByteSizeM/2);

    if(sizeChallenge!=32) {
        fprintf(g_logFile, 
          "rsaXmlDecodeandVerifyChallenge: Only take 32 byte challenges now, this is %d\n",
          sizeChallenge);
        return NULL;
    }
    iOut= 1024;
    if(!fromBase64(strlen(szSig), szSig, &iOut, rgBase64Decoded)) {
        fprintf(g_logFile, "rsaXmlDecodeChallenge: Cant base64 decode challenge\n");
        return false;
    }
#ifdef TEST
    PrintBytes("rsaXmlDecodeandVerifyChallenge decoded\n", rgBase64Decoded, iOut);
#endif
    mpZeroNum(bnMsg);
    mpZeroNum(bnOut);
    memset(rgPadded, 0, 1024);
    if(rgKey.m_iByteSizeM!=iOut) {
        fprintf(g_logFile, "rsaXmlDecodeandVerifyChallenge: bad signed challenge size\n");
        return false;
    }
    memcpy((byte*)bnMsg.m_pValue, rgBase64Decoded, rgKey.m_iByteSizeM);
    if(fEncrypt) {
        if(!mpRSAENC(bnMsg, *(rgKey.m_pbnE), *(rgKey.m_pbnM), bnOut)) {
            fprintf(g_logFile, "rsaXmlDecodeandVerifyChallenge: decrypt failure\n");
            return false;
        }
        revmemcpy(rgPadded, (byte*)bnOut.m_pValue, rgKey.m_iByteSizeM);
    }
    else {
        if(!mpRSAENC(bnMsg, *(rgKey.m_pbnD), *(rgKey.m_pbnM), bnOut)) {
            fprintf(g_logFile, "rsaXmlDecodeandVerifyChallenge: decrypt failure\n");
            return false;
        }
        revmemcpy(rgPadded,(byte*)bnOut.m_pValue, rgKey.m_iByteSizeM);
    }
#ifdef TEST
    PrintBytes("rsaXmlDecodeandVerifyChallenge: padded\n", rgPadded, 
                rgKey.m_iByteSizeM);
#endif
    if(!emsapkcsverify(SHA256HASH, puOriginal, rgKey.m_iByteSizeM, rgPadded)) {
        fprintf(g_logFile, "rsaXmlDecodeandVerifyChallenge: padding failure\n");
        fflush(g_logFile);
        return false;
    }
#ifdef CRYPTOTEST
    fprintf(g_logFile, "rsaXmlDecodeandVerifyChallenge: sucess\n");
    fflush(g_logFile);
#endif
    return true;
}


char* rsaXmlEncodeChallenge(bool fEncrypt, RSAKey& rgKey, byte* puChallenge, 
                            int sizeChallenge)

{
    int     iOut;
    byte    rgPadded[1024];
    char    rgBase64[1024];
    bnum    bnMsg(rgKey.m_iByteSizeM/2);
    bnum    bnOut(rgKey.m_iByteSizeM/2);
    u32     uHash= 0;

#ifdef TEST
    fprintf(g_logFile, "rsaXmlEncodeChallenge\n");
    fflush(g_logFile);
#endif
    if(sizeChallenge==32) {
        uHash=SHA256HASH;
    }
    else if(sizeChallenge==64) {
        uHash=SHA512HASH;
    }
    else {
        fprintf(g_logFile, "Only take 32 byte challenges now, this is %d\n",
                sizeChallenge);
        return NULL;
    }
    memset(rgPadded, 0, 512);
    if(!emsapkcspad(uHash, puChallenge, rgKey.m_iByteSizeM, rgPadded)) {
        fprintf(g_logFile, "rsaXmlEncryptandEncodeChallenge: padding failure\n");
        return NULL;
    }
#ifdef TEST
    PrintBytes("rsaXmlEncodeChallenge: padded\n", rgPadded, 
                rgKey.m_iByteSizeM);
#endif
    memset(bnMsg.m_pValue, 0, rgKey.m_iByteSizeM);
    memset(bnOut.m_pValue, 0, rgKey.m_iByteSizeM);
    if(fEncrypt) {
        revmemcpy((byte*)bnMsg.m_pValue, rgPadded, rgKey.m_iByteSizeM);
        if(!mpRSAENC(bnMsg, *(rgKey.m_pbnE), *(rgKey.m_pbnM), bnOut)) {
            fprintf(g_logFile, "rsaXmlEncryptandEncodeChallenge: decrypt failure\n");
            return NULL;
        }
    }
    else {
        revmemcpy((byte*)bnMsg.m_pValue, rgPadded, rgKey.m_iByteSizeM);
        if(!mpRSAENC(bnMsg, *(rgKey.m_pbnD), *(rgKey.m_pbnM), bnOut)) {
            fprintf(g_logFile, "rsaXmlEncryptandEncodeChallenge: decrypt failure\n");
            return NULL;
        }
    }
    iOut= 1024;
    if(!toBase64(rgKey.m_iByteSizeM, (byte*)bnOut.m_pValue, &iOut, rgBase64)) {
        fprintf(g_logFile, "rsaXmlEncryptandEncodeChallenge: can't base64 encode challenge\n");
        return NULL;
    }

    return strdup(rgBase64);
}

 
#define MAXPRINCIPALS 25
#define BIGSIGNEDSIZE 256

const char* szMsgChallenge1= "<SignedChallenges count='%d'>";
const char* szMsgChallenge2= "\n<SignedChallenge>";
const char* szMsgChallenge3= "\n</SignedChallenge>";
const char* szMsgChallenge4= "\n</SignedChallenges>\n";


char* rsaXmlEncodeChallenges(bool fEncrypt, int iNumKeys, RSAKey** rgKeys, 
                                    byte* puChallenge, int sizeChallenge) 
{
    int     i;
    char*   rgszSignedChallenges[MAXPRINCIPALS];
    byte    rguCurrentChallenge[BIGSIGNEDSIZE];
    int     n= 0;
    char    szMsgHdr[64];
    int     iSC1;
    int     iSC2= strlen(szMsgChallenge2);
    int     iSC3= strlen(szMsgChallenge3);
    int     iSC4= strlen(szMsgChallenge4);

    memset(rguCurrentChallenge, 0, BIGSIGNEDSIZE);
    memcpy(rguCurrentChallenge, puChallenge, sizeChallenge);

    sprintf(szMsgHdr, szMsgChallenge1, iNumKeys);
    iSC1= strlen(szMsgHdr);
    
    for(i=0; i< iNumKeys; i++) {
        rgszSignedChallenges[i]= rsaXmlEncodeChallenge(fEncrypt,
                *rgKeys[i], rguCurrentChallenge, sizeChallenge);
        if(rgszSignedChallenges[i]==NULL) {
            fprintf(g_logFile, "Bad signed challenge %d\n", i);
            return NULL;
        }
        n+= strlen(rgszSignedChallenges[i]);
        if(i<(iNumKeys-1)) {
            if(!bumpChallenge(sizeChallenge, rguCurrentChallenge)) {
                fprintf(g_logFile, "Can't bump challenge %d\n", i);
                return NULL;
            }
        }
    }

    // concatinate and return
    n+= iSC1+iSC4+iNumKeys*(iSC2+iSC3);
    char*   szReturn= (char*) malloc(n+1);
    char*   p= szReturn;
    int     iLeft= n+1;

    if(szReturn!=NULL) {

        if(!safeTransfer(&p, &iLeft, szMsgHdr))
            return NULL;

        for(i=0; i< iNumKeys; i++) {
            if(!safeTransfer(&p, &iLeft, szMsgChallenge2))
                return NULL;
            if(!safeTransfer(&p, &iLeft, rgszSignedChallenges[i]))
                return NULL;
            if(!safeTransfer(&p, &iLeft, szMsgChallenge3))
                return NULL;
            // free(rgszSignedChallenges[i]);
        }
        if(!safeTransfer(&p, &iLeft, szMsgChallenge4))
            return NULL;
        *p= 0;
    }
    
#ifdef CRYPTOTEST
    fprintf(g_logFile, "Signed challenges: %s\n", szReturn);
#endif
    return szReturn;
}


// ------------------------------------------------------------------------


