//
//  File: cryptUtility.cpp
//
//  Description: cryptoUtility
//
//  Copyright (c) 2011, Intel Corporation. All rights reserved.
//  Incorporates contributions  (c) John Manferdelli.  All rights reserved.
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
#include "jlmcrypto.h"
#include "jlmUtility.h"
#include "cryptUtility.h"
#include "algs.h"
#include "keys.h"
#include "tinyxml.h"
#include "sha256.h"
#ifdef NOAESNI
#include "aes.h"
#else
#include "aesni.h"
#endif
#include "bignum.h"
#include "fileHash.h"
#include "mpFunctions.h"
#include "modesandpadding.h"
#include "rsaHelper.h"
#include "cryptSupport.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <time.h>


#define NOACTION                   0
#define GENKEY                     1
#define SIGN                       2
#define CANONICAL                  3
#define VERIFY                     4
#define RSATEST                    5
#define MAKEPOLICYFILE             6
#define ENCRYPTFILE                7
#define DECRYPTFILE                8
#define TIMEREPORT                 9
#define GCMTEST                   10
#define HEXQUOTETEST              11
#define SIGNHEXMODULUS            12
#define HASHFILE                  13
#define MAKEPOLICYKEYFILE         14
#define MAKESERVICEHASHFILE       15
#define VERIFYQUOTE               16

#define MAXREQUESTSIZE          2048
#define MAXADDEDSIZE              64
#define MAXREQUESTSIZEWITHPAD   (MAXREQUESTSIZE+MAXADDEDSIZE)


// --------------------------------------------------------------------- 


bool sameBigNum(int size, bnum& bnA, const char* szBase64A)  
//size in # bytes
{
    int iOutLen= 512;
    bnum bnB(64);

    if(!fromBase64(strlen(szBase64A), szBase64A, &iOutLen, (u8*)bnB.m_pValue)) {
        fprintf(g_logFile, "sameBigNum: Cant base64 decode A\n");
        return false;
    }
    
    if(mpCompare(bnA, bnB)!=s_isEqualTo) {
        fprintf(g_logFile, "%d bytes output\n", iOutLen);
        fprintf(g_logFile, "A: "); printNum(bnA); printf("\n");
        fprintf(g_logFile, "B: "); printNum(bnB); printf("\n");
        return false;
        }
    return true;
}


#define MAXTRY 20


bool GenRSAKey(int size, const char*szOutFile)
{
    TiXmlDocument   doc;
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;
    TiXmlNode*      pNode2;
    extern char*    szRSAKeyProto;
    int             iOutLen= 1024;
    char            szBase64KeyP[1024];
    char            szBase64KeyQ[1024];
    char            szBase64KeyM[1024];
    char            szBase64KeyE[1024];
    char            szBase64KeyD[1024];
    bnum            bnP(32);
    bnum            bnQ(32);
    bnum            bnM(64);
    bnum            bnPhi(64);
    bnum            bnE(64);
    bnum            bnD(64);
    bnum            bnG(64);
    int             iTry= 0;
    bool            fGotKey;

    fprintf(g_logFile, "RSAKeyGen %d bits, psize(bytes): %d, msize(bytes): %d\n", 
            size, size/16, size/8);
    // Set E
    bnE.m_pValue[0]= (1ULL<<16)+1ULL;

    while(iTry++<MAXTRY) {
        fGotKey= mpRSAGen(size, bnE, bnP, bnQ, bnM, bnD, bnPhi);
        if(fGotKey)
            break;
    }
    if(!fGotKey) {
        fprintf(g_logFile, "Cant generate key\n");
        return false;
    }

    fprintf(g_logFile, "P: "); printNum(bnP); printf("\n");
    fprintf(g_logFile, "Q: "); printNum(bnQ); printf("\n");
    PrintBytes("P:", (u8*)bnP.m_pValue, size/16);
    PrintBytes("Q:", (u8*)bnQ.m_pValue, size/16);
    PrintBytes("M:", (u8*)bnM.m_pValue, size/8);
    PrintBytes("E:", (u8*)bnE.m_pValue, size/8);
    PrintBytes("D:", (u8*)bnD.m_pValue, size/8);

    iOutLen= 1024;
    if(!toBase64(size/16, (u8*)bnP.m_pValue, &iOutLen, szBase64KeyP)) {
        fprintf(g_logFile, "Cant base64 encode P\n");
        return false;
    }
    iOutLen= 1024;
    if(!toBase64(size/16, (u8*)bnQ.m_pValue, &iOutLen, szBase64KeyQ)) {
        fprintf(g_logFile, "Cant base64 encode Q\n");
        return false;
    }
    iOutLen= 1024;
    if(!toBase64(size/8, (u8*)bnM.m_pValue, &iOutLen, szBase64KeyM)) {
        fprintf(g_logFile, "Cant base64 encode M\n");
        return false;
    }
    iOutLen= 1024;
    if(!toBase64(size/8, (u8*)bnE.m_pValue, &iOutLen, szBase64KeyE)) {
        fprintf(g_logFile, "Cant base64 encode E\n");
        return false;
    }
    iOutLen= 1024;
    if(!toBase64(size/8, (u8*)bnD.m_pValue, &iOutLen, szBase64KeyD)) {
        fprintf(g_logFile, "Cant base64 encode D\n");
        return false;
    }

    fprintf(g_logFile, "\nEncoded size: %d\n", (int)strlen(szBase64KeyM));
    if(sameBigNum(size/16, bnP, szBase64KeyP)) {
        fprintf(g_logFile, "P key matches\n");
    }
    else {
        fprintf(g_logFile, "P key fails\n");
        return false;
    }
    if(sameBigNum(size/16, bnQ, szBase64KeyQ)) {
        fprintf(g_logFile, "Q key matches\n");
    }
    else {
        fprintf(g_logFile, "Q key fails\n");
        return false;
    }
    if(sameBigNum(size/8, bnM, szBase64KeyM)) {
        fprintf(g_logFile, "M key matches\n");
    }
    else {
        fprintf(g_logFile, "M key fails\n");
        return false;
    }
    if(sameBigNum(size/8, bnE, szBase64KeyE)) {
        fprintf(g_logFile, "E key matches\n");
    }
    else {
        fprintf(g_logFile, "E key fails\n");
        return false;
    }
    if(sameBigNum(size/8, bnD, szBase64KeyD)) {
        fprintf(g_logFile, "D key matches\n");
    }
    else {
        fprintf(g_logFile, "D key fails\n");
        return false;
    }

    fprintf(g_logFile, "Writing: %s\n", szOutFile);

    if(!doc.Parse(szRSAKeyProto)) {
        fprintf(g_logFile, "Cant parse RSAKeyProto\n%s\n",szRSAKeyProto);
        return false;
    }

    TiXmlElement* pRootElement= doc.RootElement();
    TiXmlText* pNewText;
    if(strcmp(pRootElement->Value(),"ds:KeyInfo")==0) {
        pRootElement->SetAttribute("KeyName","KEYNAME");
    }
    
    pNode= pRootElement->FirstChild();
    while(pNode) {
        if(pNode->Type()==TiXmlNode::TINYXML_ELEMENT) {
            if(strcmp(((TiXmlElement*)pNode)->Value(),"KeyType")==0) {
                    pNewText= new TiXmlText("RSAKeyType");
                    pNode->InsertEndChild(*pNewText);
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"ds:KeyValue")==0) {
                pNode1= pNode->FirstChild();
                while(pNode1) {
                    if(strcmp(((TiXmlElement*)pNode1)->Value(),"ds:RSAKeyValue")==0) {
                        ((TiXmlElement*) pNode1)->SetAttribute ("size", size);
                        pNode2= pNode1->FirstChild();
                        while(pNode2) {
                            if(strcmp(((TiXmlElement*)pNode2)->Value(),"ds:P")==0) {
                                TiXmlText* pNewTextP= new TiXmlText(szBase64KeyP);
                                pNode2->InsertEndChild(*pNewTextP);
                            }
                            if(strcmp(((TiXmlElement*)pNode2)->Value(),"ds:Q")==0) {
                                TiXmlText* pNewTextQ= new TiXmlText(szBase64KeyQ);
                                pNode2->InsertEndChild(*pNewTextQ);
                            }
                            if(strcmp(((TiXmlElement*)pNode2)->Value(),"ds:M")==0) {
                                TiXmlText* pNewTextM= new TiXmlText(szBase64KeyM);
                                pNode2->InsertEndChild(*pNewTextM);
                            }
                            if(strcmp(((TiXmlElement*)pNode2)->Value(),"ds:E")==0) {
                                TiXmlText* pNewTextE= new TiXmlText(szBase64KeyE);
                                pNode2->InsertEndChild(*pNewTextE);
                            }
                            if(strcmp(((TiXmlElement*)pNode2)->Value(),"ds:D")==0) {
                                TiXmlText* pNewTextD= new TiXmlText(szBase64KeyD);
                                pNode2->InsertEndChild(*pNewTextD);
                            }
                            pNode2= pNode2->NextSibling();
                        }
                    }
                    pNode1= pNode1->NextSibling();
                }
            }
        }
        pNode= pNode->NextSibling();
    }

    TiXmlPrinter printer;
    doc.Accept(&printer);
    const char* szDoc= printer.CStr();
    fprintf(g_logFile, "Writing: %s\n", szOutFile);
    FILE* out= fopen(szOutFile,"w");
    fprintf(out, "%s", szDoc);
    fclose(out);
    return true;
}


bool  Canonical(const char* szInFile, const char* szOutFile)
{
    TiXmlDocument   doc;

    if(!doc.LoadFile(szInFile)) {
        fprintf(g_logFile, "Cant load file %s\n", szInFile);
        return NULL;
    }
    TiXmlElement*   pRootElement= doc.RootElement();

    char* szDoc= canonicalize((TiXmlNode*) pRootElement);
    FILE* out= fopen(szOutFile,"w");
    fprintf(out, "%s", szDoc);
    fclose(out);
    return true;
}


bool GenAESKey(int size, const char* szOutFile)
{
    TiXmlDocument   doc;
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;
    u8              buf[32];
    extern char*    szAESKeyProto;
    int             iOutLen= 128;
    char            szBase64Key[256];

    /*
     *  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" KeyName=''>
     *  <ds:KeyValue>
     *  <ds:AESKeyValue size=''>
     */

    if(!getCryptoRandom(size, buf)) {
        fprintf(g_logFile, "Cant generate AES key\n");
        return false;
    }

    PrintBytes("AES key:", buf, size/8);

    if(!toBase64(size/8, buf, &iOutLen, szBase64Key)) {
        fprintf(g_logFile, "Cant base64 encode AES key\n");
        return false;
    }

#ifdef TEST2
    fprintf(g_logFile, "Base64 encoded: %s\n",szBase64Key);
#endif

    doc.Parse(szAESKeyProto);

    TiXmlElement* pRootElement= doc.RootElement();
    TiXmlText* pNewText;
    if(strcmp(pRootElement->Value(),"ds:KeyInfo")==0) {
        pRootElement->SetAttribute("KeyName","KEYNAME");
    }
    pNode= pRootElement->FirstChild();
    while(pNode) {
        if(pNode->Type()==TiXmlNode::TINYXML_ELEMENT) {
            if(strcmp(((TiXmlElement*)pNode)->Value(),"KeyType")==0) {
                    pNewText= new TiXmlText("AESKeyType");
                    pNode->InsertEndChild(*pNewText);
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"ds:KeyValue")==0) {
                pNode1= pNode->FirstChild();
                while(pNode1) {
                    if(strcmp(((TiXmlElement*)pNode1)->Value(),"ds:AESKeyValue")==0) {
                        ((TiXmlElement*) pNode1)->SetAttribute ("size", size);
                        pNewText= new TiXmlText(szBase64Key);
                        pNode1->InsertEndChild(*pNewText);
                    }
                    pNode1= pNode1->NextSibling();
                }
            }
        }
        pNode= pNode->NextSibling();
    }

    TiXmlPrinter printer;
    doc.Accept(&printer);
    const char* szDoc= printer.CStr();
    FILE* out= fopen(szOutFile,"w");
    fprintf(out, "%s", szDoc);
    fclose(out);
    // fprintf(g_logFile, "%s", szDoc);
    return true;
}


bool GenKey(const char* szKeyType, const char* szOutFile)
{
    bool fRet;

    if(szKeyType==NULL)
        return false;
    if(strcmp(szKeyType, "AES128")==0) {
        return GenAESKey(128, szOutFile);
    }
    if(strcmp(szKeyType, "AES256")==0) {
        return GenAESKey(256, szOutFile);
    }
    // just for test
    if(strcmp(szKeyType, "RSA128")==0) {
        return GenRSAKey(128, szOutFile);
    }
    if(strcmp(szKeyType, "RSA256")==0) {
        return GenRSAKey(256, szOutFile);
    }
    if(strcmp(szKeyType, "RSA512")==0) {
        return GenRSAKey(512, szOutFile);
    }
    if(strcmp(szKeyType, "RSA1024")==0) {
        fprintf(g_logFile, "calling GenRSAKey\n");
        fRet= GenRSAKey(1024, szOutFile);
        fprintf(g_logFile, "returned from GenRSAKey\n");
        return fRet;
    }
    if(strcmp(szKeyType, "RSA2048")==0) {
        return GenRSAKey(2048, szOutFile);
    }
    return false;
}


// --------------------------------------------------------------------


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


// --------------------------------------------------------------------


const char*   szSigHeader= 
          "<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id='uniqueid'>\n";
const char*   szSigValueBegin= "    <ds:SignatureValue>    \n";
const char*   szSigValueEnd= "\n    </ds:SignatureValue>\n";
const char*   szSigTrailer= "</ds:Signature>\n";


bool Sign(const char* szKeyFile, const char* szAlgorithm, const char* szInFile, const char* szOutFile)
{
    int         iAlgIndex;
    Sha256      oHash;
    u8          rgHashValue[SHA256_DIGESTSIZE_BYTES];
    u8          rgToSign[512];
    char        rgBase64Sig[1024];
    int         iSigSize= 512;
    TiXmlNode*  pNode= NULL;
    TiXmlNode*  pNode1= NULL;
    char*       szToHash= NULL;
    RSAKey*     pRSAKey= NULL;
    char*       szKeyInfo= NULL;
    int         iWrite= -1;
    bool        fRet= true;

    if(szKeyFile==NULL) {
        fprintf(g_logFile, "No Key file\n");
        return false;
    }
    if(szAlgorithm==NULL) {
        fprintf(g_logFile, "No Algorithm specifier\n");
        return false;
    }
    if(szInFile==NULL) {
        fprintf(g_logFile, "No Input file\n");
        return false;
    }
    if(szOutFile==NULL) {
        fprintf(g_logFile, "No Output file\n");
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "Sign(%s, %s, %s, %s)\n", szKeyFile, szAlgorithm, szInFile, szOutFile);
#endif

    try {

        pRSAKey= (RSAKey*)ReadKeyfromFile(szKeyFile);
        if(pRSAKey==NULL)
            throw "Cant parse or open Keyfile\n";
        if(((KeyInfo*)pRSAKey)->m_ukeyType!=RSAKEYTYPE) {
            delete (KeyInfo*) pRSAKey;
            pRSAKey= NULL;
            throw "Wrong key type for signing\n";
        }
        // Signature algorithm
        iAlgIndex= algorithmIndexFromShortName(szAlgorithm);
        if(iAlgIndex<0)
            throw "Unsupported signing algorithm\n";

        fprintf(g_logFile, "\n");
        pRSAKey->printMe();
        fprintf(g_logFile, "\n");

        // read input file
        TiXmlDocument toSignDoc;
        if(!toSignDoc.LoadFile(szInFile))
            throw "Can't open file for signing\n";
        
        pNode= Search(toSignDoc.RootElement(),"ds:SignedInfo");
        if(pNode==NULL) {
            fprintf(g_logFile, "Can't find SignedInfo\n");
            return false;
        }

        // Canonicalize
        szToHash= canonicalize(pNode);
        if(szToHash==NULL) 
            throw "Can't canonicalize\n";

        pNode1= Search(toSignDoc.RootElement(), "ds:SignatureMethod");
        if(pNode1==NULL)
            throw "Can't find SignatureMethod\n";

        char* szAlgLongName= longAlgNameFromIndex(iAlgIndex);
        if(szAlgLongName==NULL)
            throw "Can't find Algorithm index\n";
        ((TiXmlElement*) pNode1)->SetAttribute("Algorithm", szAlgLongName);
    
        // hash it
        if(hashAlgfromIndex(iAlgIndex)==SHA256HASH) {
            oHash.Init();
            oHash.Update((byte*) szToHash , strlen(szToHash));
            oHash.Final();
            oHash.GetDigest(rgHashValue);
        }
        else 
            throw "Unsupported hash algorithm\n";

        // pad it
        if(padAlgfromIndex(iAlgIndex)==PKCSPAD) {
            memset(rgToSign, 0, 512);
            if(!emsapkcspad(SHA256HASH, rgHashValue, pRSAKey->m_iByteSizeM, rgToSign)) 
                throw "Padding failure in Signing\n";
        }
        else
            throw  "Unsupported hash algorithm\n";

        bnum    bnMsg(pRSAKey->m_iByteSizeM/2);
        bnum    bnOut(pRSAKey->m_iByteSizeM/2);

        iSigSize= pRSAKey->m_iByteSizeM;
        // encrypt with private key
        if( (pkAlgfromIndex(iAlgIndex)==RSA2048 && pRSAKey->m_iByteSizeM == 256) ||
            (pkAlgfromIndex(iAlgIndex)==RSA1024 && pRSAKey->m_iByteSizeM == 128)) {

            memset(bnMsg.m_pValue, 0, pRSAKey->m_iByteSizeM);
            memset(bnOut.m_pValue, 0, pRSAKey->m_iByteSizeM);

            revmemcpy((byte*)bnMsg.m_pValue, rgToSign, iSigSize);
            if(iSigSize>pRSAKey->m_iByteSizeM) 
                throw "Signing key block too small\n";
            if((pRSAKey->m_iByteSizeM==0) || (pRSAKey->m_iByteSizeD==0))
                throw "Signing keys not available\n";

            if(!mpRSAENC(bnMsg, *(pRSAKey->m_pbnD), *(pRSAKey->m_pbnM), bnOut))
                throw "Can't sign with private key\n";
        }
        else 
            throw "Unsupported public key algorithm\n";

#ifdef TEST
        fprintf(g_logFile, "Signed output\n");
        fprintf(g_logFile, "\tM: "); printNum(*(pRSAKey->m_pbnM)); printf("\n");
        fprintf(g_logFile, "\tD: "); printNum(*(pRSAKey->m_pbnD)); printf("\n");
        fprintf(g_logFile, "\tIn: "); printNum(bnMsg); printf("\n");
        fprintf(g_logFile, "\tOut: "); printNum(bnOut); printf("\n");

        bnum  bnCheck(pRSAKey->m_iByteSizeM/2);
        mpRSAENC(bnOut, *(pRSAKey->m_pbnE), *(pRSAKey->m_pbnM), bnCheck);
        fprintf(g_logFile, "\tCheck: "); printNum(bnCheck); printf("\n"); printf("\n");

#endif

        // write XML to output file
        iWrite= open(szOutFile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if(iWrite<0)
            throw "Can't open file to write signed version\n";

        // Header
        if(write(iWrite, szSigHeader, strlen(szSigHeader))<0) {
            fprintf(g_logFile, "bad write\n");
            return false;
        }

        // write SignedInfo
        if(write(iWrite, szToHash, strlen(szToHash))<0) {
            fprintf(g_logFile, "bad write\n");
            return false;
        }

        // write signature value
        if(write(iWrite, szSigValueBegin, strlen(szSigValueBegin))<0) {
            fprintf(g_logFile, "bad write\n");
            return false;
        }
        int iOutLen= 1024;
        if(!toBase64(pRSAKey->m_iByteSizeM, (u8*)bnOut.m_pValue, &iOutLen, rgBase64Sig))
            throw "Cant base64 encode signature value\n";
        if(write(iWrite, rgBase64Sig, strlen(rgBase64Sig))<0) {
            fprintf(g_logFile, "bad write\n");
            return false;
        }
        if(write(iWrite, szSigValueEnd, strlen(szSigValueEnd))<0) {
            fprintf(g_logFile, "bad write\n");
            return false;
        }

        // public key info of signer
        szKeyInfo= pRSAKey->SerializePublictoString();
        if(szKeyInfo==NULL)
            throw "Can't Serialize key class\n";
    
        if(write(iWrite, szKeyInfo, strlen(szKeyInfo))<0) {
            fprintf(g_logFile, "bad write\n");
            return false;
        }
        if(write(iWrite, szSigTrailer, strlen(szSigTrailer))<0) {
            fprintf(g_logFile, "bad write\n");
            return false;
        }

#ifdef TEST
        fprintf(g_logFile, "Signature written\n");
#endif
    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "Sign error: %s\n", szError);
    }

    // clean up
    if(iWrite>0)
        close(iWrite);
    if(szKeyInfo!=NULL) {
        free(szKeyInfo);
        szKeyInfo= NULL;
    }
    if(szToHash!=NULL) {
        free(szToHash);
        szToHash= NULL;
    }
    if(pRSAKey!=NULL) {
        delete pRSAKey;
        pRSAKey= NULL;
    }
    return fRet;
}


bool Verify(const char* szKeyFile, const char* szInFile)
{
    int         iAlgIndex= 0;  // Fix: there's only one now
    Sha256      oHash;
    u8          rgHashValue[SHA256_DIGESTSIZE_BYTES];
    u8          rguDecoded[1024];
    u8          rguOut[1024];
    TiXmlNode*  pNode= NULL;
    TiXmlNode*  pNode1= NULL;
    TiXmlNode*  pNode2= NULL;

    RSAKey*     pRSAKey= NULL;
    char*       szToHash= NULL;
    bool        fRet= true;

#ifdef TEST
    fprintf(g_logFile, "Verify(%s, %s)\n", szKeyFile, szInFile);
#endif
    if(szKeyFile==NULL) {
        fprintf(g_logFile, "No Key file\n");
        return false;
    }
    if(szInFile==NULL) {
        fprintf(g_logFile, "No Input file\n");
        return false;
    }

    try {

        // read input file
        TiXmlDocument signedDoc;
        if(!signedDoc.LoadFile(szInFile)) 
            throw "Can't read signed file\n";

        // SignedInfo
        pNode= Search(signedDoc.RootElement(), "ds:SignedInfo");
        if(pNode==NULL)
            throw "Can't find SignedInfo\n";
        szToHash= canonicalize(pNode);
        if(szToHash==NULL)
            throw "Can't canonicalize\n";

        // hash it
        if(hashAlgfromIndex(iAlgIndex)==SHA256HASH) {
            oHash.Init();
            oHash.Update((byte*) szToHash, strlen(szToHash));
            oHash.Final();
            oHash.GetDigest(rgHashValue);
        }
        else
            throw "Unsupported hash algorithm\n";

#ifdef TEST
            fprintf(g_logFile, "Canonical SignedInfo\n%s\n", szToHash);
            fprintf(g_logFile, "Size hashed: %d\n", (int)strlen(szToHash));
            PrintBytes("Hash", rgHashValue, SHA256_DIGESTSIZE_BYTES);
            fprintf(g_logFile, "\tBytes hashed: %d\n", (int)strlen(szToHash));
#endif

        // key from keyfile
        pRSAKey= (RSAKey*)ReadKeyfromFile(szKeyFile);
        if(pRSAKey==NULL) {
            delete (KeyInfo*) pRSAKey;
            throw "Cant parse or open Keyfile\n";
        }
        if(((KeyInfo*)pRSAKey)->m_ukeyType!=RSAKEYTYPE) {
            delete (KeyInfo*) pRSAKey;
            throw "Wrong key type for signing\n";
        }

        fprintf(g_logFile, "\n");
        pRSAKey->printMe();
        fprintf(g_logFile, "\n");

        // signature method
        pNode1= Search(signedDoc.RootElement(), "ds:SignatureMethod");
        if(pNode1==NULL)
            throw "Can't find SignatureMethod\n";

        const char* szAlgorithm= ((((TiXmlElement*) pNode1)->Attribute("Algorithm")));
        if(szAlgorithm==NULL)
            throw "Cant get signing algorithm\n";
        iAlgIndex= algorithmIndexFromLongName(szAlgorithm);
        if(iAlgIndex<0)
            throw "Unsupported signing algorithm\n";

        // get SignatureValue
        pNode1= Search(signedDoc.RootElement(), "ds:SignatureValue");
        if(pNode1==NULL)
            throw "Can't find SignatureValue\n";
        pNode2= pNode1->FirstChild();
        if(pNode2==NULL)
            throw "Can't find SignatureValue element\n";

        const char* szBase64Sign= pNode2->Value();
        if(szBase64Sign==NULL)
            throw "Can't get base64 signature value\n";
        int iOutLen= 1024;
        if(!fromBase64(strlen(szBase64Sign), szBase64Sign, &iOutLen, rguDecoded))
            throw "Cant base64 decode signature block\n";

        // decrypt with public key
        bnum    bnMsg(pRSAKey->m_iByteSizeM/2);
        bnum    bnOut(pRSAKey->m_iByteSizeM/2);
    
        if( (pkAlgfromIndex(iAlgIndex)==RSA2048 && pRSAKey->m_iByteSizeM == 256) ||
            (pkAlgfromIndex(iAlgIndex)==RSA1024 && pRSAKey->m_iByteSizeM == 128)) {
            if((pRSAKey->m_iByteSizeM==0) || (pRSAKey->m_iByteSizeE==0))
                throw "Verifying keys not available\n";
            memset(bnMsg.m_pValue, 0, pRSAKey->m_iByteSizeM);
            memset(bnOut.m_pValue, 0, pRSAKey->m_iByteSizeM);
            memcpy(bnMsg.m_pValue, rguDecoded, iOutLen);
    
            if(!mpRSAENC(bnMsg, *(pRSAKey->m_pbnE), *(pRSAKey->m_pbnM), bnOut))
                throw "Can't sign with private key\n";
            revmemcpy(rguOut, (byte*)bnOut.m_pValue, pRSAKey->m_iByteSizeM);
        }
        else 
            throw "Unsupported public key algorithm\n";

#ifdef TEST
        fprintf(g_logFile, "Decrypted signature\n");
        fprintf(g_logFile, "\tM: "); printNum(*(pRSAKey->m_pbnM)); printf("\n");
        fprintf(g_logFile, "\tE: "); printNum(*(pRSAKey->m_pbnE)); printf("\n");
        fprintf(g_logFile, "\tIn: "); printNum(bnMsg); printf("\n");
        fprintf(g_logFile, "\tOut: "); printNum(bnOut); printf("\n"); printf("\n");
#endif

        // pick alg from index
        if(padAlgfromIndex(iAlgIndex)==PKCSPAD) 
            fRet= emsapkcsverify(SHA256HASH, rgHashValue, pRSAKey->m_iByteSizeM, rguOut);
        else 
            throw "(char*) Unsupported public key algorithm\n";
    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "Verify error: %s\n", szError);
    }

    // clean up
    if(szToHash!=NULL) {
        free(szToHash);
        szToHash= NULL;
    }
    if(pRSAKey!=NULL) {
        delete pRSAKey;
        pRSAKey= NULL;
    }

    return fRet;
}


bool RSATest(const char* szKeyFile, const char* szInFile)
{
    if(szKeyFile==NULL) {
        fprintf(g_logFile, "No Key file\n");
        return false;
    }
    if(szInFile==NULL) {
        fprintf(g_logFile, "No Input file\n");
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "RSATest(%s, %s\n", szKeyFile, szInFile);
#endif

    KeyInfo* pKey= ReadKeyfromFile(szKeyFile);
    if(pKey==NULL) {
        fprintf(g_logFile, "Cant parse or open Keyfile %s\n", szKeyFile);
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "Key file retreived\n");
#endif

    if(pKey->m_ukeyType!=RSAKEYTYPE) {
        fprintf(g_logFile, "Wrong key type for test\n");
        return false;
    }
    RSAKey*     pRSAKey= (RSAKey*) pKey;

    fprintf(g_logFile, "\n");
    pRSAKey->printMe();
    fprintf(g_logFile, "\n");

    // read input file
    TiXmlDocument theDoc;

    if(!theDoc.LoadFile(szInFile)) {
        fprintf(g_logFile, "Can't read doc file\n");
        return false;
    }

    TiXmlNode* pNode= Search(theDoc.RootElement(), "ds:SignedInfo");
    if(pNode==NULL) {
        fprintf(g_logFile, "Can't find SignedInfo\n");
        return false;
    }
    char* szToHash= canonicalize(pNode);
    if(szToHash==NULL) {
        fprintf(g_logFile, "Can't canonicalize\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "\nCanonical SignedInfo\n%s\n", szToHash);
#endif

    // hash it
    Sha256      oHash;
    u8          rgHashValue[SHA256_DIGESTSIZE_BYTES];
    u8          rguoriginalMsg[1024];
    u8          rguencryptedMsg[1024];
    u8          rgudecryptedMsg[1024];

    oHash.Init();
    oHash.Update((byte*) szToHash, strlen(szToHash));
    oHash.Final();
    oHash.GetDigest(rgHashValue);
#ifdef TEST
    PrintBytes("Hash", rgHashValue, SHA256_DIGESTSIZE_BYTES);
#endif

    memset(rguoriginalMsg, 0, 1024);
    memset(rguencryptedMsg, 0, 1024);
    memset(rgudecryptedMsg, 0, 1024);

    int iEncSize= SHA256_DIGESTSIZE_BYTES;
    if(iEncSize>pRSAKey->m_iByteSizeM)
        iEncSize= pRSAKey->m_iByteSizeM-1;
    memcpy(rguoriginalMsg, rgHashValue, iEncSize);

    free(szToHash);
    szToHash= NULL;

    // encrypt/decrypt with public key
    if((pRSAKey->m_iByteSizeM==0) || (pRSAKey->m_iByteSizeD==0) || (pRSAKey->m_iByteSizeE==0)) {
        fprintf(g_logFile, "Keys not available\n");
        return false;
    }

    bnum    bnIn(pRSAKey->m_iByteSizeM/2);
    bnum    bnEncrypted(pRSAKey->m_iByteSizeM/2);
    bnum    bnDecrypted(pRSAKey->m_iByteSizeM/2);
    memcpy(bnIn.m_pValue, rguoriginalMsg, iEncSize);

    bnum R(256);

    fprintf(g_logFile, "About to fermat test\n");
    if(mpTestFermatCondition(bnIn, *(pRSAKey->m_pbnP))) {
        fprintf(g_logFile, "P passes Fermat test\n");
        fprintf(g_logFile, "P: "); printNum(*(pRSAKey->m_pbnP)); printf("\n");
        fprintf(g_logFile, "bnIn: "); printNum(bnIn);printf("\n");
        }
    else
        fprintf(g_logFile, "P fails Fermat test\n");
    if(mpTestFermatCondition(bnIn, *(pRSAKey->m_pbnQ))) 
        fprintf(g_logFile, "Q passes Fermat test\n");
    else
        fprintf(g_logFile, "Q fails Fermat test\n");

    if(!mpRSAENC(bnIn, *(pRSAKey->m_pbnE), *(pRSAKey->m_pbnM), bnEncrypted)) {
        fprintf(g_logFile, "Can't encrypt\n");
        return false;
    }
    if(!mpRSAENC(bnEncrypted, *(pRSAKey->m_pbnD), *(pRSAKey->m_pbnM), bnDecrypted)) {
        fprintf(g_logFile, "Can't encrypt\n");
        return false;
    }
    
    fprintf(g_logFile, "\n\nOriginal:"); printNum(bnIn); printf("\n");
    fprintf(g_logFile, "\nEncrypted:"); printNum(bnEncrypted); printf("\n");
    fprintf(g_logFile, "\nDecrypted:"); printNum(bnDecrypted); printf("\n");
    memcpy(rguencryptedMsg, bnEncrypted.m_pValue, pRSAKey->m_iByteSizeM);
    memcpy(rgudecryptedMsg, bnDecrypted.m_pValue, pRSAKey->m_iByteSizeM);
    fprintf(g_logFile, "\n\nAs Bytes\n");
    PrintBytes("Original ", rguoriginalMsg, pRSAKey->m_iByteSizeM);
    PrintBytes("Encrypted", rguencryptedMsg, pRSAKey->m_iByteSizeM);
    PrintBytes("Decrypted", rgudecryptedMsg, pRSAKey->m_iByteSizeM);

    int     i;
    bool    fMatch= true;

    for(i=0;i<pRSAKey->m_iByteSizeM;i++) {
        if(rguoriginalMsg[i]!=rgudecryptedMsg[i]) {
            fMatch= false;
            break;
        }
    }

    if(fMatch)
        fprintf(g_logFile, "Test succeeds\n");
    else
        fprintf(g_logFile, "Test fails\n");

    return true;
}


#define BUFSIZE       2048
#define BYTESPERLINE    16


bool MakePolicyFile(const char* szKeyFile, const char* szOutFile, const char* szProgramName)
{
    int         i, n;
    int         iToRead;
    char        rgszBuf[BUFSIZE];
    struct stat statBlock;

    if(szKeyFile==NULL || szOutFile==NULL) {
        fprintf(g_logFile, "Error: null file name\n");
        return false;
    }
    int iRead = open(szKeyFile, O_RDONLY);
    if(iRead<0) {
        fprintf(g_logFile, "Can't open input file %s\n", szKeyFile);
        return false;
    }
    FILE* out= fopen(szOutFile,"w");
    if(out==NULL) {
        fprintf(g_logFile, "Can't open output file %s\n", szOutFile);
        return false;
    }

    if(stat(szKeyFile, &statBlock)<0) {
        fprintf(g_logFile, "Can't stat input file\n");
        return false;
    }

    int iFileSize= statBlock.st_size;
    int iLeft= iFileSize;

    fprintf(out, "\n// Policy Cert\n\n");
    fprintf(out, "char    g_szXmlPolicyCert[%d]= {", iFileSize+1);  // we'll add a 0 byte
    while(iLeft>0) {
        if(iLeft<BUFSIZE)
            iToRead= iLeft;
        else
            iToRead= BUFSIZE;

        n= read(iRead, rgszBuf, iToRead);
        if(n<0) {
            fprintf(g_logFile, "Unexpected file end\n");
            break;
        }
        iLeft-= n;
        for(i=0; i<n; i++) {
            if((i%BYTESPERLINE)==0)
                fprintf(out, "\n    ");
            fprintf(out, "0x%02x,", rgszBuf[i]);
            
        }
    }
    fprintf(out, "0x00\n};\n\n");
    fprintf(out, "\nint    g_szpolicykeySize= %d;\n\n", iFileSize+1);
    fprintf(out, "\nint    g_szProgramNameSize= %d;\n", (int) strlen(szProgramName)+1);
    fprintf(out, "\nchar*  g_szProgramName= \"%s\";\n\n", szProgramName);
    
    fclose(out);
    close(iRead);

    return true;
}


bool VerifyQuote(const char* szQuoteFile, const char* szCertFile)
{
    Quote           oQuote;
    PrincipalCert   oCert;
    char* szCertString= readandstoreString(szCertFile);
    char* szQuoteString= readandstoreString(szQuoteFile);

    // get and parse Quote
    if(szQuoteFile==NULL) {
        fprintf(g_logFile, "Can't cant read quote file %s\n", szQuoteFile);
        return false;
    }
    if(!oQuote.init(szQuoteString)) {
        fprintf(g_logFile, "Can't parse quote\n");
        return false;
    }

    // get and parse Cert
    if(szCertFile==NULL) {
        fprintf(g_logFile, "Can't cant read cert file %s\n", szCertFile);
        return false;
    }
    if(!oCert.init(szCertString)) {
        fprintf(g_logFile, "Can't parse cert\n");
        return false;
    }

    // decode request
    char* szAlg= oQuote.getQuoteAlgorithm();
    char* szQuotedInfo= oQuote.getCanonicalQuoteInfo();
    char* szQuoteValue= oQuote.getQuoteValue();
    char* sznonce= oQuote.getnonceValue();
    char* szDigest= oQuote.getcodeDigest();

    if(!oCert.parsePrincipalCertElements()) {
        fprintf(g_logFile, "Can't get principal cert elements\n");
        return false;
    }


    // check quote
    RSAKey* pAIKKey= (RSAKey*) oCert.getSubjectKeyInfo();
    if(pAIKKey==NULL) {
        fprintf(g_logFile, "Cant get quote keyfromkeyInfo\n");
        return false;
    }

    fprintf(g_logFile, "Quote:\n%s\n\n", szQuoteString);
    fprintf(g_logFile, "Quoted value:\n%s\n\n", szQuotedInfo);
    fprintf(g_logFile, "AIKCert:\n%s\n\n", szCertString);
    
    return verifyXMLQuote(szAlg, szQuotedInfo, sznonce,
                          szDigest, pAIKKey, szQuoteValue);
}


#ifdef GCMENABLED
bool AES128GCMEncryptFile(int filesize, int iRead, int iWrite, u8* enckey)
{
    gcm     oGCM;
    int     ivSize= AES128BYTEBLOCKSIZE-sizeof(u32);
    int     fileLeft= filesize;
    u8      iv[AES128BYTEBLOCKSIZE];
    u8      rgBufIn[4*AES128BYTEBLOCKSIZE];
    u8      rgBufOut[4*AES128BYTEBLOCKSIZE];

#ifdef TEST
    fprintf(g_logFile, "GCMEncrypt\n");
#endif
    // init iv
    if(!getCryptoRandom(ivSize*NBITSINBYTE, iv)) {
        fprintf(g_logFile, "Cant generate iv\n");
        return false;
    }
    memset(&iv[ivSize],0, sizeof(u32));

    // init 
    if(!oGCM.initEnc(AES128, ivSize, iv, AES128BYTEKEYSIZE, enckey, filesize, 0, AES128BYTEKEYSIZE))
        return false;

    // get and send first cipher block
    oGCM.firstCipherBlockOut(rgBufOut);
    write(iWrite, rgBufOut, AES128BYTEBLOCKSIZE);

    // read, encrypt, and write bytes
    while(fileLeft>AES128BYTEBLOCKSIZE) {
        if(read(iRead, rgBufIn, AES128BYTEBLOCKSIZE)<0) {
            fprintf(g_logFile, "bad read\n");
            return false;
        }
        oGCM.nextPlainBlockIn(rgBufIn, rgBufOut);
        write(iWrite, rgBufOut, AES128BYTEBLOCKSIZE);
        fileLeft-= AES128BYTEBLOCKSIZE;
    }

    // final block
    if(read(iRead, rgBufIn, fileLeft)<0) {
        fprintf(g_logFile, "bad read\n");
        return false;
    }
    int n= oGCM.lastPlainBlockIn(fileLeft, rgBufIn, rgBufOut);
    if(n<0)
        return false;

    // write final encrypted block
    write(iWrite, rgBufOut, n);

    // write tag
    oGCM.getTag(oGCM.m_iBlockSize, rgBufOut);
    write(iWrite, rgBufOut, oGCM.m_iBlockSize);

    return true;
}


bool AES128GCMDecryptFile(int filesize, int iRead, int iWrite, u8* enckey)
{
    gcm     oGCM;
    int     fileLeft= filesize;
    u8      rgBufIn[4*AES128BYTEBLOCKSIZE];
    u8      rgBufOut[4*AES128BYTEBLOCKSIZE];

#ifdef TEST
    fprintf(g_logFile, "GCMDecrypt\n");
#endif
    // init 
    if(!oGCM.initDec(AES128, AES128BYTEKEYSIZE, enckey, filesize, 0, AES128BYTEKEYSIZE))
        return false;

    // get and send first cipher block
    if(read(iRead, rgBufIn, AES128BYTEBLOCKSIZE)<0) {
        fprintf(g_logFile, "bad read\n");
        return false;
    }
    oGCM.firstCipherBlockIn(rgBufIn);
    fileLeft-= AES128BYTEBLOCKSIZE;

    // read, decrypt, and write bytes
    while(fileLeft>2*AES128BYTEBLOCKSIZE) {
        if(read(iRead, rgBufIn, AES128BYTEBLOCKSIZE)<0) {
            fprintf(g_logFile, "bad read\n");
            return false;
        }
        oGCM.nextCipherBlockIn(rgBufIn, rgBufOut);
        write(iWrite, rgBufOut, AES128BYTEBLOCKSIZE);
        fileLeft-= AES128BYTEBLOCKSIZE;
    }

    // final block
    read(iRead, rgBufIn, fileLeft);
    int n= oGCM.lastCipherBlockIn(fileLeft, rgBufIn, rgBufOut);
    if(n<0)
        return false;

    // write final decrypted bytes
    if(write(iWrite, rgBufOut, n)<0) {
        fprintf(g_logFile, "bad write\n");
        return false;
    }

    return oGCM.validateTag();
}
#endif


bool AES128CBCHMACSHA256SYMPADEncryptFile (int filesize, int iRead, int iWrite, 
                        u8* enckey, u8* intkey)
{
    cbc     oCBC;
    int     fileLeft= filesize;
    u8      iv[AES128BYTEBLOCKSIZE];
    u8      rgBufIn[4*AES128BYTEBLOCKSIZE];
    u8      rgBufOut[4*AES128BYTEBLOCKSIZE];

#ifdef TEST
    fprintf(g_logFile, "CBCEncrypt\n");
#endif
    // init iv
    if(!getCryptoRandom(AES128BYTEBLOCKSIZE*NBITSINBYTE, iv)) {
        fprintf(g_logFile, "Cant generate iv\n");
        return false;
    }

    // init 
    if(!oCBC.initEnc(AES128, SYMPAD, HMACSHA256, AES128BYTEKEYSIZE, enckey, AES128BYTEKEYSIZE, 
                     intkey, filesize, AES128BYTEBLOCKSIZE, iv))
        return false;

    // get and send first cipher block
    oCBC.firstCipherBlockOut(rgBufOut);
    if(write(iWrite, rgBufOut, AES128BYTEBLOCKSIZE)<0) {
        fprintf(g_logFile, "AES128CBCHMACSHA256SYMPADEncryptFile: bad write\n");
        return false;
    }

    // read, encrypt, and copy bytes
    while(fileLeft>AES128BYTEBLOCKSIZE) {
        if(read(iRead, rgBufIn, AES128BYTEBLOCKSIZE)<0) {
            fprintf(g_logFile, "bad read\n");
            return false;
        }
        oCBC.nextPlainBlockIn(rgBufIn, rgBufOut);
        if(write(iWrite, rgBufOut, AES128BYTEBLOCKSIZE)<0) {
            fprintf(g_logFile, "bad write\n");
            return false;
        }
        fileLeft-= AES128BYTEBLOCKSIZE;
    }

    // final block
    if(read(iRead, rgBufIn, fileLeft)<0) {
        fprintf(g_logFile, "AES128CBCHMACSHA256SYMPADEncryptFile: bad read\n");
        return false;
    }
    int n= oCBC.lastPlainBlockIn(fileLeft, rgBufIn, rgBufOut);
    if(n<0)
        return false;

    // write final encrypted blocks and HMAC
    if(write(iWrite, rgBufOut, n)<0) {
        fprintf(g_logFile, "bad write\n");
        return false;
    }

    return true;
}


bool AES128CBCHMACSHA256SYMPADDecryptFile (int filesize, int iRead, int iWrite,
                         u8* enckey, u8* intkey)
{
    cbc     oCBC;
    int     fileLeft= filesize;
    u8      rgBufIn[4*AES128BYTEBLOCKSIZE];
    u8      rgBufOut[4*AES128BYTEBLOCKSIZE];

#ifdef TEST
    fprintf(g_logFile, "CBCDecrypt\n");
#endif
    // init 
    if(!oCBC.initDec(AES128, SYMPAD, HMACSHA256, AES128BYTEKEYSIZE, enckey, AES128BYTEKEYSIZE, 
                     intkey, filesize))
        return false;

    // get and send first cipher block
    if(read(iRead, rgBufIn, AES128BYTEBLOCKSIZE)<0) {
            fprintf(g_logFile, "bad read\n");
            return false;
        }
    oCBC.firstCipherBlockIn(rgBufIn);
    fileLeft-= AES128BYTEBLOCKSIZE;

    // read, decrypt, and write bytes
    while(fileLeft>3*AES128BYTEBLOCKSIZE) {
        if(read(iRead, rgBufIn, AES128BYTEBLOCKSIZE)<0) {
            fprintf(g_logFile, "bad read\n");
            return false;
        }
        oCBC.nextCipherBlockIn(rgBufIn, rgBufOut);
        if(write(iWrite, rgBufOut, AES128BYTEBLOCKSIZE)<0) {
            fprintf(g_logFile, "bad write\n");
            return false;
        }
        fileLeft-= AES128BYTEBLOCKSIZE;
    }

    // final blocks
    if(read(iRead, rgBufIn, fileLeft)<0) {
            fprintf(g_logFile, "bad read\n");
            return false;
        }
    int n= oCBC.lastCipherBlockIn(fileLeft, rgBufIn, rgBufOut);
    if(n<0)
        return false;

    // write final decrypted bytes
    if(write(iWrite, rgBufOut, n)<0) {
        fprintf(g_logFile, "bad write\n");
        return false;
    }

    return oCBC.validateMac();
}


bool Encrypt(u32 op, const char* szKeyFile, const char* szInFile, const char* szOutFile, u32 mode=CBCMODE, 
             u32 alg=AES128, u32 pad=SYMPAD, u32 mac=HMACSHA256)
{
    u8          rguEncKey[BIGSYMKEYSIZE];
    u8          rguIntKey[BIGSYMKEYSIZE];

    if(op==ENCRYPTFILE)
        fprintf(g_logFile, "Encrypt (%s, %s, %s)\n", szKeyFile, szInFile, szOutFile);
    else
        fprintf(g_logFile, "Decrypt (%s, %s, %s)\n", szKeyFile, szInFile, szOutFile);
    if(mode==CBCMODE)
        fprintf(g_logFile, "CBC Mode\n");
    else
        fprintf(g_logFile, "GCM Mode\n");

    memset(rguEncKey , 0, BIGSYMKEYSIZE);
    memset(rguIntKey , 0, BIGSYMKEYSIZE);

    // Get File size
    struct stat statBlock;
    if(stat(szInFile, &statBlock)<0) {
        fprintf(g_logFile, "Can't stat input file\n");
        return false;
    }
    int fileSize= statBlock.st_size;

    int iRead= open(szInFile, O_RDONLY);
    if(iRead<0) {
        fprintf(g_logFile, "Can't open read file\n");
        return false;
    }

    int iWrite= open(szOutFile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if(iWrite<0) {
        fprintf(g_logFile, "Can't open write file\n");
        return false;
    }

    int iKey= open(szKeyFile, O_RDONLY);
    if(iKey<0) {
        fprintf(g_logFile, "Can't open Key file\n");
        return false;
    }
    if(read(iKey, rguEncKey, AES128BYTEKEYSIZE)<0) {
            fprintf(g_logFile, "bad read\n");
            return false;
        }
    if(mode==CBCMODE)
        if(read(iKey, rguIntKey, AES128BYTEKEYSIZE)<0) {
            fprintf(g_logFile, "bad read\n");
            return false;
        }
    close(iKey);

    bool fRet= false;

    if(op==ENCRYPTFILE && alg==AES128 && mode==CBCMODE && mac==HMACSHA256 && pad==SYMPAD)
        fRet= AES128CBCHMACSHA256SYMPADEncryptFile(fileSize, iRead, iWrite, 
                     rguEncKey, rguIntKey);
    else if(op==DECRYPTFILE && alg==AES128 && mode==CBCMODE && mac==HMACSHA256 && pad==SYMPAD)
        fRet= AES128CBCHMACSHA256SYMPADDecryptFile(fileSize, iRead, iWrite, 
                     rguEncKey, rguIntKey);
#ifdef GCMENABLED
    else if(op==ENCRYPTFILE && alg==AES128 && mode==GCMMODE)
        fRet= AES128GCMEncryptFile(fileSize, iRead, iWrite, rguEncKey);
    else if(op==DECRYPTFILE && alg==AES128 && mode==GCMMODE)
        fRet= AES128GCMDecryptFile(fileSize, iRead, iWrite, rguEncKey);
#endif
    else
        fRet= false;
    
    close(iRead);
    close(iWrite);
    memset(rguEncKey , 0, BIGSYMKEYSIZE);
    memset(rguIntKey , 0, BIGSYMKEYSIZE);

#ifdef TEST
    if(fRet)
        fprintf(g_logFile, "Encrypt/Decrypt returns true\n");
    else
        fprintf(g_logFile, "Encrypt/Decrypt returns false\n");
#endif
    return fRet;
}


void  GetTime()
{
    time_t      timer;

    time(&timer);
    // 1997-07-16T19:20:30.45+01:00
    struct tm*  pgmtime= gmtime((const time_t*)&timer);
    char* szTime= gmTimetoUTCstring(pgmtime);

    fprintf(g_logFile,  "The current date/time is: %s\n", szTime);

    return;
}


#ifdef GCMENABLED
void printGCM(gcm& oGCM)
{
    fprintf(g_logFile, "BlockSize: %d, NumAuthBytes: %d, NumPlainBytes: %d, NumCipherBytes: %d, TagSize: %d\n",
            oGCM.m_iBlockSize, oGCM.m_iNumAuthBytes, oGCM.m_iNumPlainBytes, 
            oGCM.m_iNumCipherBytes, oGCM.m_iTagSize);
    PrintBytes("H", oGCM.m_rguH, oGCM.m_iBlockSize);
    PrintBytes("Y", oGCM.m_rgLastY, oGCM.m_iBlockSize);
    PrintBytes("X", oGCM.m_rgLastX, oGCM.m_iBlockSize);
    PrintBytes("First", oGCM.m_rguFirstBlock, oGCM.m_iBlockSize);
    PrintBytes("Last", oGCM.m_rguLastBlocks, 2*oGCM.m_iBlockSize);
    PrintBytes("Tag", oGCM.m_rgTag, oGCM.m_iBlockSize);
    PrintBytes("sentTag", oGCM.m_rgsentTag, oGCM.m_iBlockSize);
    fprintf(g_logFile, "\n");
}


void TestGcm()
{
    int     n;
    gcm     oGCM;
    int     ivSize= AES128BYTEBLOCKSIZE-sizeof(u32);
    int     filesize= AES128BYTEBLOCKSIZE;
    int     fileLeft= filesize;
    u8      iv[AES128BYTEBLOCKSIZE];
    u8      enckey[AES128BYTEBLOCKSIZE];
    u8      rgBufOut[4*AES128BYTEBLOCKSIZE];
    u8      rgplainText[10*AES128BYTEBLOCKSIZE];
    u8      rgcipherText[10*AES128BYTEBLOCKSIZE];
    u8      rgEy0[AES128BYTEBLOCKSIZE];

#ifdef TEST
    fprintf(g_logFile, "TestGcm\n");
#endif

#if 0
    extern bool multmodF(u8* rguC, u8* rguA, u8* rguB, int n);
    u8  rgA[16];
    u8  rgB[16];
    u8  rgC[16];

    memset(rgA, 0, 16);
    memset(rgB, 0, 16);
    memset(rgC, 0, 16);
    rgA[15]= 0x01;
    rgB[0]= 0xff;
    multmodF(rgC, rgA, rgB, 16);

    fprintf(g_logFile, "\nmodmultF\n");
    PrintBytes("\tA", rgA, 16);
    PrintBytes("\tB", rgB, 16);
    PrintBytes("\tC", rgC, 16);
    fprintf(g_logFile, "\n");
    return;
#endif

    memset(iv, 0, AES128BYTEBLOCKSIZE);
    memset(enckey, 0, AES128BYTEBLOCKSIZE);
    memset(rgplainText, 0, 10*AES128BYTEBLOCKSIZE);
    memset(rgcipherText, 0, 10*AES128BYTEBLOCKSIZE);
    memset(rgEy0, 0, AES128BYTEBLOCKSIZE);

    PrintBytes("Key", enckey, AES128BYTEBLOCKSIZE);
    fprintf(g_logFile, "\n");

    // init 
    if(!oGCM.initEnc(AES128, ivSize, iv, AES128BYTEKEYSIZE, enckey, filesize, 0, AES128BYTEKEYSIZE)) {
        fprintf(g_logFile, "init failed\n");
        return;
    }

    PrintBytes("Y0", oGCM.m_rgLastY, oGCM.m_iBlockSize);
    oGCM.m_oAES.Encrypt(oGCM.m_rgLastY, rgEy0);
    PrintBytes("EY0", rgEy0, oGCM.m_iBlockSize);
    fprintf(g_logFile, "\n");
    
    printGCM(oGCM);

    // get and send first cipher block
    oGCM.firstCipherBlockOut(rgBufOut);
    PrintBytes("first cipher block", rgBufOut, oGCM.m_iBlockSize);

    u8*  puIn= rgplainText;
    u8*  puOut= rgcipherText;

    // read, encrypt, and write bytes
    while(fileLeft>oGCM.m_iBlockSize) {
        oGCM.nextPlainBlockIn(puIn, puOut);
        PrintBytes("Cipher in", puIn, oGCM.m_iBlockSize);
        PrintBytes("Cipher out", puOut, oGCM.m_iBlockSize);
        puIn+= oGCM.m_iBlockSize;
        puOut+= oGCM.m_iBlockSize;
        fileLeft-= oGCM.m_iBlockSize;
    }

    // final block
    fprintf(g_logFile, "Final block\n");
    n= oGCM.lastPlainBlockIn(fileLeft, puIn, puOut);
    if(n<0) {
        fprintf(g_logFile, "lastPlainBlock failed\n");
        return;
    }
    PrintBytes("last cipher block", puOut, oGCM.m_iBlockSize);

    oGCM.getTag(oGCM.m_iBlockSize, rgBufOut);
    PrintBytes("Final Tag        ", rgBufOut, oGCM.m_iBlockSize);

    return;
}
#endif


inline byte fromHextoVal(char a, char b)
{
    byte x= 0;

    if(a>='a' && a<='f')
        x= (((byte) (a-'a')+10)&0xf)<<4;
    else if(a>='A' && a<='F')
        x= (((byte) (a-'A')+10)&0xf)<<4;
    else
        x= (((byte) (a-'0'))&0xf)<<4;

    if(b>='a' && b<='f')
        x|= ((byte) (b-'a')+10)&0xf;
    else if(b>='A' && b<='F')
        x|= ((byte) (b-'A')+10)&0xf;
    else
        x|= ((byte) (b-'0'))&0xf;

    return x;
}


int MyConvertFromHexString(const char* szIn, int iSizeOut, byte* rgbBuf)
{
    char    a, b;
    int     j= 0;

    while(*szIn!=0) {
        if(*szIn=='\n' || *szIn==' ') {
            szIn++;
            continue;
        }
        a= *(szIn++);
        b= *(szIn++);
        if(a==0 || b==0)
            break;
        rgbBuf[j++]= fromHextoVal(a, b);
    }
    return j;
}

const char* g_aikTemplate=
"<ds:SignedInfo>\n" \
"    <ds:CanonicalizationMethod Algorithm=\"http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#\" />\n" \
"    <ds:SignatureMethod Algorithm=\"http://www.manferdelli.com/2011/Xml/algorithms/rsa1024-sha256-pkcspad#\" />\n" \
"    <Certificate Id='%s' version='1'>\n" \
"        <SerialNumber>20110930001</SerialNumber>\n" \
"        <PrincipalType>Hardware</PrincipalType>\n" \
"        <IssuerName>manferdelli.com</IssuerName>\n" \
"        <IssuerID>manferdelli.com</IssuerID>\n" \
"        <ValidityPeriod>\n" \
"            <NotBefore>2011-01-01Z00:00.00</NotBefore>\n" \
"            <NotAfter>2021-01-01Z00:00.00</NotAfter>\n" \
"        </ValidityPeriod>\n" \
"        <SubjectName>//www.manferdelli.com/Keys/attest/0001</SubjectName>\n" \
"        <SubjectKey>\n" \
"<ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" " \
"            KeyName=\"%s\">\n" \
"    <KeyType>RSAKeyType</KeyType>\n" \
"    <ds:KeyValue>\n" \
"        <ds:RSAKeyValue size='%d'>\n" \
"            <ds:M>%s</ds:M>\n" \
"            <ds:E>AAAAAAABAAE=</ds:E>\n" \
"        </ds:RSAKeyValue>\n" \
"    </ds:KeyValue>\n" \
"</ds:KeyInfo>\n" \
"        </SubjectKey>\n" \
"        <SubjectKeyID>%s</SubjectKeyID>\n" \
"        <RevocationPolicy>Local-check-only</RevocationPolicy>\n" \
"    </Certificate>\n" \
"</ds:SignedInfo>\n" ;

// Cert ID
// Key name
// M
// Subject Key id


bool SignHexModulus(const char* szKeyFile, const char* szInFile, const char* szOutFile)
{
    Sha256      oHash;
    u8          rgHashValue[SHA256_DIGESTSIZE_BYTES];
    u8          rgToSign[512];
    int         iSigSize= 512;
    char        rgBase64Sig[1024];
    int         size= 512;
    char        rgBase64[512];
    TiXmlNode*  pNode= NULL;
    char*       szToHash= NULL;
    RSAKey*     pRSAKey= NULL;
    char*       szKeyInfo= NULL;
    int         iWrite= -1;
    bool        fRet= true;
    char        szSignedInfo[4096];

    fprintf(g_logFile, "SignHexModulus(%s, %s, %s)\n", szKeyFile, szInFile, szOutFile);
    char* modString= readandstoreString(szInFile); 
    if(modString==NULL) {
        fprintf(g_logFile, "Couldn't open modulusfile %s\n", szInFile);
        return false;
    }

    byte    modHex[1024];
    int     modSize=  MyConvertFromHexString(modString, 1024, modHex);
    PrintBytes("\nmodulus\n", modHex, modSize);

    if(szKeyFile==NULL) {
        fprintf(g_logFile, "No Key file\n");
        return false;
    }
    if(szInFile==NULL) {
        fprintf(g_logFile, "No Input file\n");
        return false;
    }
    if(szOutFile==NULL) {
        fprintf(g_logFile, "No Output file\n");
        return false;
    }

    try {

        pRSAKey= (RSAKey*)ReadKeyfromFile(szKeyFile);
        if(pRSAKey==NULL)
            throw "Cant open Keyfile\n";
        if(((KeyInfo*)pRSAKey)->m_ukeyType!=RSAKEYTYPE) {
            delete (KeyInfo*) pRSAKey;
            pRSAKey= NULL;
            throw "Wrong key type for signing\n";
        }

        fprintf(g_logFile, "\n");
        pRSAKey->printMe();
        fprintf(g_logFile, "\n");

        // construct key XML from modulus
        const char*   szCertid= "www.manferdelli.com/certs/000122";
        const char*   szKeyName= "Gauss-AIK-CERT";
        byte    revmodHex[1024];

        revmemcpy(revmodHex, modHex, modSize);
        if(!toBase64(modSize, revmodHex, &size, rgBase64))
            throw "Cant base64 encode modulus value\n";

        const char*   szKeyId= "/Gauss/AIK";
        int     iNumBits= ((size*6)/1024)*1024;

        sprintf(szSignedInfo, g_aikTemplate, szCertid, 
                szKeyName, iNumBits, rgBase64, szKeyId);

        // read input file
        TiXmlDocument toSignDoc;
        if(!toSignDoc.Parse(szSignedInfo))
            throw "Can't parse signed info\n";
        
        pNode= Search(toSignDoc.RootElement(), "ds:SignedInfo");
        if(pNode==NULL) {
            fprintf(g_logFile, "Can't find SignedInfo\n");
            return false;
        }

        // Canonicalize
        szToHash= canonicalize(pNode);
        if(szToHash==NULL) 
            throw "Can't canonicalize\n";

        // hash it
        oHash.Init();
        oHash.Update((byte*) szToHash , strlen(szToHash));
        oHash.Final();
        oHash.GetDigest(rgHashValue);

        // pad it
        memset(rgToSign, 0, 512);
        if(!emsapkcspad(SHA256HASH, rgHashValue, pRSAKey->m_iByteSizeM, rgToSign)) 
            throw "Padding failure in Signing\n";

        bnum    bnMsg(pRSAKey->m_iByteSizeM/2);
        bnum    bnOut(pRSAKey->m_iByteSizeM/2);

        iSigSize= pRSAKey->m_iByteSizeM;

        // encrypt with private key
        memset(bnMsg.m_pValue, 0, pRSAKey->m_iByteSizeM);
        memset(bnOut.m_pValue, 0, pRSAKey->m_iByteSizeM);

        revmemcpy((byte*)bnMsg.m_pValue, rgToSign, iSigSize);
#ifdef TEST
        PrintBytes("from pad: ", rgToSign, iSigSize);
        PrintBytes("As signed: ", (byte*)bnMsg.m_pValue, iSigSize);
#endif
        if(iSigSize>pRSAKey->m_iByteSizeM) 
            throw "Signing key block too small\n";
        if((pRSAKey->m_iByteSizeM==0) || (pRSAKey->m_iByteSizeD==0))
            throw "Signing keys not available\n";

        if(!mpRSAENC(bnMsg, *(pRSAKey->m_pbnD), *(pRSAKey->m_pbnM), bnOut))
            throw "Can't sign with private key\n";

#ifdef TEST
        fprintf(g_logFile, "Signed output\n");
        fprintf(g_logFile, "\tM: "); printNum(*(pRSAKey->m_pbnM)); printf("\n");
        fprintf(g_logFile, "\tD: "); printNum(*(pRSAKey->m_pbnD)); printf("\n");
        fprintf(g_logFile, "\tIn: "); printNum(bnMsg); printf("\n");
        fprintf(g_logFile, "\tOut: "); printNum(bnOut); printf("\n");

        bnum  bnCheck(pRSAKey->m_iByteSizeM/2);
        mpRSAENC(bnOut, *(pRSAKey->m_pbnE), *(pRSAKey->m_pbnM), bnCheck);
        fprintf(g_logFile, "\tCheck: "); printNum(bnCheck); printf("\n"); printf("\n");
#endif

        // write XML to output file
        iWrite= open(szOutFile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if(iWrite<0)
            throw "Can't open file to write signed version\n";

        // Header
        if(write(iWrite, szSigHeader, strlen(szSigHeader))<0) {
            fprintf(g_logFile, "bad write\n");
            return false;
        }

        // write SignedInfo
        if(write(iWrite, szToHash, strlen(szToHash))<0) {
            fprintf(g_logFile, "bad write\n");
            return false;
        }

        // write signature value
        if(write(iWrite, szSigValueBegin, strlen(szSigValueBegin))<0) {
            fprintf(g_logFile, "bad write\n");
            return false;
        }
        int iOutLen= 1024;
        if(!toBase64(pRSAKey->m_iByteSizeM, (u8*)bnOut.m_pValue, &iOutLen, rgBase64Sig))
            throw "Cant base64 encode signature value\n";
        if(write(iWrite, rgBase64Sig, strlen(rgBase64Sig))<0) {
            fprintf(g_logFile, "bad write\n");
            return false;
        }
        if(write(iWrite, szSigValueEnd, strlen(szSigValueEnd))<0) {
            fprintf(g_logFile, "bad write\n");
            return false;
        }

        // public key info of signer
        szKeyInfo= pRSAKey->SerializePublictoString();
        if(szKeyInfo==NULL)
            throw "Can't Serialize key class\n";
    
        if(write(iWrite, szKeyInfo, strlen(szKeyInfo))<0) {
            fprintf(g_logFile, "bad write\n");
            return false;
        }
        if(write(iWrite, szSigTrailer, strlen(szSigTrailer))<0) {
            fprintf(g_logFile, "bad write\n");
            return false;
        }

#ifdef TEST
        fprintf(g_logFile, "Signature written\n");
#endif
    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "Sign error: %s\n", szError);
    }

    // clean up
    if(iWrite>0)
        close(iWrite);
    if(szKeyInfo!=NULL) {
        free(szKeyInfo);
        szKeyInfo= NULL;
    }
    if(szToHash!=NULL) {
        free(szToHash);
        szToHash= NULL;
    }
    if(pRSAKey!=NULL) {
        delete pRSAKey;
        pRSAKey= NULL;
    }

    return fRet;
}



bool QuoteTest(const char* szKeyFile, const char* szInFile)
{
    char* keyString= readandstoreString(szKeyFile); 
    char* quoteString= readandstoreString(szInFile); 
    if(keyString==NULL) {
        fprintf(g_logFile, "Couldn't open key file %s\n", szKeyFile);
        return false;
    }
    if(quoteString==NULL) {
        fprintf(g_logFile, "Couldn't open quote file %s\n", szInFile);
        return false;
    }
    byte    keyHex[1024];
    int     keySize=   MyConvertFromHexString(keyString, 1024, keyHex);
    byte    quoteHex[1024];
    int     quoteSize=  MyConvertFromHexString(quoteString, 1024, quoteHex);

    fprintf(g_logFile, "keySize: %d, quoteSize: %d\n\n", keySize, quoteSize);
    PrintBytes("\nkey", keyHex, keySize);
    PrintBytes("\nquote", quoteHex, quoteSize);

    bnum  bnM(32);
    bnum  bnC(32);
    bnum  bnE(2);
    bnum  bnR(32);

    int     i;
    byte*   pB; 
    byte*   pA;

    pA= (byte*) bnM.m_pValue;
    for(i=(keySize-1); i>=0; i--) {
        pB= &keyHex[i];
        *(pA++)= *pB;
    }

    pA= (byte*) bnC.m_pValue;
    for(i=(quoteSize-1); i>=0; i--) {
        pB= &quoteHex[i];
        *(pA++)= *pB;
    }
    bnE.m_pValue[0]= 0x10001ULL;

    fprintf(g_logFile, "\nM: "); printNum(bnM); printf("\n");
    fprintf(g_logFile, "\nC: "); printNum(bnC); printf("\n");
    fprintf(g_logFile, "\nE: "); printNum(bnE); printf("\n");

    if(!mpRSAENC(bnC, bnE, bnM, bnR))
        fprintf(g_logFile, "\nENC fails\n");
    else
        fprintf(g_logFile, "\nENC succeeds\n");
    fprintf(g_logFile, "\nR: "); printNum(bnR); printf("\n");

    fprintf(g_logFile, "\n\nreturning\n");
    
    return true;
}


// --------------------------------------------------------------------- 


//  -GenKey keytype outputfile
//  -Sign keyfile algname inputfile outputfile
//  -Verify keyfile inputfile 
//  -Hash algname inputfile outputfile
//  -Canonical inputfile outputfile 
//  -RSATest keyfile SignedInfoFile
//  -PolicyCert certFile outputfile
//  -Encrypt   keyFile inputfile outputfile
//  -Decrypt   keyFile inputfile outputfile
//  -HashquoteTest keyFile inputFile


int main(int an, char** av)
{
    const char*   szInFile= NULL;
    const char*   szKeyType= NULL;
    const char*   szOutFile= NULL;
    const char*   szAlgorithm= NULL;
    const char*   szKeyFile= NULL;
    const char*   szProgramName=  "Program no name";
    int     iAction= NOACTION;
    int     mode= CBCMODE;
    bool    fRet;
    int     i;

    for(i=0; i<an; i++) {
        if(strcmp(av[i], "-help")==0) {
            fprintf(g_logFile, "\nUsage: cryptUtility -GenKey keytype outputfile\n");
            fprintf(g_logFile, "       cryptUtility -Sign keyfile rsa1024-sha256-pkcspad inputfile outputfile\n");
            fprintf(g_logFile, "       cryptUtility -Verify keyfile inputfile\n");
            fprintf(g_logFile, "       cryptUtility -Canonical inputfile outputfile\n");
            fprintf(g_logFile, "       cryptUtility -RSATest keyfile\n");
            fprintf(g_logFile, "       cryptUtility -PolicyCert certfile outputfile programname\n");
            fprintf(g_logFile, "       cryptUtility -Encrypt keyfile inputfile outputfile\n");
            fprintf(g_logFile, "       cryptUtility -Decrypt keyfile inputfile outputfile\n");
            fprintf(g_logFile, "       cryptUtility -Time \n");
#ifdef GCMENABLED
            fprintf(g_logFile, "       cryptUtility -TestGCM \n");
#endif
            fprintf(g_logFile, "       cryptUtility -HexquoteTest\n");
            fprintf(g_logFile, "       cryptUtility -SignHexModulus keyfile input-file output-file\n");
            fprintf(g_logFile, "       cryptUtility -HashFile input-file [alg]\n");
            fprintf(g_logFile, "       cryptUtility -makePolicyKeyFile input-file outputfile\n");
            fprintf(g_logFile, "       cryptUtility -makeServiceHashFile input-file outputfile\n");
            fprintf(g_logFile, "       cryptUtility -VerifyQuote xml-quote xml-aikcert\n");
            return 0;
        }
        if(strcmp(av[i], "-Canonical")==0) {
            if(an<(i+2)) {
                fprintf(g_logFile, "Too few arguments: input-file elementName\n");
                return 1;
            }
            szInFile= av[i+1];
            szOutFile= av[i+2];
            iAction= CANONICAL;
            break;
        }
        if(strcmp(av[i], "-GenKey")==0) {
            if(an<(i+3)) {
                fprintf(g_logFile, "Too few arguments: [AES128|RSA1024] output-file\n");
                return 1;
            }
            szKeyType= av[i+1];
            szOutFile= av[i+2];
            iAction= GENKEY;
            break;
        }
        if(strcmp(av[i], "-Sign")==0) {
            if(an<(i+4)) {
                fprintf(g_logFile, "Too few arguments: key-file rsa2048-sha256-pkcspad input-file output-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szAlgorithm= av[i+2];
            szInFile= av[i+3];
            szOutFile= av[i+4];
            iAction= SIGN;
            break;
        }
        if(strcmp(av[i], "-Verify")==0) {
            if(an<(i+2)) {
                fprintf(g_logFile, "Too few arguments: key-file input-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szInFile= av[i+2];
            iAction= VERIFY;
            break;
        }
        if(strcmp(av[i], "-RSATest")==0) {
            if(an<(i+2)) {
                fprintf(g_logFile, "Too few arguments: key-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szInFile= av[i+2];
            iAction= RSATEST;
            break;
        }
        if(strcmp(av[i], "-PolicyCert")==0) {
            if(an<(i+3)) {
                fprintf(g_logFile, "Too few arguments: cert-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szOutFile= av[i+2];
            szProgramName= av[i+3];
            iAction= MAKEPOLICYFILE;
            break;
        }
        if(strcmp(av[i], "-makePolicyKeyFile")==0) {
            if(an<(i+3)) {
                fprintf(g_logFile, "Too few arguments: key-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szOutFile= av[i+2];
            szProgramName= av[i+3];
            iAction= MAKEPOLICYKEYFILE;
            break;
        }
        if(strcmp(av[i], "-Encrypt")==0) {
            if(an<(i+3)) {
                fprintf(g_logFile, "Too few arguments: key-file input-file output-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szInFile= av[i+2];
            szOutFile= av[i+3];
            iAction= ENCRYPTFILE;
            if(an>(i+4) && strcmp(av[i+4],"gcm")==0)
                mode= CBCMODE;
            break;
        }
        if(strcmp(av[i], "-Decrypt")==0) {
            if(an<(i+3)) {
                fprintf(g_logFile, "Too few arguments: key-file input-file output-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szInFile= av[i+2];
            szOutFile= av[i+3];
            iAction= DECRYPTFILE;
            if(an>(i+4) && strcmp(av[i+4],"gcm")==0)
                mode= CBCMODE;
            break;
        }
        if(strcmp(av[i], "-Time")==0) {
            iAction= TIMEREPORT;
            break;
        }
#ifdef GCMENABLED
        if(strcmp(av[i], "-TestGCM")==0) {
            iAction= GCMTEST;
            break;
        }
#endif
        if(strcmp(av[i], "-HashFile")==0) {
            iAction= HASHFILE;
            szInFile= av[i+1];
            szAlgorithm= "SHA256";
            break;
        }
        if(strcmp(av[i], "-makeServiceHashFile")==0) {
            iAction= MAKESERVICEHASHFILE;
            szInFile= av[i+1];
            szOutFile= av[i+2];
            szAlgorithm= "SHA256";
            break;
        }
        if(strcmp(av[i], "-VerifyQuote")==0) {
            iAction= VERIFYQUOTE;
            szInFile= av[i+1];
            szKeyFile= av[i+2];
            break;
        }
        if(strcmp(av[i], "-HexquoteTest")==0) {
            if(an<(i+2)) {
                fprintf(g_logFile, "Too few arguments: key-file input-file output-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szInFile= av[i+2];
            iAction= HEXQUOTETEST;
            break;
        }
        if(strcmp(av[i], "-SignHexModulus")==0) {
            if(an<(i+3)) {
                fprintf(g_logFile, "Too few arguments: key-file input-file output-file\n");
                return 1;
            }
            szKeyFile= av[i+1];
            szInFile= av[i+2];
            szOutFile= av[i+3];
            iAction= SIGNHEXMODULUS;
            break;
        }

    }

    if(iAction==NOACTION) {
        fprintf(g_logFile, "Cant find option\n");
        return 1;
    }

    if(iAction==GENKEY) {
        initCryptoRand();
        initBigNum();
        fRet= GenKey(szKeyType, szOutFile);
        if(fRet)
            fprintf(g_logFile, "GenKey returning successfully\n");
        else
            fprintf(g_logFile, "GenKey returning unsuccessfully\n");
        closeCryptoRand();
    }

    if(iAction==VERIFY) {
        initCryptoRand();
        initBigNum();
        fRet= Verify(szKeyFile, szInFile);
        if(fRet)
            fprintf(g_logFile, "Signature verifies\n");
        else
            fprintf(g_logFile, "Signature fails\n");
        closeCryptoRand();
    }

    if(iAction==SIGN) {
        initCryptoRand();
        initBigNum();
        fRet= Sign(szKeyFile, szAlgorithm, szInFile, szOutFile);
        closeCryptoRand();
        if(fRet)
            fprintf(g_logFile, "Sign succeeded\n");
        else
            fprintf(g_logFile, "Sign failed\n");
    }

    if(iAction==MAKEPOLICYFILE) {
        MakePolicyFile(szKeyFile, szOutFile, szProgramName);
        fprintf(g_logFile, "MakePolicyFile complete\n");
    }

    if(iAction==CANONICAL) {
        Canonical(szInFile, szOutFile);
        fprintf(g_logFile, "Canonical complete\n");
    }

    if(iAction==RSATEST) {
        initCryptoRand();
        initBigNum();
        fRet= RSATest(szKeyFile, szInFile);
        closeCryptoRand();
    }

    if(iAction==ENCRYPTFILE) {
        initCryptoRand();
        initBigNum();
        fRet= Encrypt(ENCRYPTFILE, szKeyFile, szInFile, szOutFile, mode);
        closeCryptoRand();
    }

    if(iAction==DECRYPTFILE) {
        initCryptoRand();
        initBigNum();
        fRet= Encrypt(DECRYPTFILE, szKeyFile, szInFile, szOutFile, mode);
        closeCryptoRand();
    }

    if(iAction==TIMEREPORT) {
        GetTime();
    }

#ifdef GCMENABLED
    if(iAction==GCMTEST) {
        TestGcm();
    }
#endif

    if(iAction==HEXQUOTETEST) {
        initCryptoRand();
        initBigNum();
        fRet= QuoteTest(szKeyFile, szInFile);
        closeCryptoRand();
    }

    if(iAction==SIGNHEXMODULUS) {
        initCryptoRand();
        initBigNum();
        fRet= SignHexModulus(szKeyFile, szInFile, szOutFile);
        closeCryptoRand();
    }

    if(iAction==HASHFILE) {
        u32  uType= 0;
        int  size= SHA256DIGESTBYTESIZE;
        byte rgHash[SHA256DIGESTBYTESIZE];
        if(getfileHash(szInFile, &uType, &size, rgHash)) {
            fprintf(g_logFile, "cryptUtility: cant hash file\n");
            return 1;
        }
        fprintf(g_logFile, "Hash of file %s is: ", szInFile);
        PrintBytes("", rgHash, size);
    }
   
    if(iAction==MAKEPOLICYKEYFILE) {
        RSAKey* pKey= (RSAKey*)ReadKeyfromFile(szKeyFile);
        byte*   rgB= pKey->m_rgbM;

        if(pKey==NULL) {
            fprintf(g_logFile, "can't read key %s\n", szKeyFile);
            return 1;
        }

        // write output file
        FILE* out= fopen(szOutFile,"w");
        fprintf(out, "u32 tciodd_policykeyType= RSA1024;\n");
        fprintf(out, "int tciodd_sizepolicykey= 128;\n");
        fprintf(out, "byte tciodd_policykey[256] = {\n");
        for(i=0; i<128; i+=8) {
            fprintf(out, "    0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, \n",
                    rgB[i], rgB[i+1], rgB[i+2], rgB[i+3],
                    rgB[i+4], rgB[i+5], rgB[i+6], rgB[i+7]);
        }
        fprintf(out, "};\n");
        fclose(out);
        fprintf(g_logFile, "MakePolicyKeyFile complete\n");
    }

    if(iAction==MAKESERVICEHASHFILE ) {
        u32  uType= 0;
        int  size= SHA256DIGESTBYTESIZE;
        byte rgHash[SHA256DIGESTBYTESIZE];
        if(!getfileHash(szInFile, &uType, &size, rgHash)) {
            fprintf(g_logFile, "cryptUtility: cant hash file\n");
            return 1;
        }

        // write output file
        FILE* out= fopen(szOutFile,"w");
        fprintf(out, "u32 tciodd__fileHashtype= SHA256HASH;\n");
        fprintf(out, "#define SHA256HASHSIZE 32\n");
        fprintf(out, "byte tciodd_serviceHash[SHA256HASHSIZE]= {\n");
        for(i=0; i<SHA256DIGESTBYTESIZE; i+=8) {
            fprintf(out, "    0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, 0x%02x, \n",
                    rgHash[i], rgHash[i+1], rgHash[i+2], rgHash[i+3],
                    rgHash[i+4], rgHash[i+5], rgHash[i+6], rgHash[i+7]);
        }
        fprintf(out, "};\n");
        fclose(out);

        fprintf(g_logFile, "Hash of file %s is: ", szInFile);
        PrintBytes("", rgHash, size);
    }

    if(iAction==VERIFYQUOTE) {
        if(VerifyQuote(szInFile, szKeyFile)) {
            fprintf(g_logFile, "Quote verifies\n");
        }
        else {
            fprintf(g_logFile, "Quote does NOT verifies\n");
        }
        return 0;
    }

    closeLog();
    return 0;
}


// -------------------------------------------------------------------------



