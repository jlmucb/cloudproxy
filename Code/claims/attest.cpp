//
//  File: attest.cpp
//      John Manferdelli
//
//  Description:  Attestation 
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


#include "jlmTypes.h"
#include "logging.h"
#include "jlmUtility.h"
#include "cryptoHelper.h"
#include "modesandpadding.h"
#include "sha1.h"
#include "sha256.h"
#include "algs.h"
#include "attest.h"
#include "cert.h"
#include "tao.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "attest.h"	// remove later
#include "hashprep.h"
#include "tinyxml.h"

#include <time.h>
#include <string.h>


#define MAXREQUESTSIZE 16384
#ifndef SMALLNONCESIZE
#define SMALLNONCESIZE 32
#endif


// ------------------------------------------------------------------------


const char*   g_szNonceTemplate= "<nonce> %s </nonce>\n";
const char*   g_szQuoteTemplate= 
"<Quote format='xml'>\n"\
"    %s\n" \
"    <CodeDigest alg='%s'> %s </CodeDigest>\n" \
"%s\n" \
"        <QuoteValue>\n" \
"%s\n" \
"        </QuoteValue>\n" \
"%s\n" \
"</Quote>\n";


// ------------------------------------------------------------------


/*
 * 
 *  Typical attest for public key
 * 
 *  <Attest format="xml" type="CP1">
 *    <ds:CanonicalizationMethod Algorithm="http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#" />
 *     <ds:AttestMethod Algorithm="Attest-Sha256FileHash-RSA1024" />
 *     <CodeDigest alg="SHA256">al5/jR40s+ytNsx3SRTLE67oZV5bSl+EXNRrqI2gxKY=</CodeDigest>
 *     <AttestdValue> xxxxxx  </AttestdValue>
 *     <AttestValue>a0NDX3hYz3OzGvGQlOp87X0oJV00zGQ5YOaeVfW/3NqCdml4EzAWcjZNaFf26kry84hZ9ULOpB7+RiBplhKg9kSinMEPfljkvvJJ+vuVdbmEzu45oi3FAh4PMGyp5hoWTxpnhr+MSBhvs08BUcWe+xxMlerdI17T1Tv6wO9iJMo=</AttestValue>
 *    <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" KeyName="//www.manferdelli.com/jlmlinuxhp/Keys/TrustedOSAttest">
 *      <KeyType>RSAKeyType</KeyType>
 *        <ds:KeyValue>
 *          <ds:RSAKeyValue size="1024">
 *            <ds:M>rBdxn3Cd7a+X736tzMrIp6yCzfsF9gN+7NdoHYmRBtvy2zWRWtAbeyrxpzzbDyC7zwtZRxVCPem0NbszpP066v7Rw/SeSZvr0dWaBpzkatIhKpJHqRigcAl43RgSH0tSB6+/mEj11a/tTMUidTobi4ZEV1qPX+qauUr8dwM9kEs=</ds:M>
 *            <ds:E>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAE=</ds:E>
 *        </ds:RSAKeyValue>
 *      </ds:KeyValue>
 *    </ds:KeyInfo>
 *  
 *   <InterpretationHint>
 *    <attestedInfo>
 *      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" KeyName="//www.manferdelli.com/jlmlinuxhp/Keys/fileClientProgram">
 *        <KeyType>RSAKeyType</KeyType>
 *          <ds:KeyValue>
 *          <ds:RSAKeyValue size="1024">
 *            <ds:M>hGwM+FLbzGTrOhbz6iiKrIdgx+NptyUWHJAqNLUUtppsQcWcbX01pBam74muwqd9Cjc1MXgHLnmthqXtqJ3VLW75mcTAKqtJXlMO3Mb6BeewfFAHBKuVB9yf5qJyGIqLOQy2jGkoo66SSb40xuypcbsSc0acWdhTDL15wPETiT8=</ds:M>
 *            <ds:E>AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAE=</ds:E>
 *          </ds:RSAKeyValue>
 *        </ds:KeyValue>
 *      </ds:KeyInfo>
 *    </attestedInfo>
 *  </InterpretationHint>
 *
 *</Attest>
 * 
 * 
 */


#define MAXATTESTSIZE 16384


// ------------------------------------------------------------------


Attest::Attest()
{
    m_pNodeAttest= NULL;
    m_pNodeNonce= NULL;
    m_pNodeAttestdInfo= NULL;
    m_pNodeCodeDigest= NULL;
    m_pNodeAttestValue= NULL;
    m_pNodeAttestdInfo= NULL;
    m_pNodeattestKeyInfo= NULL;
    m_pNodeattestdKeyInfo= NULL;
    m_szAttestalg= NULL;
}


Attest::~Attest()
{
}


bool  Attest::init(const char* szXMLAttest)
{
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    const char*     szA= NULL;
    
#ifdef QUOTETEST1
    fprintf(g_logFile, "init()\n");
#endif
    if(szXMLAttest==NULL)
        return false;
    
    if(!m_doc.Parse(szXMLAttest)) {
        fprintf(g_logFile, "Attest::init: Can't parse attest\n");
        return false;
    }   
    pRootElement= m_doc.RootElement();
    if(pRootElement==NULL) {
        fprintf(g_logFile, "Attest::init: Can't get root of attest\n");
        return false;
    }
    m_pNodeAttest= Search((TiXmlNode*) pRootElement, "Attest");
    if(m_pNodeAttest==NULL) {
        fprintf(g_logFile, "Attest::init: No Attest node\n");
        return false;
    }
    // <ds:AttestMethod Algorithm=
    pNode=  Search(m_pNodeAttest, "ds:AttestMethod");
    if(pNode==NULL) {
        fprintf(g_logFile, "Attest::init: No ds:AttestMethod node\n");
        return false;
    }
    szA= ((TiXmlElement*) pNode)->Attribute ("Algorithm");
    if(szA==NULL) {
        fprintf(g_logFile, "Attest::init: No ds:AttestMethod Algorithm\n");
        return false;
    }
    m_szAttestalg= strdup(szA);
    m_pNodeNonce= Search(m_pNodeAttest, "Nonce");
    m_pNodeCodeDigest= Search(m_pNodeAttest, "CodeDigest");
    if(m_pNodeCodeDigest==NULL) {
        fprintf(g_logFile, "Attest::init: No CodeDigest node\n");
        return false;
    }
    m_pNodeAttestdInfo= Search(m_pNodeAttest, "AttestdInfo");
    if(m_pNodeAttestdInfo==NULL) {
        fprintf(g_logFile, "Attest::init: No AttestdInfo node\n");
        return false;
    }
    m_pNodeAttestValue= Search(m_pNodeAttestdInfo, "AttestValue");
    if(m_pNodeAttestValue==NULL) {
        fprintf(g_logFile, "Attest::init: No AttestValue node\n");
        return false;
    }
    m_pNodeattestdKeyInfo= Search(m_pNodeAttestdInfo, "ds:KeyInfo");
    pNode= m_pNodeAttestValue->NextSibling();
    m_pNodeattestKeyInfo= Search(pNode, "ds:KeyInfo");

    return true;
}


char*  Attest::getCanonicalAttestInfo()
{
    if(m_pNodeAttestdInfo==NULL)
        return NULL;
    return canonicalize(m_pNodeAttestdInfo);
}


char*  Attest::getAttestValue()
{
    TiXmlNode* pNode= m_pNodeAttestValue->FirstChild();
    if(pNode!=NULL)
        return strdup(pNode->Value());
    return NULL;
}


char* Attest::getnonceValue()
{
    if(m_pNodeNonce==NULL)
        return NULL;
    TiXmlNode* pNode= m_pNodeNonce->FirstChild();
    if(pNode!=NULL)
        return strdup(pNode->Value());
    return NULL;
}


char* Attest::getcodeDigest()
{
    if(m_pNodeCodeDigest==NULL)
        return NULL;

    const char*   szCodeDigest= NULL;
    TiXmlNode* pNode= NULL;
    pNode= m_pNodeCodeDigest->FirstChild();

    if(pNode!=NULL) {
        szCodeDigest= pNode->Value();
        if(szCodeDigest==NULL) {
            return NULL;
        }
        return strdup(szCodeDigest);
    }

    return NULL;
}


char* Attest::getattestkeyInfo()
{
    if(m_pNodeattestKeyInfo==NULL) {
        return NULL;
    }
    return canonicalize(m_pNodeattestKeyInfo);
}


char* Attest::getattestdkeyName()
{
    if(m_pNodeattestdKeyInfo==NULL) 
        return NULL;
    const char* szA= ((TiXmlElement*) m_pNodeattestdKeyInfo)->Attribute ("KeyName");
    if(szA==NULL)
        return NULL;
    return strdup(szA);
}


char* Attest::getattestdkeyInfo()
{
    if(m_pNodeattestdKeyInfo==NULL) {
        return NULL;
    }
    return canonicalize(m_pNodeattestdKeyInfo);
}


char* Attest::getAttestAlgorithm()
{
    if(m_szAttestalg==NULL)
        return NULL;
    // Fix
    return strdup(m_szAttestalg);
}


// ------------------------------------------------------------------


bool checkXMLAttest(const char* szAttestAlg, const char* szCanonicalAttestdBody, const char* sznonce, 
                const char* szdigest, KeyInfo* pKeyInfo, const char* szAttestValue)
{
    Sha1    oSha1Hash;
    Sha256  oSha256Hash;

    int     sizeNonce= SHA256DIGESTBYTESIZE;
    byte    nonce[SHA256DIGESTBYTESIZE];
    int     sizehashBody= SHA256DIGESTBYTESIZE;
    byte    hashBody[SHA256DIGESTBYTESIZE];
    int     sizehashCode= SHA256DIGESTBYTESIZE;
    byte    hashCode[SHA256DIGESTBYTESIZE];

    int     outLen= RSA2048BYTEBLOCKSIZE;
    byte    attestValue[RSA2048BYTEBLOCKSIZE];

    byte    hashFinal[SHA256DIGESTBYTESIZE];

    int     hashType= 0;
    int     sizefinalHash= 0;

#ifdef TEST
    fprintf(g_logFile, "checkXMLAttest alg: %s\n", szAttestAlg);
    fprintf(g_logFile, "checkXMLAttest sig value: %s\nSigner Keyinfo:\n", szAttestValue);
    ((RSAKey*)pKeyInfo)->printMe();
#endif
    UNUSEDVAR(sizefinalHash);   

    if(szAttestAlg==NULL) {
        fprintf(g_logFile, "checkXMLAttest: empty alg\n");
        return false;
    }

    if(strcmp(QUOTEMETHODTPM12RSA1024, szAttestAlg)==0 
        || strcmp(QUOTEMETHODTPM12RSA2048, szAttestAlg)==0) {
        hashType= SHA1HASH;
    }
    else if(strcmp(QUOTEMETHODSHA256FILEHASHRSA1024, szAttestAlg)==0 
        || strcmp(QUOTEMETHODSHA256FILEHASHRSA2048, szAttestAlg)==0) {
        hashType= SHA256HASH;
    }
    else {
        fprintf(g_logFile, "checkXMLAttest: Unsupported attest algorithm %s\n", szAttestAlg);
        return false;
    }

    // get nonce
    if(sznonce!=NULL) {
        if(!fromBase64(strlen(sznonce), sznonce, &sizeNonce, nonce)) {
            fprintf(g_logFile, "checkXMLAttest: Cant base64 decode noncevalue\n");
            return false;
        }
    }
    else {
        sizeNonce= 0;
    }

    // hash body
    if(szCanonicalAttestdBody==NULL) {
        fprintf(g_logFile, "checkXMLAttest: empty body to attest\n");
        return false;
    }
    if(hashType==SHA1HASH) {
        oSha1Hash.Init();
        oSha1Hash.Update((byte*) szCanonicalAttestdBody, strlen(szCanonicalAttestdBody));
        oSha1Hash.Final();
        oSha1Hash.getDigest(hashBody);
        sizehashBody= SHA1DIGESTBYTESIZE;
    }
    else if(hashType==SHA256HASH) {
        oSha256Hash.Init();
        oSha256Hash.Update((byte*) szCanonicalAttestdBody, strlen(szCanonicalAttestdBody));
        oSha256Hash.Final();
        oSha256Hash.GetDigest(hashBody);
        sizehashBody= SHA256DIGESTBYTESIZE;
    }
    else {
        fprintf(g_logFile, "checkXMLAttest: invalid hash type\n");
        return false;
    }

    // get code hash
    if(szdigest==NULL) {
        fprintf(g_logFile, "checkXMLAttest: no code digest\n");
        return false;
    }
    if(!fromBase64(strlen(szdigest), szdigest, &sizehashCode, hashCode)) {
        fprintf(g_logFile, "checkXMLAttest: Cant base64 decode noncevalue\n");
        return false;
    }

    // decode attest value
    if(!fromBase64(strlen(szAttestValue), szAttestValue, &outLen, attestValue, false)) {
        fprintf(g_logFile, "checkXMLAttest: Cant base64 code decode attest value\n");
        return false;
    }

    // generate final attest hash
    if(strcmp(QUOTEMETHODTPM12RSA2048, szAttestAlg)==0 || strcmp(QUOTEMETHODTPM12RSA1024, szAttestAlg)==0) {
#ifdef NOQUOTE
        if(!tpm12attestHash(0, NULL, sizehashBody, hashBody,
                           sizehashCode, hashCode, hashFinal)) {
            fprintf(g_logFile, "checkXMLAttest: Cant compute TPM12 hash\n");
            return false;
        }
#else
        byte    locality= 0; 
        u32     sizeversion= 0;
        byte*   versionInfo= NULL;

#ifdef PCR18
        byte pcrMask[3]= {0,0,0x6};  // pcr 17, 18
#else
        byte pcrMask[3]= {0,0,0x2};  // pcr 17
#endif

        // reconstruct PCR composite and composite hash
        if(!tpm12attest2Hash(0, NULL, pcrMask, locality,
                            sizehashBody, hashBody, sizehashCode, hashCode, 
                            false, sizeversion, versionInfo, 
                            hashFinal)) {
            fprintf(g_logFile, "checkXMLAttest: Cant compute TPM12 hash\n");
            return false;
        }
#endif
        sizefinalHash= SHA1DIGESTBYTESIZE;
    }
    else if(strcmp(QUOTEMETHODSHA256FILEHASHRSA2048, szAttestAlg)==0 || 
             strcmp(QUOTEMETHODSHA256FILEHASHRSA1024, szAttestAlg)==0) {
        if(!sha256attestHash(0, NULL, sizehashBody, hashBody,
                           sizehashCode, hashCode, hashFinal)) {
            fprintf(g_logFile, "checkXMLAttest: Cant compute sha256 hash\n");
            return false;
        }
        sizefinalHash= SHA256DIGESTBYTESIZE;
    }
    else {
        fprintf(g_logFile, "checkXMLAttest: Unsupported attest algorithm %s\n", szAttestAlg);
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "hashType: %d, method: %s, hashSize: %d\n", 
            hashType, szAttestAlg, sizefinalHash);
    PrintBytes((char*)"Hash body: ", hashBody, sizehashBody);
    PrintBytes((char*)"Code digest: ", hashCode, sizehashCode);
    PrintBytes((char*)"final hash: ", hashFinal, sizehashCode);
    fflush(g_logFile);
#endif

    bool fRet= RSAVerify(*(RSAKey*)pKeyInfo, hashType, hashFinal,
                               attestValue);
    return fRet;
}


// <Attest format='xml'>
//     <nonce> </nonce>  (optional)
//     <CodeDigest alg='SHA256'>
//     </CodeDigest>
//     <AttestdInfo>
//         <ds:CanonicalizationMethod 
//          Algorithm="http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#"/>
//            <ds:AttestMethod Algorithm="#"/>
//         <KeyInfo ...>
//     </AttestdInfo>
//     <AttestValue>
//     </AttestValue>
// </Attest>
char* encodeXMLAttest(int sizenonce, byte* nonce, int sizeCodeDigest, 
                     byte* codeDigest, const char* szAttestdInfo, 
                     const char* szKeyInfo, int sizeAttest, byte* attest)
{
    char            szB[4096];
    int             nsize= 2*GLOBALMAXPUBKEYSIZE;
    char            szN[2*GLOBALMAXPUBKEYSIZE];
    char*           szattestValue= NULL;
    char*           szAttest= NULL;
    char*           szNonce= NULL;
    char*           szCodeDigest= NULL;
    const char*     szdigestAlg= "SHA256";

    nsize=  2*GLOBALMAXPUBKEYSIZE;
    if(sizenonce>0) {
        if(!toBase64(sizenonce, nonce, &nsize, szN)) {
            fprintf(g_logFile, "encodeXMLAttest: cant transform nonce to base64\n");
            goto cleanup;
        }
        if((strlen(g_szNonceTemplate)+strlen(szN)+16)>4096) {
            fprintf(g_logFile, "encodeXMLAttest: nonce too large\n");
            goto cleanup;
        }
        sprintf(szB, g_szNonceTemplate, szN);
        szNonce= strdup(szB);
    }
    else
        szNonce= strdup("");

    nsize=  2*GLOBALMAXPUBKEYSIZE-16;
    if(!toBase64(sizeCodeDigest, codeDigest, &nsize, szN)) {
        fprintf(g_logFile, "encodeXMLAttest: cant transform codeDigest to base64\n");
        goto cleanup;
    }
    szCodeDigest= strdup(szN);
    if(sizeCodeDigest==20)
        szdigestAlg= "SHA1";

    nsize=  2*GLOBALMAXPUBKEYSIZE-16;
    if(!toBase64(sizeAttest, attest, &nsize, szN)) {
        fprintf(g_logFile, "encodeXMLAttest: cant transform attestd value to base64\n");
        goto cleanup;
    }
    szattestValue= strdup(szN);

    if((strlen(g_szAttestTemplate)+strlen(szNonce)+strlen(szdigestAlg)+strlen(szCodeDigest)
         +strlen(szAttestdInfo) +strlen(szattestValue) +strlen(szKeyInfo) +16)>4096) {
        fprintf(g_logFile, "encodeXMLAttest: attest too large\n");
        goto cleanup;
    }
    sprintf(szB, g_szAttestTemplate, szNonce, szdigestAlg, szCodeDigest, 
            szAttestdInfo, szattestValue, szKeyInfo);
    szAttest= strdup(szB);

cleanup:
    if(szCodeDigest!=NULL) {
        free(szCodeDigest);
        szCodeDigest= NULL;
    }
    if(szattestValue!=NULL) {
        free(szattestValue);
        szattestValue= NULL;
    }
    if(szNonce!=NULL) {
        free(szNonce);
        szNonce= NULL;
    }
#ifdef QUOTETEST
    fprintf(g_logFile, "encodeXMLAttest, %s, size: %d, attest\n%s\n", szdigestAlg, 
           sizeCodeDigest, szAttest);
#endif
    return szAttest;
}


// decode attest 
//      nonce
//      CodeDigest value and alg
//      canonicalized AttestdInfo
//      attestValue
bool decodeXMLAttest(const char* szXMLAttest, char** pszAlg, char** psznonce, 
                    char** pszDigest, char** pszAttestdInfo, char** pszAttestValue, 
                    char** pszattestKeyInfo, char** pszattestdKeyInfo,
                    char** pszattestdKeyName)
{
    Attest   oAttest;

    if(!oAttest.init(szXMLAttest)) {
        fprintf(g_logFile, "decodeXMLAttest: cant init Attest\n");
        return false;
    }
    *pszAlg= oAttest.getAttestAlgorithm();
    *pszAttestdInfo= oAttest.getCanonicalAttestInfo();
    *pszAttestValue= oAttest.getAttestValue();
    *psznonce= oAttest.getnonceValue();
    *pszattestKeyInfo= oAttest.getattestkeyInfo();
    *pszDigest= oAttest.getcodeDigest();
    *pszattestdKeyInfo= oAttest.getattestdkeyInfo();
    *pszattestdKeyName= oAttest.getattestdkeyName();

    return true;
}


// ------------------------------------------------------------------


const char*   g_szCertTemplate= 
"<ds:Signature>\n%s\n"\
"<ds:SignatureValue>\n%s\n</ds:SignatureValue>\n" \
"</ds:Signature>\n";


char*   formatCert(const char* szSignedInfo, const char* szSig)
{
    char    rgBuf[MAXREQUESTSIZE];

    if(szSignedInfo==NULL || szSig==NULL)
        return NULL;
    sprintf(rgBuf,g_szCertTemplate, szSignedInfo, szSig);
    return strdup(rgBuf);
}


const char* g_szSignedInfo1=
"<ds:SignedInfo>\n"\
"    <ds:CanonicalizationMethod Algorithm=\"http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#\" />\n"\
"    <ds:SignatureMethod Algorithm=\"http://www.manferdelli.com/2011/Xml/algorithms/rsa%d-sha256-pkcspad#\" />\n"\
"    <Certificate Id=\"%s\" version='1'>\n"\
"        <SerialNumber>%d</SerialNumber>\n"\
"        <PrincipalType>%s</PrincipalType>\n"\
"        <IssuerName>%s</IssuerName>\n"\
"        <IssuerID>%d</IssuerID>\n";

const char* g_szValidity=
"        <ValidityPeriod>\n"\
"            <NotBefore>%s</NotBefore>\n"\
"            <NotAfter>%s</NotAfter>\n"\
"        </ValidityPeriod>\n";

const char* g_szSignedInfoDigest=
"        <CodeDigest>%s</CodeDigest>\n";

const char* g_szSignedInfo2=
"        <SubjectName>%s</SubjectName>\n"\
"        <SubjectKey>\n";
const char* g_szSignedInfo3=
" </SubjectKey>\n"\
"        <SubjectKeyID>%s</SubjectKeyID>\n"\
"        <RevocationPolicy>Local-check-only</RevocationPolicy>\n"\
"    </Certificate>\n"\
"</ds:SignedInfo>\n";


char*   formatSignedInfo(RSAKey* pKey, 
            const char* szCertid, int serialNo, const char* szPrincipalType, 
            const char* szIssuerName, const char* szIssuerID, const char* szNotBefore, 
            const char* szNotAfter, const char* szSubjName, const char* szKeyInfo, 
            const char* szDigest, const char* szSubjKeyID)
{
    char    szTemp[MAXREQUESTSIZE];
    char    rgBuf[MAXREQUESTSIZE];
    int     iLeft= MAXREQUESTSIZE;
    char*   p= rgBuf;
    char*   szSignedInfo= NULL;
    int     bitkeySize= pKey->m_ikeySize;

#ifdef  TEST
    fprintf(g_logFile, "Format signedInfo %d\n", bitkeySize);
    fflush(g_logFile);
    fprintf(g_logFile, "\tCertid: %s, serialNo: %d\n", szCertid, serialNo);
    fflush(g_logFile);
    fprintf(g_logFile, "\tnotBefore: %s, notAfter: %s\n", szNotBefore, szNotAfter);
    fflush(g_logFile);
    fprintf(g_logFile, "\tszKeyInfo: %s, digest: %s, subjID\n", szKeyInfo, szDigest, szSubjKeyID);
    fflush(g_logFile);
#endif

    sprintf(szTemp, g_szSignedInfo1, bitkeySize, szCertid, serialNo, 
            szPrincipalType, szIssuerName, szIssuerID);
    if(!safeTransfer(&p, &iLeft, szTemp))
        return NULL;

    sprintf(szTemp, g_szValidity, szNotBefore, szNotAfter);
    if(!safeTransfer(&p, &iLeft, szTemp))
        return NULL;

    sprintf(szTemp, g_szSignedInfo2, szSubjName);
    if(!safeTransfer(&p, &iLeft, szTemp))
        return NULL;

    if(!safeTransfer(&p, &iLeft, szKeyInfo))
        return NULL;

    sprintf(szTemp, g_szSignedInfoDigest, szDigest);
    if(!safeTransfer(&p, &iLeft, szTemp))
        return NULL;

    sprintf(szTemp, g_szSignedInfo3, szSubjKeyID);
    if(!safeTransfer(&p, &iLeft, szTemp))
        return NULL;

    szSignedInfo= XMLCanonicalizedString(rgBuf);

#ifdef  QUOTETEST
    fprintf(g_logFile, "formatSignedInfo, Canonicalized: %s\n", szSignedInfo);
#endif
    return szSignedInfo;
}


// ------------------------------------------------------------------


