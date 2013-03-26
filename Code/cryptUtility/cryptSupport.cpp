//
//  cryptSupport.cpp
//      John Manferdelli
//
//  Description: security principal class implementation
//
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
#include "jlmcrypto.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "cryptSupport.h"
#include "rsaHelper.h"
#include "sha256.h"
#include "sha1.h"
#include "tinyxml.h"
#include "hashprep.h"

#include <string.h>


#define QUOTE2_DEFINED


// ------------------------------------------------------------------------


bool RsaPkcsPadSignCheck(RSAKey* pKey, int hashType, byte* hash, int sizeSig, byte* sig)
{
    byte    rgPadded[RSA2048BYTEBLOCKSIZE];
    bnum    bnMsg(pKey->m_iByteSizeM/2);
    bnum    bnOut(pKey->m_iByteSizeM/2);

    printf("RsaPkcsPadSignCheck\n");
    PrintBytes((char*)"sig\n", sig, sizeSig);
    memcpy((byte*)bnMsg.m_pValue, sig, sizeSig);
    if(!mpRSAENC(bnMsg, *(pKey->m_pbnE), *(pKey->m_pbnM), bnOut))
        return false;
    revmemcpy(rgPadded, (byte*)bnOut.m_pValue, pKey->m_iByteSizeM);
    if(!emsapkcsverify(hashType, hash, sizeSig, rgPadded)) {
        printf("%d bytes\n", pKey->m_iByteSizeM);
        PrintBytes((char*)"decrypted sig\n", rgPadded, pKey->m_iByteSizeM);
        return false;
    }

    return true;
}


bool verifyXMLQuote(const char* szQuoteAlg, const char* szCanonicalQuotedBody, const char* sznonce, 
                const char* szdigest, KeyInfo* pKeyInfo, const char* szQuoteValue)
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
    byte    quoteValue[RSA2048BYTEBLOCKSIZE];

    byte    hashFinal[SHA256DIGESTBYTESIZE];

    int     hashType= 0;

    byte    locality= 0; 
    u32     sizeversion= 0;
    byte*   versionInfo= NULL;
#ifdef PCR18
    byte pcrMask[3]= {0,0,0x6};  // pcr 17, 18
#else
    byte pcrMask[3]= {0,0,0x2};  // pcr 17
#endif

    if(szQuoteAlg==NULL) {
        fprintf(g_logFile, "verifyXMLQuote: empty alg\n");
        return false;
    }

    if(strcmp(QUOTEMETHODTPM12RSA1024, szQuoteAlg)==0 
        || strcmp(QUOTEMETHODTPM12RSA2048, szQuoteAlg)==0) {
        hashType= SHA1HASH;
    }
    else if(strcmp(QUOTEMETHODSHA256FILEHASHRSA1024, szQuoteAlg)==0 
        || strcmp(QUOTEMETHODSHA256FILEHASHRSA2048, szQuoteAlg)==0) {
        hashType= SHA256HASH;
    }
    else {
        fprintf(g_logFile, "verifyXMLQuote: Unsupported quote algorithm %s\n", szQuoteAlg);
        return false;
    }

    // get nonce
    if(sznonce!=NULL) {
        if(!fromBase64(strlen(sznonce), sznonce, &sizeNonce, nonce)) {
            fprintf(g_logFile, "verifyXMLQuote: Cant base64 decode noncevalue\n");
            return false;
        }
    }
    else {
        sizeNonce= 0;
    }

    // hash body
    if(szCanonicalQuotedBody==NULL) {
        fprintf(g_logFile, "verifyXMLQuote: empty body to quote\n");
        return false;
    }
    if(hashType==SHA1HASH) {
        oSha1Hash.Init();
        oSha1Hash.Update((byte*) szCanonicalQuotedBody, strlen(szCanonicalQuotedBody));
        oSha1Hash.Final();
        oSha1Hash.getDigest(hashBody);
        sizehashBody= SHA1DIGESTBYTESIZE;
    }
    else if(hashType==SHA256HASH) {
        oSha256Hash.Init();
        oSha256Hash.Update((byte*) szCanonicalQuotedBody, strlen(szCanonicalQuotedBody));
        oSha256Hash.Final();
        oSha256Hash.GetDigest(hashBody);
        sizehashBody= SHA256DIGESTBYTESIZE;
    }
    else {
        fprintf(g_logFile, "verifyXMLQuote: invalid hash type\n");
        return false;
    }

    // get code hash
    if(szdigest==NULL) {
        fprintf(g_logFile, "verifyXMLQuote: no code digest\n");
        return false;
    }
    if(!fromBase64(strlen(szdigest), szdigest, &sizehashCode, hashCode)) {
        fprintf(g_logFile, "verifyXMLQuote: Cant base64 decode noncevalue\n");
        return false;
    }

    // decode quote value
    if(!fromBase64(strlen(szQuoteValue), szQuoteValue, &outLen, quoteValue)) {
        fprintf(g_logFile, "verifyXMLQuote: Cant base64 code decode quote value\n");
        return false;
    }

    // generate final quote hash
    if(strcmp(QUOTEMETHODTPM12RSA2048, szQuoteAlg)==0 || strcmp(QUOTEMETHODTPM12RSA1024, szQuoteAlg)==0) {
#ifndef QUOTE2_DEFINED 
        if(!tpm12quoteHash(0, NULL, sizehashBody, hashBody,
                           sizehashCode, hashCode, hashFinal)) {
            fprintf(g_logFile, "verifyXMLQuote: Cant compute TPM12 hash\n");
            return false;
        }
#else
         // reconstruct PCR composite and composite hash
        if(!tpm12quote2Hash(0, NULL, pcrMask, locality,
                            sizehashBody, hashBody, sizehashCode, hashCode, 
                            false, sizeversion, versionInfo, 
                            hashFinal)) {
            fprintf(g_logFile, "verifyXMLQuote: Cant compute TPM12 hash\n");
            return false;
        }
#endif
    }
    else if(strcmp(QUOTEMETHODSHA256FILEHASHRSA2048, szQuoteAlg)==0 || 
             strcmp(QUOTEMETHODSHA256FILEHASHRSA1024, szQuoteAlg)==0) {
        if(!sha256quoteHash(0, NULL, sizehashBody, hashBody,
                           sizehashCode, hashCode, hashFinal)) {
            fprintf(g_logFile, "verifyXMLQuote: Cant compute sha256 hash\n");
            return false;
        }
    }
    else {
        fprintf(g_logFile, "verifyXMLQuote: Unsupported quote algorithm %s\n", szQuoteAlg);
        return false;
    }

    return RsaPkcsPadSignCheck((RSAKey*) pKeyInfo, hashType, hashFinal,
                               outLen, quoteValue);
}


RSAKey* keyfromkeyInfo(const char* szKeyInfo)
{
    RSAKey*         pKey= new RSAKey();
    TiXmlElement*   pRootElement= NULL;

    if(pKey==NULL) {
        fprintf(g_logFile, "keyfromkeyInfo: did not new key\n");
        return NULL;
    }
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


// ------------------------------------------------------------------------


PrincipalCert::PrincipalCert()
{
    m_szSignature= NULL;
    m_szSignedInfo= NULL;
    m_szSignatureValue= NULL;
    m_szSignatureMethod= NULL;
    m_szCanonicalizationMethod= NULL;
    m_szRevocationInfo= NULL;
    m_pSignerKeyInfo= NULL;
    m_pSubjectKeyInfo= NULL;
    m_szPrincipalName= NULL;
    m_fSigValuesValid= false;
}


PrincipalCert::~PrincipalCert()
{
    if(m_szSignature!=NULL) {
        free(m_szSignature);
    } 
    m_szSignature= NULL;
    if(m_szSignedInfo!=NULL) {
        free(m_szSignedInfo);
    } 
    m_szSignedInfo= NULL;
    m_szSignatureValue= NULL;
    m_szSignatureMethod= NULL;
    m_szCanonicalizationMethod= NULL;
    m_szRevocationInfo= NULL;
    m_pSignerKeyInfo= NULL;
    if(m_pSubjectKeyInfo!=NULL) {
        delete m_pSubjectKeyInfo;
    }
    m_pSubjectKeyInfo= NULL;
    m_fSigValuesValid= false;
}


bool  PrincipalCert::init(const char* szSig)
{
    m_szSignature= strdup(szSig);
    return true;
}


char* PrincipalCert::getPrincipalName()
{
    return m_szPrincipalName;
}


char* PrincipalCert::getCanonicalizationMethod()
{
    return m_szCanonicalizationMethod;
}


bool PrincipalCert::parsePrincipalCertElements()
{
    TiXmlDocument   doc;
    TiXmlElement*  pRootElement;

#ifdef CERTTEST
    fprintf(g_logFile, "parsePrincipalCertElements\n%s\n", m_szSignature);
#endif
    if(m_szSignature==NULL) {
        fprintf(g_logFile, "parsePrincipalCertElements: No signature document\n");
        return false;
    }
    if(!doc.Parse(m_szSignature)) {
        fprintf(g_logFile, "parsePrincipalCertElements: Cant parse document from file string\n");
        return false;
    }
    pRootElement= doc.RootElement();
    if(pRootElement==NULL) {
        fprintf(g_logFile, "parsePrincipalCertElements: Cant get root element of PrincipalCert\n");
        return false;
    }
    return parsePrincipalCertfromRoot(pRootElement);
}


bool PrincipalCert::parsePrincipalCertfromRoot(TiXmlElement*  pRootElement)
{
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;
    TiXmlNode*      pNode2= NULL;
    TiXmlNode*      pSignedInfoNode= NULL;
    TiXmlNode*      pSubjectKeyInfoNode= NULL;
    const char*           szTimePoint= NULL;

#ifdef CERTTEST
    fprintf(g_logFile, "parsePrincipalCertElementfromRoot\n");
#endif
    if(strcmp(pRootElement->Value(), "ds:Signature")!=0) {
        fprintf(g_logFile, "Does not start with signature (%s)\n", pRootElement->Value());
        return false;
    }
     
    // make sure it's in signedinfo
    pSignedInfoNode= Search((TiXmlNode*) pRootElement, "ds:SignedInfo");
    if(pSignedInfoNode==NULL) {
        fprintf(g_logFile, "Cant find SignedInfo\n");
        return false;
    }

    // fill m_szSignedInfo;
    m_szSignedInfo= canonicalize(pSignedInfoNode);

    // fill m_szSignatureMethod;
    pNode= Search(pSignedInfoNode, "ds:SignatureMethod");
    if(pNode==NULL) {
        fprintf(g_logFile, "Cant find SignatureMethod\n");
        return false;
    }
    m_szSignatureMethod= strdup(((TiXmlElement*) pNode)->Attribute("Algorithm"));


    // fill m_szCanonicalizationMethod;
    pNode= Search(pSignedInfoNode, "ds:CanonicalizationMethod");
    if(pNode==NULL) {
        fprintf(g_logFile, "Cant find CanonicalizationMethod\n");
        return false;
    }
    m_szCanonicalizationMethod= strdup(((TiXmlElement*) pNode)->Attribute("Algorithm"));

    // fill m_szRevocationInfo;
    pNode= Search(pSignedInfoNode, "RevocationPolicy");
    if(pNode==NULL) {
        fprintf(g_logFile, "Cant find RevocationPolicy\n");
        return false;
    }

    // fill m_pSubjectKeyInfo;
    pNode= Search(pSignedInfoNode, "SubjectKey");
    if(pNode==NULL) {
        fprintf(g_logFile, "Cant find SubjectKey\n");
        return false;
    }
    pSubjectKeyInfoNode= Search(pNode, "ds:KeyInfo");
    if(pSubjectKeyInfoNode==NULL) {
        fprintf(g_logFile, "Cant find SubjectKey KeyInfo\n");
        return false;
    }

    if(!initRSAKeyFromKeyInfo(&m_pSubjectKeyInfo, pSubjectKeyInfoNode)) {
        fprintf(g_logFile, "Cant init KeyInfo\n");
        return false;
    }

    // fill principal name
    pNode= Search(pSignedInfoNode, "SubjectName");
    if(pNode==NULL) {
        fprintf(g_logFile, "Cant find Subject name\n");
        return false;
    }
    pNode1= ((TiXmlElement*)pNode)->FirstChild();
    if(pNode1!=NULL) {
        m_szPrincipalName= strdup(((TiXmlElement*)pNode1)->Value());
    }
    else {
        fprintf(g_logFile, "Cant get subject name value\n");
        return false;
    }

    // fill m_ovalidityPeriod;
    pNode= Search((TiXmlNode*) pSignedInfoNode, "ValidityPeriod");
    if(pNode==NULL) {
        fprintf(g_logFile, "Cant find Validity Period\n");
        return false;
    }
    pNode1= Search(pNode, "NotBefore");
    if(pNode1==NULL) {
        fprintf(g_logFile, "Cant find NotBefore\n");
        return false;
    }
    pNode2= ((TiXmlElement*)pNode1)->FirstChild();
    if(pNode2) {
        szTimePoint= ((TiXmlElement*)pNode2)->Value();
    }
    else {
        fprintf(g_logFile, "Cant get NotBefore value\n");
        return false;
    }

    if(!UTCtogmTime(szTimePoint, &m_ovalidityPeriod.notBefore)) {
        fprintf(g_logFile, "Cant interpret NotBefore value\n");
        return false;
    }
    pNode1= Search(pNode, "NotAfter");
    if(pNode1==NULL) {
        fprintf(g_logFile, "Cant find NotAfter\n");
        return false;
    }
    pNode2= ((TiXmlElement*)pNode1)->FirstChild();
    if(pNode2) {
        szTimePoint= ((TiXmlElement*)pNode2)->Value();
    }
    else {
        fprintf(g_logFile, "Cant get NotAftervalue\n");
        return false;
    }

    if(!UTCtogmTime(szTimePoint, &m_ovalidityPeriod.notAfter)) {
        fprintf(g_logFile, "Cant interpret NotAftervalue\n");
        return false;
    }

    // fill m_szSignatureValue;
    pNode= Search((TiXmlNode*) pRootElement, "ds:SignatureValue");
    if(pNode==NULL) {
        fprintf(g_logFile, "Cant find SignatureValue\n");
        return false;
    }
    pNode1= ((TiXmlElement*)pNode)->FirstChild();
    if(pNode1) {
        m_szSignatureValue= strdup(((TiXmlElement*)pNode1)->Value());
    }
    else {
        fprintf(g_logFile, "Cant get SignatureValue\n");
        return false;
    }

#ifdef CERTTEST
    fprintf(g_logFile, "parseCertElementfromRoot returns true\n");
#endif
    m_fSigValuesValid= true;
    return true;
}


KeyInfo*  PrincipalCert::getSubjectKeyInfo()
{
    return m_pSubjectKeyInfo;
}


#ifdef TEST
void  PrincipalCert::printMe()
{
    if(m_fSigValuesValid)
        fprintf(g_logFile, "Signatures valid\n");
    else
        fprintf(g_logFile, "Signatures invalid\n");
    if(m_szSignature!=NULL)
        fprintf(g_logFile, "Signature: %s\n", m_szSignature);
    if(m_szSignedInfo!=NULL)
        fprintf(g_logFile, "SignedInfo: %s\n", m_szSignedInfo);
    if(m_szSignatureMethod!=NULL)
        fprintf(g_logFile, "SignatureMethod: %s\n", m_szSignatureMethod);
    if(m_szCanonicalizationMethod!=NULL)
        fprintf(g_logFile, "CanonicalizationMethod: %s\n", m_szCanonicalizationMethod);
    if(m_szPrincipalName!=NULL)
        fprintf(g_logFile, "PrincipalName: %s\n", m_szPrincipalName);
}
#endif


void copyTime(tm& from, tm& to)
{
    to.tm_year= from.tm_year;
    to.tm_mon= from.tm_mon;
    to.tm_mday= from.tm_mday;
    to.tm_hour= from.tm_hour;
    to.tm_min= from.tm_min;
    to.tm_sec= from.tm_sec;
}


bool PrincipalCert::getvalidityPeriod(Period& period)
{
    copyTime(m_ovalidityPeriod.notBefore, period.notBefore);
    copyTime(m_ovalidityPeriod.notAfter, period.notAfter);
    return true;
}


char*    PrincipalCert::getCanonicalwasSigned()
{
    return m_szSignedInfo;
}


char*    PrincipalCert::getRevocationPolicy()
{
    return m_szRevocationInfo;
}


char*    PrincipalCert::getSignatureValue()
{
    return m_szSignatureValue;
}


char*    PrincipalCert::getSignatureAlgorithm()
{
    return m_szSignatureMethod;
}


/*
 * 
 *  Typical quote for public key
 * 
 *  <Quote format='xml'>
 *      <nonce> </nonce>  (optional)
 *      <CodeDigest alg='SHA256'> </CodeDigest>
 *      <ds:QuotedInfo>
 *           <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" KeyName="//www...">
 *             <KeyType>RSAKeyType</KeyType>
 *                <ds:KeyValue>
 *                  <ds:RSAKeyValue size="1024">
 *                     <ds:M></ds:M>
 *                     <ds:E></ds:E>
 *                  </ds:RSAKeyValue>
 *                </ds:KeyValue>
 *           </ds:KeyInfo>
 *      </ds:QuotedInfo>
 *      <quoteValue> </quoteValue>
 *  </Quote>
 * 
 * 
 */


#define MAXATTESTSIZE 16384


// ------------------------------------------------------------------


Quote::Quote()
{
    m_pNodeQuote= NULL;
    m_pNodeNonce= NULL;
    m_pNodeQuotedInfo= NULL;
    m_pNodeCodeDigest= NULL;
    m_pNodeQuoteValue= NULL;
    m_pNodeQuotedInfo= NULL;
    m_pNodequoteKeyInfo= NULL;
    m_pNodequotedKeyInfo= NULL;
    m_szQuotealg= NULL;
}


Quote::~Quote()
{
}


bool  Quote::init(const char* szXMLQuote)
{
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    const char*           szA= NULL;
    
#ifdef QUOTETEST1
    fprintf(g_logFile, "init()\n");
#endif
    if(szXMLQuote==NULL)
        return false;
    
    if(!m_doc.Parse(szXMLQuote)) {
        fprintf(g_logFile, "Quote::init: Can't parse quote\n");
        return false;
    }   
    pRootElement= m_doc.RootElement();
    if(pRootElement==NULL) {
        fprintf(g_logFile, "Quote::init: Can't get root of quote\n");
        return false;
    }
    m_pNodeQuote= Search((TiXmlNode*) pRootElement, "Quote");
    if(m_pNodeQuote==NULL) {
        fprintf(g_logFile, "Quote::init: No Quote node\n");
        return false;
    }
    // <ds:QuoteMethod Algorithm=
    pNode=  Search(m_pNodeQuote, "ds:QuoteMethod");
    if(pNode==NULL) {
        fprintf(g_logFile, "Quote::init: No ds:QuoteMethod node\n");
        return false;
    }
    szA= ((TiXmlElement*) pNode)->Attribute ("Algorithm");
    if(szA==NULL) {
        fprintf(g_logFile, "Quote::init: No ds:QuoteMethod Algorithm\n");
        return false;
    }
    m_szQuotealg= strdup(szA);
    m_pNodeNonce= Search(m_pNodeQuote, "Nonce");
    m_pNodeCodeDigest= Search(m_pNodeQuote, "CodeDigest");
    if(m_pNodeCodeDigest==NULL) {
        fprintf(g_logFile, "Quote::init: No CodeDigest node\n");
        return false;
    }
    m_pNodeQuotedInfo= Search(m_pNodeQuote, "QuotedInfo");
    if(m_pNodeQuotedInfo==NULL) {
        fprintf(g_logFile, "Quote::init: No QuotedInfo node\n");
        return false;
    }
    m_pNodeQuoteValue= Search(m_pNodeQuotedInfo, "QuoteValue");
    if(m_pNodeQuoteValue==NULL) {
        fprintf(g_logFile, "Quote::init: No QuoteValue node\n");
        return false;
    }
    m_pNodequotedKeyInfo= Search(m_pNodeQuotedInfo, "ds:KeyInfo");
    pNode= m_pNodeQuoteValue->NextSibling();
    m_pNodequoteKeyInfo= Search(pNode, "ds:KeyInfo");

    return true;
}


char*  Quote::getCanonicalQuoteInfo()
{
    if(m_pNodeQuotedInfo==NULL)
        return NULL;
    return canonicalize(m_pNodeQuotedInfo);
}


char*  Quote::getQuoteValue()
{
    TiXmlNode* pNode= m_pNodeQuoteValue->FirstChild();
    if(pNode!=NULL)
        return strdup((pNode->Value()));
    return NULL;
}


char* Quote::getnonceValue()
{
    if(m_pNodeNonce==NULL)
        return NULL;
    TiXmlNode* pNode= m_pNodeNonce->FirstChild();
    if(pNode!=NULL)
        return strdup((pNode->Value()));
    return NULL;
}


char* Quote::getcodeDigest()
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


char* Quote::getquotekeyInfo()
{
    if(m_pNodequoteKeyInfo==NULL) {
        return NULL;
    }
    return canonicalize(m_pNodequoteKeyInfo);
}


char* Quote::getquotedkeyInfo()
{
    if(m_pNodequotedKeyInfo==NULL) {
        return NULL;
    }
    return canonicalize(m_pNodequotedKeyInfo);
}


char* Quote::getQuoteAlgorithm()
{
    if(m_szQuotealg==NULL)
        return NULL;
    // Fix
    return strdup(m_szQuotealg);
}


// ------------------------------------------------------------------



