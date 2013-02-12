//
//  File: claims.cpp
//      John Manferdelli
//
//  Description:  Attestation and other claims
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
#include "rsaHelper.h"
#include "modesandpadding.h"
#include "aes.h"
#include "sha1.h"
#include "sha256.h"
#include "algs.h"
#include "secPrincipal.h"
#include "tao.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "claims.h"
#include "hashprep.h"
#include "tinyxml.h"

#include <time.h>
#include <string.h>


#define MAXREQUESTSIZE 16384


// ------------------------------------------------------------------------


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


// ------------------------------------------------------------------


char*   g_szNonceTemplate= (char*) "<nonce> %s </nonce>\n";
char*   g_szQuoteTemplate= (char*)
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


bool  Quote::init(char* szXMLQuote)
{
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    char*           szA= NULL;
    
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
    m_pNodeQuote= Search((TiXmlNode*) pRootElement, (char*)"Quote");
    if(m_pNodeQuote==NULL) {
        fprintf(g_logFile, "Quote::init: No Quote node\n");
        return false;
    }
    // <ds:QuoteMethod Algorithm=
    pNode=  Search(m_pNodeQuote, (char*)"ds:QuoteMethod");
    if(pNode==NULL) {
        fprintf(g_logFile, "Quote::init: No ds:QuoteMethod node\n");
        return false;
    }
    szA= (char*)((TiXmlElement*) pNode)->Attribute ("Algorithm");
    if(szA==NULL) {
        fprintf(g_logFile, "Quote::init: No ds:QuoteMethod Algorithm\n");
        return false;
    }
    m_szQuotealg= strdup(szA);
    m_pNodeNonce= Search(m_pNodeQuote, (char*)"Nonce");
    m_pNodeCodeDigest= Search(m_pNodeQuote, (char*)"CodeDigest");
    if(m_pNodeCodeDigest==NULL) {
        fprintf(g_logFile, "Quote::init: No CodeDigest node\n");
        return false;
    }
    m_pNodeQuotedInfo= Search(m_pNodeQuote, (char*)"QuotedInfo");
    if(m_pNodeQuotedInfo==NULL) {
        fprintf(g_logFile, "Quote::init: No QuotedInfo node\n");
        return false;
    }
    m_pNodeQuoteValue= Search(m_pNodeQuotedInfo, (char*)"QuoteValue");
    if(m_pNodeQuoteValue==NULL) {
        fprintf(g_logFile, "Quote::init: No QuoteValue node\n");
        return false;
    }
    m_pNodequotedKeyInfo= Search(m_pNodeQuotedInfo, (char*)"ds:KeyInfo");
    pNode= m_pNodeQuoteValue->NextSibling();
    m_pNodequoteKeyInfo= Search(pNode, (char*)"ds:KeyInfo");

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
        return strdup((char*)(pNode->Value()));
    return NULL;
}


char* Quote::getnonceValue()
{
    if(m_pNodeNonce==NULL)
        return NULL;
    TiXmlNode* pNode= m_pNodeNonce->FirstChild();
    if(pNode!=NULL)
        return strdup((char*)(pNode->Value()));
    return NULL;
}


char* Quote::getcodeDigest()
{
    if(m_pNodeCodeDigest==NULL)
        return NULL;

    char*   szCodeDigest= NULL;
    TiXmlNode* pNode= NULL;
    pNode= m_pNodeCodeDigest->FirstChild();

    if(pNode!=NULL) {
        szCodeDigest= (char*)pNode->Value();
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


bool RsaPkcsPadSignCheck(RSAKey* pKey, int hashType, byte* hash, int sizeSig, byte* sig)
{
    byte    rgPadded[RSA2048BYTEBLOCKSIZE];
    bnum    bnMsg(pKey->m_iByteSizeM/2);
    bnum    bnOut(pKey->m_iByteSizeM/2);

    // Fix: this is a vulnerability, since sizeSig is controlled by the XML
    // received from an external source and bnMsg.m_pValue is not necessarily
    // long enough to hold it. A remediation in this case would be to use the
    // min of sizeSig and the length of bnMsg.m_pValue (as long as both are
    // expressed in bytes). But a better solution would be to implement some
    // kind of buffer class that wraps memcpy and arrays so we don't have to
    // worry about this problem everywhere. E.g., bnum should have a method that
    // copies in a string, and a method that copies out to a buffer of a given
    // length.
    memcpy((byte*)bnMsg.m_pValue, sig, sizeSig);
    if(!mpRSAENC(bnMsg, *(pKey->m_pbnE), *(pKey->m_pbnM), bnOut))
        return false;
    revmemcpy(rgPadded, (byte*)bnOut.m_pValue, pKey->m_iByteSizeM);
    if(!emsapkcsverify(hashType, hash, sizeSig, rgPadded))
        return false;

    return true;
}


bool checkXMLSignature(char* szSigAlgorithm, char* szCanonicalSignedBody, 
                       KeyInfo* pKeyInfo, char* szSignatureValue)
{
    Sha256   oHash;
    byte     rgHash[SHA256DIGESTBYTESIZE];
    int      iOutLen= SHA256DIGESTBYTESIZE;
    byte     rgSignedValue[RSA2048BYTEBLOCKSIZE];
    int      hashType;

#ifdef TEST
    fprintf(g_logFile, "checkXMLSignature\n");
    fflush(g_logFile);
#endif

    if(pKeyInfo==NULL) {
        fprintf(g_logFile, "checkXMLSignature NULL key\n");
        return false;
    }
    if(szSigAlgorithm==NULL) {
        fprintf(g_logFile, "checkXMLSignature empty alg\n");
        return false;
    }

    if(strcmp(RSA2048SIGALG, szSigAlgorithm)==0 || 
       strcmp(RSA1024SIGALG, szSigAlgorithm)==0) {
        hashType= SHA256HASH;
        // hash signed body
        oHash.Init();
        oHash.Update((byte*) szCanonicalSignedBody, strlen(szCanonicalSignedBody));
        oHash.Final();
        oHash.GetDigest(rgHash);

        // decode signature value
        iOutLen= RSA2048BYTEBLOCKSIZE;
        if(!fromBase64(strlen(szSignatureValue), szSignatureValue, 
                       &iOutLen, rgSignedValue)) {
            fprintf(g_logFile, "checkXMLSignature: Cant base64 decode signature value\n");
            return false;
        }

#ifdef TEST1
        fprintf(g_logFile, "RsaPkcsPadSignCheck\n");
        fflush(g_logFile);
        ((RSAKey*) pKeyInfo)->printMe();
        fflush(g_logFile);
#endif
        return RsaPkcsPadSignCheck((RSAKey*) pKeyInfo, hashType, rgHash,
                                   iOutLen, rgSignedValue);
    }
    else {
        fprintf(g_logFile, "checkXMLSignature: Unsupported signature algorithm %s\n", 
                szSigAlgorithm);
        return false;
    }
}


bool checkXMLQuote(char* szQuoteAlg, char* szCanonicalQuotedBody, char* sznonce, 
                char* szdigest, KeyInfo* pKeyInfo, char* szQuoteValue)
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

    int     sizehashFinal= SHA256DIGESTBYTESIZE;
    byte    hashFinal[SHA256DIGESTBYTESIZE];

    int     hashType= 0;
    int     sizefinalHash= 0;

    byte    locality= 0; 
    u32     sizeversion= 0;
    byte*   versionInfo= NULL;
#ifdef PCR18
    byte pcrMask[3]= {0,0,0x6};  // pcr 17, 18
#else
    byte pcrMask[3]= {0,0,0x2};  // pcr 17
#endif

#ifdef TEST
    fprintf(g_logFile, "checkXMLQuote alg: %s\n", szQuoteAlg);
    fprintf(g_logFile, "checkXMLQuote sig value: %s\nSigner Keyinfo:\n", szQuoteValue);
    ((RSAKey*)pKeyInfo)->printMe();
#endif
    if(szQuoteAlg==NULL) {
        fprintf(g_logFile, "checkXMLQuote: empty alg\n");
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
        fprintf(g_logFile, "checkXMLQuote: Unsupported quote algorithm %s\n", szQuoteAlg);
        return false;
    }

    // get nonce
    if(sznonce!=NULL) {
        if(!fromBase64(strlen(sznonce), sznonce, &sizeNonce, nonce)) {
            fprintf(g_logFile, "checkXMLQuote: Cant base64 decode noncevalue\n");
            return false;
        }
    }
    else {
        sizeNonce= 0;
    }

    // hash body
    if(szCanonicalQuotedBody==NULL) {
        fprintf(g_logFile, "checkXMLQuote: empty body to quote\n");
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
        fprintf(g_logFile, "checkXMLQuote: invalid hash type\n");
        return false;
    }

    // get code hash
    if(szdigest==NULL) {
        fprintf(g_logFile, "checkXMLQuote: no code digest\n");
        return false;
    }
    if(!fromBase64(strlen(szdigest), szdigest, &sizehashCode, hashCode)) {
        fprintf(g_logFile, "checkXMLQuote: Cant base64 decode noncevalue\n");
        return false;
    }

    // decode quote value
    if(!fromBase64(strlen(szQuoteValue), szQuoteValue, &outLen, quoteValue)) {
        fprintf(g_logFile, "checkXMLQuote: Cant base64 code decode quote value\n");
        return false;
    }

    // generate final quote hash
    if(strcmp(QUOTEMETHODTPM12RSA2048, szQuoteAlg)==0 || strcmp(QUOTEMETHODTPM12RSA1024, szQuoteAlg)==0) {
#ifndef QUOTE2_DEFINED 
        if(!tpm12quoteHash(0, NULL, sizehashBody, hashBody,
                           sizehashCode, hashCode, hashFinal)) {
            fprintf(g_logFile, "checkXMLQuote: Cant compute TPM12 hash\n");
            return false;
        }
#else
         // reconstruct PCR composite and composite hash
        if(!tpm12quote2Hash(0, NULL, pcrMask, locality,
                            sizehashBody, hashBody, sizehashCode, hashCode, 
                            false, sizeversion, versionInfo, 
                            hashFinal)) {
            fprintf(g_logFile, "checkXMLQuote: Cant compute TPM12 hash\n");
            return false;
        }
#endif
        sizefinalHash= SHA1DIGESTBYTESIZE;
    }
    else if(strcmp(QUOTEMETHODSHA256FILEHASHRSA2048, szQuoteAlg)==0 || 
             strcmp(QUOTEMETHODSHA256FILEHASHRSA1024, szQuoteAlg)==0) {
        if(!sha256quoteHash(0, NULL, sizehashBody, hashBody,
                           sizehashCode, hashCode, hashFinal)) {
            fprintf(g_logFile, "checkXMLQuote: Cant compute sha256 hash\n");
            return false;
        }
        sizefinalHash= SHA256DIGESTBYTESIZE;
    }
    else {
        fprintf(g_logFile, "checkXMLQuote: Unsupported quote algorithm %s\n", szQuoteAlg);
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "checkXMLQuote hashtype: %d\n", hashType);
    PrintBytes((char*)"Code digest: ", hashCode, sizehashCode);
    PrintBytes((char*)"final hash: ", hashFinal, sizefinalHash);
    PrintBytes((char*)"quotevalue: ", quoteValue, outLen);
    fflush(g_logFile);
#endif

    return RsaPkcsPadSignCheck((RSAKey*) pKeyInfo, hashType, hashFinal,
                               outLen, quoteValue);
}


// -----------------------------------------------------------------------------


char* s_EvidenceListStart= (char*) "<EvidenceList count='%d'>\n";
char* s_EvidenceListStop= (char*) "</EvidenceList>\n";


char* consttoEvidenceList(char* szEvidence, char* szEvidenceSupport)
{

    if(szEvidence==NULL) {
        return NULL;
    }

    TiXmlDocument   listDoc;
    TiXmlNode*      pNode= NULL;
    int             numpiecesofEvidence= 0;
    int             len= strlen(szEvidenceSupport)+strlen(szEvidence)+128;
    char*           buf= (char*) malloc(len);
    char*           p= buf;
    int             left= len;
    int             n;
    char*           szNode= NULL;

    if(buf==NULL) {
        return NULL;
    }

    if(szEvidenceSupport==NULL) {
        // append szEvidence
        sprintf(buf, s_EvidenceListStart, 1);
        n= strlen(p);
        p+= n;
        left-= n;
        if(!safeTransfer(&p, &left, szEvidence)) {
            return NULL;
        }
        if(!safeTransfer(&p, &left, s_EvidenceListStop)) {
            return NULL;
        }
        return strdup(buf);
    }


    if(listDoc.Parse(szEvidenceSupport)) {
        return NULL;
    }

    TiXmlElement* pRootElement= listDoc.RootElement();
    pRootElement->QueryIntAttribute ("count", &numpiecesofEvidence);
    numpiecesofEvidence++;

    // append szEvidence
    sprintf(buf, s_EvidenceListStart, numpiecesofEvidence);
    n= strlen(p);
    p+= n;
    left-= n;
    if(!safeTransfer(&p, &left, szEvidence)) {
        return NULL;
    }

    // add evidence support
    pNode= pRootElement->FirstChild();
    while(pNode!=NULL) {
        if(pNode->Type()==TiXmlNode::TINYXML_ELEMENT) {
            szNode= canonicalize(pNode);
            if(szNode==NULL) {
                return NULL;
            }
            if(!safeTransfer(&p, &left, szEvidence)) {
                free(szNode);
                return NULL;
            }
            free(szNode);
            szNode= NULL;
        }
        pNode= pNode->NextSibling();
    }
    if(!safeTransfer(&p, &left, s_EvidenceListStop)) {
        return NULL;
    }
    return strdup(buf);
}


char* getSerializedKeyfromCert(char* szCert)
{
    TiXmlDocument doc;
    if(!doc.Parse(szCert)) {
        fprintf(g_logFile, "getSerializedKeyfromCert: cant parse cert\n");
        return NULL;
    }
    TiXmlElement*   pRootElement= doc.RootElement();
    if(pRootElement==NULL) {
        fprintf(g_logFile, "getSerializedKeyfromCert: Can't get root of quote\n");
        return NULL;
    }
    TiXmlNode* pNode= Search((TiXmlNode*) pRootElement, (char*)"ds:KeyInfo");
    if(pNode==NULL) {
        fprintf(g_logFile, "getSerializedKeyfromCert: No ds:KeyInfo node\n");
        return NULL;
    }
    return canonicalize(pNode);
}


char* keyInfofromKey(RSAKey* pKey)
{
    if(pKey==NULL)
        return NULL;
    return pKey->SerializePublictoString();
}


RSAKey* keyfromkeyInfo(char* szKeyInfo)
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


// <Quote format='xml'>
//     <nonce> </nonce>  (optional)
//     <CodeDigest alg='SHA256'>
//     </CodeDigest>
//     <QuotedInfo>
//         <ds:CanonicalizationMethod 
//          Algorithm="http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#"/>
//            <ds:QuoteMethod Algorithm="#"/>
//         <KeyInfo ...>
//     </QuotedInfo>
//     <QuoteValue>
//     </QuoteValue>
// </Quote>
char* encodeXMLQuote(int sizenonce, byte* nonce, int sizeCodeDigest, 
                     byte* codeDigest, char* szQuotedInfo, char* szKeyInfo, 
                     int sizeQuote, byte* quote)
{
    int     size= 4096;
    char    szB[4096];
    int     nsize= 512;
    char    szN[512];
    char*   szquoteValue= NULL;
    char*   szQuote= NULL;
    char*   szNonce= NULL;
    char*   szCodeDigest= NULL;
    char*   szdigestAlg= (char*) "SHA256";

    nsize= 256;
    if(sizenonce>0) {
        if(!toBase64(sizenonce, nonce, &nsize, szN)) {
            fprintf(g_logFile, "encodeXMLQuote: cant transform nonce to base64\n");
            goto cleanup;
        }
        sprintf(szB, g_szNonceTemplate, szN);
        szNonce= strdup(szB);
    }
    else
        szNonce= strdup("");

    nsize= 256;
    if(!toBase64(sizeCodeDigest, codeDigest, &nsize, szN)) {
        fprintf(g_logFile, "encodeXMLQuote: cant transform codeDigest to base64\n");
        goto cleanup;
    }
    szCodeDigest= strdup(szN);
    if(sizeCodeDigest==20)
        szdigestAlg= (char*) "SHA1";

    nsize= 512;
    if(!toBase64(sizeQuote, quote, &nsize, szN)) {
        fprintf(g_logFile, "encodeXMLQuote: cant transform quoted value to base64\n");
        goto cleanup;
    }
    szquoteValue= strdup(szN);

    sprintf(szB, g_szQuoteTemplate, szNonce, szdigestAlg, szCodeDigest, 
            szQuotedInfo, szquoteValue, szKeyInfo);
    szQuote= strdup(szB);

cleanup:
    if(szCodeDigest!=NULL) {
        free(szCodeDigest);
        szCodeDigest= NULL;
    }
    if(szquoteValue!=NULL) {
        free(szquoteValue);
        szquoteValue= NULL;
    }
    if(szNonce!=NULL) {
        free(szNonce);
        szNonce= NULL;
    }
#ifdef QUOTETEST
    fprintf(g_logFile, "encodeXMLQuote, %s, size: %d, quote\n%s\n", szdigestAlg, 
           sizeCodeDigest, szQuote);
#endif
    return szQuote;
}


// decode quote 
//      nonce
//      CodeDigest value and alg
//      canonicalized QuotedInfo
//      quoteValue
bool decodeXMLQuote(char* szXMLQuote, char** pszAlg, char** psznonce, 
                    char** pszDigest, char** pszQuotedInfo, char** pszQuoteValue, 
                    char** pszquoteKeyInfo, char** pszquotedKeyInfo)
{
    Quote   oQuote;

    if(!oQuote.init(szXMLQuote)) {
        fprintf(g_logFile, "decodeXMLQuote: cant init Quote\n");
        return false;
    }
    *pszAlg= oQuote.getQuoteAlgorithm();
    *pszQuotedInfo= oQuote.getCanonicalQuoteInfo();
    *pszQuoteValue= oQuote.getQuoteValue();
    *psznonce= oQuote.getnonceValue();
    *pszquoteKeyInfo= oQuote.getquotekeyInfo();
    *pszDigest= oQuote.getcodeDigest();
    *pszquotedKeyInfo= oQuote.getquotedkeyInfo();

    return true;
}


// ------------------------------------------------------------------


char*   g_szCertTemplate= (char*) 
"<ds:Signature>\n%s\n"\
"<ds:SignatureValue>\n%s\n</ds:SignatureValue>\n" \
"</ds:Signature>\n";


char*   formatCert(char* szSignedInfo, char* szSig)
{
    char    rgBuf[MAXREQUESTSIZE];

    if(szSignedInfo==NULL || szSig==NULL)
        return NULL;
    sprintf(rgBuf,g_szCertTemplate, szSignedInfo, szSig);
    return strdup(rgBuf);
}


char* g_szSignedInfo1= (char*)
"<ds:SignedInfo>\n"\
"    <ds:CanonicalizationMethod Algorithm=\"http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#\" />\n"\
"    <ds:SignatureMethod Algorithm=\"http://www.manferdelli.com/2011/Xml/algorithms/rsa1024-sha256-pkcspad#\" />\n"\
"    <Certificate Id=\"%s\" version='1'>\n"\
"        <SerialNumber>%d</SerialNumber>\n"\
"        <PrincipalType>%s</PrincipalType>\n"\
"        <IssuerName>%s</IssuerName>\n"\
"        <IssuerID>%d</IssuerID>\n";

char* g_szValidity= (char*)
"        <ValidityPeriod>\n"\
"            <NotBefore>%s</NotBefore>\n"\
"            <NotAfter>%s</NotAfter>\n"\
"        </ValidityPeriod>\n";

char* g_szSignedInfoDigest= (char*)
"        <CodeDigest>%s</CodeDigest>\n";

char* g_szSignedInfo2= (char*)
"        <SubjectName>%s</SubjectName>\n"\
"        <SubjectKey>\n";
char* g_szSignedInfo3= (char*)
" </SubjectKey>\n"\
"        <SubjectKeyID>%s</SubjectKeyID>\n"\
"        <RevocationPolicy>Local-check-only</RevocationPolicy>\n"\
"    </Certificate>\n"\
"</ds:SignedInfo>\n";


char*   formatSignedInfo(RSAKey* pKey, 
            char* szCertid, int serialNo, char* szPrincipalType, 
            char* szIssuerName, char* szIssuerID, char* szNotBefore, 
            char* szNotAfter, char* szSubjName, char* szKeyInfo, 
            char* szDigest, char* szSubjKeyID)
{
    char    szTemp[MAXREQUESTSIZE];
    char    rgBuf[MAXREQUESTSIZE];
    int     iLeft= MAXREQUESTSIZE;
    char*   p= rgBuf;
    int     n;
    char*   szSignedInfo= NULL;

#ifdef  TEST
    fprintf(g_logFile, "Format signedInfo\n");
#endif

    sprintf(szTemp, g_szSignedInfo1, szCertid, serialNo, 
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

    TiXmlDocument  doc;
    if(!doc.Parse(rgBuf)) {
        fprintf(g_logFile, "formatSignedInfo: can't parse document\n");
        return NULL;
    }

    szSignedInfo= canonicalize((TiXmlNode*)doc.RootElement());

#ifdef  QUOTETEST
    fprintf(g_logFile, "formatSignedInfo, Canonicalized: %s\n", szSignedInfo);
#endif
    return szSignedInfo;
}


// ------------------------------------------------------------------


