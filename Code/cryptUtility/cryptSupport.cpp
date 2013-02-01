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
#include "cryptSupport.h"
#include "rsaHelper.h"
#include "sha256.h"
#include "sha1.h"
#include "tinyxml.h"

#include <string.h>


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


bool  PrincipalCert::init(char* szSig)
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
    char*           szTimePoint= NULL;

#ifdef CERTTEST
    fprintf(g_logFile, "parsePrincipalCertElementfromRoot\n");
#endif
    if(strcmp((char*)pRootElement->Value(), "ds:Signature")!=0) {
        fprintf(g_logFile, "Does not start with signature (%s)\n", (char*)pRootElement->Value());
        return false;
    }
     
    // make sure it's in signedinfo
    pSignedInfoNode= Search((TiXmlNode*) pRootElement, (char*)"ds:SignedInfo");
    if(pSignedInfoNode==NULL) {
        fprintf(g_logFile, "Cant find SignedInfo\n");
        return false;
    }

    // fill m_szSignedInfo;
    m_szSignedInfo= canonicalize(pSignedInfoNode);

    // fill m_szSignatureMethod;
    pNode= Search(pSignedInfoNode, (char*)"ds:SignatureMethod");
    if(pNode==NULL) {
        fprintf(g_logFile, "Cant find SignatureMethod\n");
        return false;
    }
    m_szSignatureMethod= strdup((char*)((TiXmlElement*) pNode)->Attribute("Algorithm"));


    // fill m_szCanonicalizationMethod;
    pNode= Search(pSignedInfoNode, (char*)"ds:CanonicalizationMethod");
    if(pNode==NULL) {
        fprintf(g_logFile, "Cant find CanonicalizationMethod\n");
        return false;
    }
    m_szCanonicalizationMethod= strdup((char*)((TiXmlElement*) pNode)->Attribute("Algorithm"));

    // fill m_szRevocationInfo;
    pNode= Search(pSignedInfoNode, (char*)"RevocationPolicy");
    if(pNode==NULL) {
        fprintf(g_logFile, "Cant find RevocationPolicy\n");
        return false;
    }

    // fill m_pSubjectKeyInfo;
    pNode= Search(pSignedInfoNode, (char*)"SubjectKey");
    if(pNode==NULL) {
        fprintf(g_logFile, "Cant find SubjectKey\n");
        return false;
    }
    pSubjectKeyInfoNode= Search(pNode, (char*)"ds:KeyInfo");
    if(pSubjectKeyInfoNode==NULL) {
        fprintf(g_logFile, "Cant find SubjectKey KeyInfo\n");
        return false;
    }

    if(!initRSAKeyFromKeyInfo(&m_pSubjectKeyInfo, pSubjectKeyInfoNode)) {
        fprintf(g_logFile, "Cant init KeyInfo\n");
        return false;
    }

    // fill principal name
    pNode= Search(pSignedInfoNode, (char*)"SubjectName");
    if(pNode==NULL) {
        fprintf(g_logFile, "Cant find Subject name\n");
        return false;
    }
    pNode1= ((TiXmlElement*)pNode)->FirstChild();
    if(pNode1!=NULL) {
        m_szPrincipalName= strdup((char*)((TiXmlElement*)pNode1)->Value());
    }
    else {
        fprintf(g_logFile, "Cant get subject name value\n");
        return false;
    }

    // fill m_ovalidityPeriod;
    pNode= Search((TiXmlNode*) pSignedInfoNode, (char*)"ValidityPeriod");
    if(pNode==NULL) {
        fprintf(g_logFile, "Cant find Validity Period\n");
        return false;
    }
    pNode1= Search(pNode, (char*)"NotBefore");
    if(pNode1==NULL) {
        fprintf(g_logFile, "Cant find NotBefore\n");
        return false;
    }
    pNode2= ((TiXmlElement*)pNode1)->FirstChild();
    if(pNode2) {
        szTimePoint= (char*)((TiXmlElement*)pNode2)->Value();
    }
    else {
        fprintf(g_logFile, "Cant get NotBefore value\n");
        return false;
    }

    if(!UTCtogmTime(szTimePoint, &m_ovalidityPeriod.notBefore)) {
        fprintf(g_logFile, "Cant interpret NotBefore value\n");
        return false;
    }
    pNode1= Search(pNode, (char*)"NotAfter");
    if(pNode1==NULL) {
        fprintf(g_logFile, "Cant find NotAfter\n");
        return false;
    }
    pNode2= ((TiXmlElement*)pNode1)->FirstChild();
    if(pNode2) {
        szTimePoint= (char*)((TiXmlElement*)pNode2)->Value();
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
    pNode= Search((TiXmlNode*) pRootElement, (char*)"ds:SignatureValue");
    if(pNode==NULL) {
        fprintf(g_logFile, "Cant find SignatureValue\n");
        return false;
    }
    pNode1= ((TiXmlElement*)pNode)->FirstChild();
    if(pNode1) {
        m_szSignatureValue= strdup((char*)((TiXmlElement*)pNode1)->Value());
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



