//
//  signedAssertion.cpp
//      John Manferdelli
//
//  Description: Signed Assertion support for access control
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
#include "jlmUtility.h"
#include "logging.h"
#include "jlmcrypto.h"
#include "signedAssertion.h"
#include "time.h"
#include "sha256.h"
#include "cryptoHelper.h"

#include <string.h>


// ------------------------------------------------------------------------


inline bool whitespace(char b)
{
    return(b==' ' || b=='\t' || b=='\r' || b=='\n');
}


int nextToken(const char* sz, const char** pszToken)
{
    int     n;

    if(sz==NULL)
        return -1;

    while(*sz!='\0') {
        if(!whitespace(*sz))
            break;
    sz++;
    }

    if(*sz=='\0')
        return -1;

    *pszToken= sz;
    n= 0;
    while(*sz!='\0' && !whitespace(*sz)) {
        sz++;
        n++;
    }
    return n;
}


Assertion::Assertion()
{
    m_szSubject= NULL;
    m_szRight= NULL;
    m_szObject= NULL;
}


Assertion::~Assertion()
{
    if(m_szSubject!=NULL) {
        free(m_szSubject);
        m_szSubject= NULL;
    }
    if(m_szRight!=NULL) {
        free(m_szRight);
        m_szRight= NULL;
    }
    if(m_szObject!=NULL) {
        free(m_szObject);
        m_szObject= NULL;
    }
}


#ifdef TEST
void Assertion::printMe()
{
    fprintf(g_logFile, "Assertion: %s %s %s\n",
            m_szSubject, m_szRight, m_szObject);

}
#endif


bool Assertion::parseMe(const char* szAssert)
{
    char            szBuf[512];     // FIX
    const char*     szTok= NULL;
    int             n;

#ifdef TEST
    fprintf(g_logFile, "Assertion::parseMe: %s\n", szAssert);
    fflush(g_logFile);
#endif
    n= nextToken(szAssert, &szTok);
    if(n<0 || n>=512)
        return false;
    memcpy(szBuf, szTok, n); 
    szBuf[n]= '\0';
    szAssert+= n;
    m_szSubject= strdup(szBuf);

    n= nextToken(szAssert, &szTok);
    if(n<0 || n>=512)
        return false;
    memcpy(szBuf, szTok, n); 
    szBuf[n]= '\0';
    szAssert+= n+1;
    m_szRight= strdup(szBuf);

    n= nextToken(szAssert, &szTok);
    if(n<0 || n>=512)
        return false;
    memcpy(szBuf, szTok, n); 
    szBuf[n]= '\0';
    szAssert+= n;
    m_szObject= strdup(szBuf);

   return true;
}


SignedAssertion::SignedAssertion()
{
    m_pRootElement= NULL;
    m_fDocValid= false;
    m_szSignature= NULL;
    m_szSignedInfo= NULL;
    m_szSignatureValue= NULL;
    m_szSignatureMethod= NULL;
    m_szCanonicalizationMethod= NULL;
    m_szRevocationInfo= NULL;
    m_pSignerKeyInfo= NULL;
    m_szPrincipalName= NULL;
    m_fSigValuesValid= false;
    m_pAssertion= NULL;
    m_pSubjectKeyInfo= NULL;

}


SignedAssertion::~SignedAssertion()
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
    m_fSigValuesValid= false;
}


bool  SignedAssertion::parseAssertion()
{
    TiXmlNode*  pSignedInfoNode= NULL;
    TiXmlNode*  pSignedGrant= NULL;
    TiXmlNode*  pAssertions= NULL;
    TiXmlNode*  pAssertion= NULL;
    const char* szAssertion= NULL;
    
#ifdef TEST
    fprintf(g_logFile, "SignedAssertion::parseAssertion\n");
    fflush(g_logFile);
#endif
    if(m_pRootElement==NULL) {
        fprintf(g_logFile, "SignedAssertion::parseAssertion: rootElement is NULL\n");
        return NULL;
    }
    // make sure it's in signedinfo
    pSignedInfoNode= Search((TiXmlNode*) m_pRootElement, "ds:SignedInfo");
    if(pSignedInfoNode==NULL) {
        fprintf(g_logFile, "SignedAssertion::parseAssertion: Cant find SignedInfo\n");
        return false;
    }
    pSignedGrant= Search(pSignedInfoNode, "SignedGrant");
    if(pSignedGrant==NULL) {
        fprintf(g_logFile, "SignedAssertion::parseAssertion: Cant find SignedGrant\n");
        return false;
    }
    pAssertions= Search(pSignedGrant, "Assertions");
    if(pAssertions==NULL) {
        fprintf(g_logFile, "SignedAssertion::parseAssertion: Cant find Assertions\n");
        return false;
    }
    pAssertion= Search(pAssertions, "Assertion");
    if(pAssertions==NULL) {
        fprintf(g_logFile, "SignedAssertion::parseAssertion: Cant find Assertion\n");
        return false;
    }

    // SignedGrant in ds:SignedInfo
    if(pAssertion==NULL || pAssertion->FirstChild()==NULL || pAssertion->FirstChild()==NULL) {
        return false;
    }
    szAssertion= pAssertion->FirstChild()->Value();

    // parse it
    m_pAssertion= new Assertion();
    if(!m_pAssertion->parseMe(szAssertion)) {
    fprintf(g_logFile, "SignedAssertion::parseAssertion: cant parse rule\n");
    return false;
    }
#ifdef TEST
    m_pAssertion->printMe();
    fflush(g_logFile);
#endif
    return true;
}


bool  SignedAssertion::init(const char* szSig)
{
#ifdef RULESTEST
    fprintf(g_logFile, "SignedAssertion::init %s\n", szSig);
#endif
    m_szSignature= strdup(szSig);
    return true;
}


char* SignedAssertion::getPrincipalName()
{
    return m_szPrincipalName;
}


char* SignedAssertion::getCanonicalizationMethod()
{
    return m_szCanonicalizationMethod;
}


#ifdef TEST
void  SignedAssertion::printMe()
{
    if(m_fSigValuesValid)
        fprintf(g_logFile, "Signed assertion signature valid\n");
    else
        fprintf(g_logFile, "Signed assertion signature invalid\n");
    if(m_fSigValuesValid)
        fprintf(g_logFile, "Signature: %s\n", m_szSignature);
    if(m_fSigValuesValid)
        fprintf(g_logFile, "Signed Info: %s\n", m_szSignedInfo);
    else
    if(m_fSigValuesValid)
        fprintf(g_logFile, "SignatureValue: %s\n", m_szSignatureValue);
    else
    if(m_szSignatureMethod!=NULL)
        fprintf(g_logFile, "SignatureMethod: %s\n", m_szSignatureMethod);
    else
    if(m_szCanonicalizationMethod!=NULL)
        fprintf(g_logFile, "CanonicalizationMethod: %s\n", m_szCanonicalizationMethod);
    else
        fprintf(g_logFile, "SignatureMethod: NULL\n");
    if(m_szPrincipalName!=NULL)
        fprintf(g_logFile, "PrincipalName: %s\n", m_szPrincipalName);
    else
        fprintf(g_logFile, "PrincipalName: NULL\n");
    if(m_szRevocationInfo!=NULL)
        fprintf(g_logFile, "Revocation: %s\n", m_szRevocationInfo);
    else
        fprintf(g_logFile, "Revocation: NULL\n");
    if(m_pAssertion!=NULL)
        m_pAssertion->printMe();
    else
        fprintf(g_logFile, "No assertions\n");
}
#endif


char* SignedAssertion::getGrantSubject()
{
    if(m_pAssertion==NULL) {
        if(!parseAssertion()) {
            return NULL;
        }
    }
    if(m_pAssertion!=NULL)
        return m_pAssertion->m_szSubject;
    return NULL;
}


char* SignedAssertion::getGrantRight()
{
    if(m_pAssertion==NULL) {
        if(!parseAssertion()) {
            return NULL;
        }
    }
    if(m_pAssertion!=NULL)
        return m_pAssertion->m_szRight;
    return NULL;
}


char* SignedAssertion::getGrantObject()
{
    if(m_pAssertion==NULL) {
        if(!parseAssertion()) {
            return NULL;
        }
    }
    if(m_pAssertion!=NULL)
        return m_pAssertion->m_szObject;
    return NULL;
}


bool SignedAssertion::parseSignedAssertionElements()
{
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;
    TiXmlNode*      pNode2= NULL;
    TiXmlNode*      pNodeA= NULL;
    TiXmlNode*      pSignedInfoNode= NULL;
    char*           szTimePoint;

#ifdef RULESTEST
    fprintf(g_logFile, "SignedAssertion::parseSignedAssertionElements()\n");
#endif
    if(m_szSignature==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: No signature document\n");
        return false;
    }

    if(!m_doc.Parse(m_szSignature)) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant parse document from file string\n");
        return false;
    }
    m_fDocValid= true;

    m_pRootElement= m_doc.RootElement();
    if(m_pRootElement==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant get root element of SignedAssertion\n");
        return false;
    }
     
    // make sure it's in signedinfo
    pSignedInfoNode= Search((TiXmlNode*) m_pRootElement, "ds:SignedInfo");
    if(pSignedInfoNode==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find SignedInfo\n");
        return false;
    }

    // fill m_szSignedInfo;
    m_szSignedInfo= canonicalize(pSignedInfoNode);


    // fill m_szSignatureMethod;
    pNode= Search(pSignedInfoNode, "ds:SignatureMethod");
    if(pNode==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find SignatureMethod\n");
        return false;
    }
    m_szSignatureMethod= strdup(((TiXmlElement*) pNode)->Attribute("Algorithm"));

    // fill m_szPrincipalName
    pNode= Search(pSignedInfoNode, "SubjectName");
    if(pNode==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find SubjectName\n");
        return false;
    }
    pNode1= ((TiXmlElement*)pNode)->FirstChild();
    if(pNode1!=NULL) {
        m_szPrincipalName= strdup(((TiXmlElement*)pNode1)->Value());
    }

    // fill m_szCanonicalizationMethod;
    pNode= Search(pSignedInfoNode, "ds:CanonicalizationMethod");
    if(pNode==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find CanonicalizationMethod\n");
        return false;
    }
    m_szCanonicalizationMethod= strdup(((TiXmlElement*) pNode)->Attribute("Algorithm"));

    // fill m_szRevocationInfo;
    pNode= Search(pSignedInfoNode, "RevocationPolicy");
    if(pNode==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find RevocationPolicy\n");
        return false;
    }

    // fill m_ovalidityPeriod;
    pNode= Search((TiXmlNode*) pSignedInfoNode, "ValidityPeriod");
    if(pNode==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find Validity Period\n");
        return false;
    }
    pNode1= Search(pNode, "NotBefore");
    if(pNode1==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find NotBefore\n");
        return false;
    }
    pNode2= ((TiXmlElement*)pNode1)->FirstChild();
    if(pNode2) {
        szTimePoint= strdup(((TiXmlElement*)pNode2)->Value());
    }
    else {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant get NotBefore value\n");
        return false;
    }
    if(!timeInfofromstring(szTimePoint, m_ovalidityPeriod.notBefore)) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant interpret NotBefore value\n");
        return false;
    }
    pNode1= Search(pNode, "NotAfter");
    if(pNode1==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find NotAfter\n");
        return false;
    }
    pNode2= ((TiXmlElement*)pNode1)->FirstChild();
    if(pNode2) {
        szTimePoint= strdup(((TiXmlElement*)pNode2)->Value());
    }
    else {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant get NotAftervalue\n");
        return false;
    }
    if(!timeInfofromstring(szTimePoint, m_ovalidityPeriod.notAfter)) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant interpret NotAftervalue\n");
        return false;
    }

    // fill m_szSignatureValue;
    pNode= Search((TiXmlNode*) m_pRootElement, "ds:SignatureValue");
    if(pNode==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find SignatureValue\n");
        return false;
    }
    pNode1= ((TiXmlElement*)pNode)->FirstChild();
    if(pNode1!=NULL) {
        m_szSignatureValue= strdup(((TiXmlElement*)pNode1)->Value());
    }
    else {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant get SignatureValue\n");
        return false;
    }

    // Assertions
    pNodeA= Search((TiXmlNode*) pSignedInfoNode, "Assertions");
    if(pNodeA==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find Assertions\n");
        return false;
    }
#if 0   // FIX
    ((TiXmlElement*)pNodeA)->QueryIntAttribute ("count", &m_iNumAssertions);

    int     iAssertions= 0;
    m_rgszAssertion=  (char**)malloc(sizeof(char*)*m_iNumAssertions);
    if(m_rgszAssertion==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant allocate Assertions\n");
        return false;
    }
    pNode= pNodeA->FirstChild();
    while(pNode!=NULL) {
        if(pNode->Type()==TiXmlNode::TINYXML_ELEMENT) {
            if(strcmp(((TiXmlElement*)pNode)->Value(),"Assertion")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1==NULL) {
                    fprintf(g_logFile, "parseSignedAssertionElements: Bad assertion\n");
                    return false;
                }
            m_rgszAssertion[iAssertions]= strdup(pNode1->Value());
            iAssertions++;
            }
        }
        pNode= pNode->NextSibling();
    }

    if(m_iNumAssertions!=iAssertions) {
        fprintf(g_logFile, "parseSignedAssertionElements: Count mismatch in assertions %d %d\n", m_iNumAssertions, iAssertions);
        return false;
    }
#endif

    m_fSigValuesValid= true;
#ifdef RULESTEST
    fprintf(g_logFile, "parseSignedAssertionElements returning true\n");
#endif
    return true;
}


extern void copyTime(tm& from, tm& to);


bool SignedAssertion::getvalidityPeriod(Period& period)
{
    copyTime(m_ovalidityPeriod.notBefore, period.notBefore);
    copyTime(m_ovalidityPeriod.notAfter, period.notAfter);
    return true;
}


char*    SignedAssertion::getCanonicalwasSigned()
{
    return m_szSignedInfo;
}


char*    SignedAssertion::getRevocationPolicy()
{
    return m_szRevocationInfo;
}


char*    SignedAssertion::getSignatureValue()
{
    return m_szSignatureValue;
}


char*    SignedAssertion::getSignatureAlgorithm()
{
    return m_szSignatureMethod;
}


KeyInfo*    SignedAssertion::getSubjectKeyInfo()
{
#ifdef TEST
    fprintf(g_logFile, "SignedAssertion::getSubjectKeyInfo: %08x\n", m_pSubjectKeyInfo);
    fflush(g_logFile);
#endif
    return m_pSubjectKeyInfo;
}


// ---------------------------------------------------------------------------


