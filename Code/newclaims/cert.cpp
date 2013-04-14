//
//  cert.cpp
//      John Manferdelli
//
//  Description: certificate class implementation
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
#include "cert.h"
#include "time.h"
#include "cryptoHelper.h"
#include "sha256.h"

#include <string.h>
#include <time.h>

//#include "policyglobals.h"


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
    const char*     szNotBefore= NULL;
    const char*     szNotAfter= NULL;

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
        fprintf(g_logFile, "parsePrincipalCertElementfromRoot: Cant find SignatureMethod\n");
        return false;
    }
    m_szSignatureMethod= strdup(((TiXmlElement*) pNode)->Attribute("Algorithm"));

    // fill m_szCanonicalizationMethod;
    pNode= Search(pSignedInfoNode, "ds:CanonicalizationMethod");
    if(pNode==NULL) {
        fprintf(g_logFile, "parsePrincipalCertElementfromRoot: Cant find CanonicalizationMethod\n");
        return false;
    }
    m_szCanonicalizationMethod= strdup(((TiXmlElement*) pNode)->Attribute("Algorithm"));

    // fill m_szRevocationInfo;
    pNode= Search(pSignedInfoNode, "RevocationPolicy");
    if(pNode==NULL) {
        fprintf(g_logFile, "parsePrincipalCertElementfromRoot: Cant find RevocationPolicy\n");
        return false;
    }

    // fill m_pSubjectKeyInfo;
    pNode= Search(pSignedInfoNode, "SubjectKey");
    if(pNode==NULL) {
        fprintf(g_logFile, "parsePrincipalCertElementfromRoot: Cant find SubjectKey\n");
        return false;
    }
    pSubjectKeyInfoNode= Search(pNode, "ds:KeyInfo");
    if(pSubjectKeyInfoNode==NULL) {
        fprintf(g_logFile, "parsePrincipalCertElementfromRoot: Cant find SubjectKey KeyInfo\n");
        return false;
    }

    m_pSubjectKeyInfo= RSAKeyfromKeyInfoNode(pSubjectKeyInfoNode);
    if(m_pSubjectKeyInfo==NULL) {
        fprintf(g_logFile, "parsePrincipalCertElementfromRoot: Cant init KeyInfo\n");
        return false;
    }

    // fill principal name
    pNode= Search(pSignedInfoNode, "SubjectName");
    if(pNode==NULL) {
        fprintf(g_logFile, "parsePrincipalCertElementfromRoot: Cant find Subject name\n");
        return false;
    }
    pNode1= ((TiXmlElement*)pNode)->FirstChild();
    if(pNode1!=NULL) {
        m_szPrincipalName= strdup(((TiXmlElement*)pNode1)->Value());
    }
    else {
        fprintf(g_logFile, "parsePrincipalCertElementfromRoot: Cant get subject name value\n");
        return false;
    }

    // fill m_ovalidityPeriod;
    pNode= Search((TiXmlNode*) pSignedInfoNode, "ValidityPeriod");
    if(pNode==NULL) {
        fprintf(g_logFile, "parsePrincipalCertElementfromRoot: Cant find Validity Period\n");
        return false;
    }
    pNode1= Search(pNode, "NotBefore");
    if(pNode1==NULL) {
        fprintf(g_logFile, "parsePrincipalCertElementfromRoot: Cant find NotBefore\n");
        return false;
    }
    pNode2= ((TiXmlElement*)pNode1)->FirstChild();
    if(pNode2!=NULL) {
        szNotBefore= ((TiXmlElement*)pNode2)->Value();
    }
    else {
        fprintf(g_logFile, "parsePrincipalCertElementfromRoot: Cant get NotBefore value\n");
        return false;
    }

    pNode1= Search(pNode, "NotAfter");
    if(pNode1==NULL) {
        fprintf(g_logFile, "parsePrincipalCertElementfromRoot: Cant find NotAfter\n");
        return false;
    }
    pNode2= ((TiXmlElement*)pNode1)->FirstChild();
    if(pNode2!=NULL) {
        szNotAfter= ((TiXmlElement*)pNode2)->Value();
    }
    else {
        fprintf(g_logFile, "parsePrincipalCertElementfromRoot: Cant get NotAftervalue\n");
        return false;
    }

    if(!timeInfofromstring(szNotBefore, m_ovalidityPeriod.notBefore)) {
        fprintf(g_logFile, "parsePrincipalCertElementfromRoot: Cant interpret NotBefore value\n");
        return false;
    }

    if(!timeInfofromstring(szNotAfter, m_ovalidityPeriod.notAfter)) {
        fprintf(g_logFile, "parsePrincipalCertElementfromRoot: Cant interpret NotAftervalue\n");
        return false;
    }

    // fill m_szSignatureValue;
    pNode= Search((TiXmlNode*) pRootElement, "ds:SignatureValue");
    if(pNode==NULL) {
        fprintf(g_logFile, "parsePrincipalCertElementfromRoot: Cant find SignatureValue\n");
        return false;
    }
    pNode1= ((TiXmlElement*)pNode)->FirstChild();
    if(pNode1) {
        m_szSignatureValue= strdup(((TiXmlElement*)pNode1)->Value());
    }
    else {
        fprintf(g_logFile, "parsePrincipalCertElementfromRoot: Cant get SignatureValue\n");
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


bool PrincipalCert::sameAs(PrincipalCert& oPrinc)
{
#if 1
    RSAKey* pKey1= (RSAKey*) getSubjectKeyInfo();
    RSAKey* pKey2= (RSAKey*) oPrinc.getSubjectKeyInfo();
    if(pKey1==NULL || pKey2==NULL)
        return false;
    return sameRSAKey(pKey1, pKey2);
#else
    return strcmp(getPrincipalName(), oPrinc.getPrincipalName())==0;
#endif
}


// ---------------------------------------------------------------------------


