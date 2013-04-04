//
//  validateEvidence.cpp
//      John Manferdelli
//
//  Description: evidence validation implementation
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
#include "validateEvidence.h"
#include "time.h"
#include "cryptoHelper.h"
#include "sha256.h"

#include "policyglobals.h"

#include <string.h>


// ------------------------------------------------------------------------



// -------------------------------------------------------------------------------


bool  revoked(const char* szCert, const char* szPolicy)
{
    return false;
}


bool checktimeinInterval(tm& time, tm& begin, tm& end)
{
    long long int iBegin;
    long long int iMiddle;
    long long int iEnd;
    
    iBegin=begin.tm_year*(3600L*24L*31L*366)+begin.tm_mon*(3600L*24L*31L)+
           begin.tm_mday*(3600L*24L)+ begin.tm_hour*3600L+ begin.tm_min*60L+ begin.tm_sec;
    iMiddle=time.tm_year*(3600L*24L*31L*366)+time.tm_mon*(3600L*24L*31L)+
           time.tm_mday*(3600L*24L)+ time.tm_hour*3600L+ time.tm_min*60L+ time.tm_sec;
    iEnd=end.tm_year*(3600L*24L*31L*366)+end.tm_mon*(3600L*24L*31L)+
           end.tm_mday*(3600L*24L)+ end.tm_hour*3600L+ end.tm_min*60L+ end.tm_sec;
    if(iBegin<=iMiddle && iMiddle<=iEnd)
        return true;
    return false;
}


int VerifyEvidence(tm* pt, int iEvidenceType, void* pEvidence, 
                    int parentEvidenceType, void* pparentEvidence,
                    bool (*pRevoke)(const char*, const char*))
{
    KeyInfo*            pmyKeyInfo= NULL;
    KeyInfo*            pParentKeyInfo= NULL;
    PrincipalCert*      pSignature= NULL;
    PrincipalCert*      pparentSignature= NULL;
    SignedAssertion*    pAssertion= NULL;
    SignedAssertion*    pparentAssertion= NULL;
    Period              period;
    char*               szCanonicalSignedBody= NULL;
    char*               szCert= NULL;
    char*               szRevocationPolicy= NULL;
    char*               szSigAlgorithm= NULL;
    char*               szSignatureValue= NULL;

#ifdef TEST
    fprintf(g_logFile, "VerifyEvidence me: %d parent: %d\n", 
            iEvidenceType, parentEvidenceType);
    fflush(g_logFile);
#endif
    switch(iEvidenceType) {
      case NOEVIDENCE:
      default:
        return INVALIDEVIDENCE;
      case KEYINFO:
        return INVALIDEVIDENCE;
      case PRINCIPALCERT:
        pSignature= (PrincipalCert*) pEvidence;
        if(pSignature==NULL)
            return INVALIDEVIDENCE;
        pmyKeyInfo= pSignature->getSubjectKeyInfo();
        if(!pSignature->getvalidityPeriod(period))
            return INVALIDPERIOD;
        // now check time
        if(!checktimeinInterval(*pt,period.notBefore,period.notAfter)) {
            fprintf(g_logFile, "Not in interval\n");
            return INVALIDPERIOD;
        }
        szCanonicalSignedBody= pSignature->getCanonicalwasSigned();
#ifdef CERTTEST
        fprintf(g_logFile, "Canonicalized size: %d\n", (int)strlen(szCanonicalSignedBody));
#endif
        if(szCanonicalSignedBody==NULL)
            return INVALIDEVIDENCE;
        szRevocationPolicy= pSignature->getRevocationPolicy();
        if(szRevocationPolicy==NULL) {
            if(pRevoke(szCert, szRevocationPolicy))
                return INVALIDREVOKED;
        }
        szSignatureValue= pSignature->getSignatureValue();
        if(szSignatureValue==NULL)
            return INVALIDSIG;
        szSigAlgorithm= pSignature->getSignatureAlgorithm();
        if(szSigAlgorithm==NULL)
            return INVALIDSIG;
        break;
      case SIGNEDGRANT:
        pAssertion= (SignedAssertion*) pEvidence;
        if(pAssertion==NULL)
            return INVALIDEVIDENCE;
        pmyKeyInfo= pAssertion->getSubjectKeyInfo();
        if(!pAssertion->getvalidityPeriod(period))
            return INVALIDPERIOD;
        // now check time
        if(!checktimeinInterval(*pt,period.notBefore,period.notAfter)) {
            fprintf(g_logFile, "Not in interval\n");
            return INVALIDPERIOD;
        }
        szCanonicalSignedBody= pAssertion->getCanonicalwasSigned();
        if(szCanonicalSignedBody==NULL)
            return INVALIDEVIDENCE;
        szRevocationPolicy= pAssertion->getRevocationPolicy();
        if(szRevocationPolicy==NULL) {
            if(pRevoke(szCert, szRevocationPolicy))
                return INVALIDREVOKED;
        }
        szSignatureValue= pAssertion->getSignatureValue();
        if(szSignatureValue==NULL)
            return INVALIDSIG;
        szSigAlgorithm= pAssertion->getSignatureAlgorithm();
        if(szSigAlgorithm==NULL)
            return INVALIDSIG;
#ifdef RULESTEST
        fprintf(g_logFile, "Signed grant\n");
        pAssertion->printMe();
        fprintf(g_logFile, "\n");
#endif
        break;
    }

#ifdef TEST
    fprintf(g_logFile, "examining parent evidence type\n");
    fflush(g_logFile);
#endif
    switch(parentEvidenceType) {
      case NOEVIDENCE:
        break;      // must be root
      default:
        return INVALIDEVIDENCE;

      case PRINCIPALCERT:
        pparentSignature= (PrincipalCert*) pparentEvidence;
        pParentKeyInfo=  pparentSignature->getSubjectKeyInfo();
        break;

      case SIGNEDGRANT:
        pparentAssertion= (SignedAssertion*) pparentEvidence;
        pParentKeyInfo=  pparentAssertion->getSubjectKeyInfo();
        break;
        
      case EMBEDDEDPOLICYPRINCIPAL:
      case KEYINFO:
#ifdef TEST
        fprintf(g_logFile, "embedded policy principal\n");
        fflush(g_logFile);
#endif
        pParentKeyInfo= (KeyInfo*) pparentEvidence;
        break;
    }

    UNUSEDVAR(pmyKeyInfo);

    if(!checkXMLSignature(szSigAlgorithm, szCanonicalSignedBody, 
                          pParentKeyInfo, szSignatureValue))
        return INVALIDSIG;
#ifdef TEST
    fprintf(g_logFile, "VerifyEvidence returns true\n");
    fflush(g_logFile);
#endif
    return VALID;
}


int VerifyEvidenceList(tm* pt, int npiecesEvidence, int* rgEvidenceType, 
                        void** rgEvidence, RSAKey* pRootKey, RSAKey* pTopKey)
//
//  This checks signatures, time based validity and revocation
//      but not specific purpose or grant use.
//  Only RSA is supported for now.
//
{
    int         i;
    int         iError;
    int         iParentType;
    void*       pParent;
    int         iMyType;
    void*       pMe;
    time_t      timer;

#ifdef TEST
    fprintf(g_logFile, "VerifyEvidenceList %d\n", npiecesEvidence);
    fflush(g_logFile);
#endif
    // now if not specified
    if(pt==NULL) {
        time(&timer);
        pt= gmtime((const time_t*)&timer);
    }

    // must root in policy key
    if(rgEvidenceType[npiecesEvidence-1]!=EMBEDDEDPOLICYPRINCIPAL) {
        fprintf(g_logFile, "No embedded policy principal\n");
        return INVALIDPRINCIPAL;
    }

    KeyInfo*            pParentKeyInfo= NULL;
    PrincipalCert*      pparentSignature= NULL;
    // check prior key?
    if(pTopKey!=NULL) {
        iParentType= rgEvidenceType[0];
        pParent= rgEvidence[0];
        switch(iParentType) {
          case NOEVIDENCE:
            return INVALIDEVIDENCE;
          default:
            return INVALIDEVIDENCE;

          case PRINCIPALCERT:
            pparentSignature= (PrincipalCert*) pParent;
            pParentKeyInfo=  pparentSignature->getSubjectKeyInfo();
          break;

          case EMBEDDEDPOLICYPRINCIPAL:
          case KEYINFO:
            pParentKeyInfo=  (KeyInfo*) pParent;
            break;
        }
        if(!sameRSAKey((RSAKey*)pTopKey, (RSAKey*)pParentKeyInfo))
            return INVALIDEVIDENCE;
    }

    // verify
    for(i=0;i<(npiecesEvidence-1);i++) {
        iParentType= rgEvidenceType[i+1];
        pParent= rgEvidence[i+1];
        iMyType= rgEvidenceType[i];
        pMe= rgEvidence[i];
        iError=  VerifyEvidence(pt, iMyType, pMe, iParentType, pParent, revoked);
        if(iError<0) {
            fprintf(g_logFile, "Verify error %d\n", iError);
            return iError;
        }
    }

#ifdef TEST
    fprintf(g_logFile, "VerifyEvidenceList returns true\n");
    fflush(g_logFile);
#endif
    return VALID;
}


// -----------------------------------------------------------------------------


const char* s_EvidenceListStart= "<EvidenceList count='%d'>\n";
const char* s_EvidenceListStop= "</EvidenceList>\n";


char* consttoEvidenceList(const char* szEvidence, const char* szEvidenceSupport)
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


// ----------------------------------------------------------------------------


evidenceCollection::~evidenceCollection()
{
}


evidenceCollection::evidenceCollection()
{
    m_fParsed= false;
    m_fValid= false;
    m_iNumEvidenceLists= 0;
    m_rgiCollectionTypes= m_rgistaticCollectionTypes;
    m_rgCollectionList= m_rgstaticCollectionList;
}


bool evidenceCollection::parseEvidenceCollection(const char* szEvidenceCollection)
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    const char*           szElt= NULL;
    evidenceList*   pEvidenceList= NULL;
    int             n= 0;

    if(!doc.Parse(szEvidenceCollection)) {
        fprintf(g_logFile, "Can't parse Evidence Collection\n");
        return false;
    }

    pRootElement= doc.RootElement();
    pRootElement->QueryIntAttribute ("count", &m_iNumEvidenceLists);
    if(m_iNumEvidenceLists>STATICNUMCOLLECTIONELTS) {
        fprintf(g_logFile, "Too many collection elements\n");
        return false;
    }

    pNode= pRootElement->FirstChild();
    while(pNode!=NULL) {
        szElt= ((TiXmlElement*)pNode)->Value();
        if(strcmp(szElt,"EvidenceList")==0) {
            pEvidenceList= new evidenceList();
            if(!pEvidenceList->parseEvidenceList((TiXmlElement*)pNode)) {
                return false;
            }
            m_rgiCollectionTypes[n]= pEvidenceList->m_rgiEvidenceTypes[0];
            m_rgCollectionList[n]= pEvidenceList;
            if(n>=STATICNUMCOLLECTIONELTS) {
                fprintf(g_logFile, "Too many collection elements\n");
                return false;
            }
            n++;
        }
        pNode= pNode->NextSibling();
    }

    if(n!=m_iNumEvidenceLists) {
        fprintf(g_logFile, "Evidence collection mismatch %d %d\n", n, m_iNumEvidenceLists);
        return false;
    }

    m_fParsed= true;
    return m_fParsed;
}


bool evidenceCollection::validateEvidenceCollection(RSAKey* pRootKey)
{
    int     i;

    for(i=0;i<m_iNumEvidenceLists; i++) {
        if(!m_rgCollectionList[i]->validateEvidenceList(pRootKey, NULL)) {
            fprintf(g_logFile, "Failing on %d\n",i);
            return false;
        }
    }
    m_fValid= true;
    return m_fValid;
}


evidenceList::evidenceList()
{
    m_fParsed= false;
    m_fValid= false;
    m_iNumPiecesofEvidence= 0;
    m_rgiEvidenceTypes= m_rgistaticEvidenceTypes;
    m_rgEvidence= m_rgstaticEvidence;
}


evidenceList::~evidenceList()
{
}


bool    evidenceList::parseEvidenceList(TiXmlElement* pRootElement)
{
    TiXmlNode*          pNode= NULL;
    TiXmlNode*          pNode1= NULL;
    int                 n= 0;
    char*               szEvidence= NULL;
    PrincipalCert*      pCert= NULL;
    SignedAssertion*    pAssert= NULL;

    if(strcmp(pRootElement->Value(),"EvidenceList")!=0) {
        fprintf(g_logFile, "Should be EvidenceList %s\n", pRootElement->Value());
        return false;
    }
    pRootElement->QueryIntAttribute ("count", &m_iNumPiecesofEvidence);
    if(m_iNumPiecesofEvidence>STATICNUMLISTELTS) {
        fprintf(g_logFile, "Too many list elements\n");
        return false;
    }

    pNode= pRootElement->FirstChild();
    while(pNode!=NULL) {
        // find EvidenceType
        if((pNode1=Search(pNode, "SignedGrant"))!=NULL) {
            m_rgiEvidenceTypes[n]= SIGNEDGRANT;
        }
        else if((pNode1=Search(pNode, "Certificate"))!=NULL) {
            m_rgiEvidenceTypes[n]= PRINCIPALCERT;
        }
        else {
            fprintf(g_logFile, "Unknown evidence type\n");
            return false;
        }
        if(n>=STATICNUMLISTELTS) {
            fprintf(g_logFile, "Too many collection elements\n");
            return false;
        }

        // parse Evidence
        szEvidence= canonicalize(pNode);
        switch(m_rgiEvidenceTypes[n]) {
          case SIGNEDGRANT:
            pAssert= new SignedAssertion();
            if(!pAssert->init(szEvidence)) {
                fprintf(g_logFile, "Can't init SignedAssertion\n");
                return false;
            }
            if(!pAssert->parseSignedAssertionElements()) {
                fprintf(g_logFile, "Can't parse SignedAssertion\n");
                return false;
            }
            m_rgEvidence[n]= (void*) pAssert;
            break;
          case PRINCIPALCERT:
            pCert= new PrincipalCert();
            if(!pCert->init(szEvidence)) {
                fprintf(g_logFile, "Can't init PrincipalCertElements\n");
                return false;
            }
            if(!pCert->parsePrincipalCertElements()) {
                fprintf(g_logFile, "Can't parse PrincipalCertElements\n");
                return false;
            }
            m_rgEvidence[n]= (void*) pCert;
            break;
          default:
           fprintf(g_logFile, "Unknown Evidence type 1\n");
            return false;
        }
        free(szEvidence);
        szEvidence= NULL;
        n++;
        pNode= pNode->NextSibling();
    }

    if(n!=m_iNumPiecesofEvidence) {
        fprintf(g_logFile, "Evidence list mismatch %d %d\n", n, m_iNumPiecesofEvidence);
        return false;
    }

    m_fParsed= true;
    return m_fParsed;
}


bool    evidenceList::validateEvidenceList(RSAKey* pRootKey, RSAKey* pTopKey)
{
    int             iVerify;

#ifdef TEST
    fprintf(g_logFile, "evidenceList::validateEvidenceList()\n");
#endif

    if(!m_fParsed) {
        fprintf(g_logFile, "Evidence List not parsed\n");
        return false;
    }

    if(pRootKey==NULL) {
        fprintf(g_logFile, "Policy principal key is NULL\n");
        return false;
    }

    if(m_iNumPiecesofEvidence<STATICNUMLISTELTS) {
        m_rgiEvidenceTypes[m_iNumPiecesofEvidence]= EMBEDDEDPOLICYPRINCIPAL;
        m_rgEvidence[m_iNumPiecesofEvidence]= pRootKey;
        m_iNumPiecesofEvidence++;
    }
    else {
        fprintf(g_logFile, "Too many list elements\n");
        return false;
    }

    iVerify= VerifyEvidenceList(NULL, m_iNumPiecesofEvidence, m_rgiEvidenceTypes,
                                (void**) m_rgEvidence, pRootKey, pTopKey);
    if(iVerify>0)
        m_fValid= true;
    else
        m_fValid= false;

#ifdef TEST
    if(m_fValid)
        fprintf(g_logFile, "evidenceList::validateEvidenceList() returns true\n");
    else
        fprintf(g_logFile, "evidenceList::validateEvidenceList() returns false\n");
    fflush(g_logFile);
#endif
    return m_fValid;
}


// -------------------------------------------------------------------------------


