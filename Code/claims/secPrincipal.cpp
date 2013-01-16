//
//  secPrincipal.cpp
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
#include "secPrincipal.h"
#include "vault.h"
#include "claims.h"
#include "time.h"
#include "rsaHelper.h"
#include "sha256.h"

#include "policyglobals.h"

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


// -------------------------------------------------------------------------------


bool  revoked(char* szCert, char* szPolicy)
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
                    bool (*pRevoke)(char*, char*))
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

    return VALID;
}


// -------------------------------------------------------------------------------


accessPrincipal::accessPrincipal()
{
    m_szPrincipalName= NULL;
    m_uPrincipalType= 0; 
    m_fValidated= false;
    m_pCert= NULL;
}


accessPrincipal::~accessPrincipal()
{
}


bool accessPrincipal::Deserialize(byte* szObj, int* pi)
{
    byte*               sz= szObj;
    int                 iTotal= 0;
    int                 n;
    PrincipalCert*      pCert= NULL;
    char*               p= NULL;

#ifdef TEST
    fprintf(g_logFile, "accessPrincipal Deserialize\n");
    fflush(g_logFile);
#endif
    m_szPrincipalName= strdup((char*)sz);
    n= strlen(m_szPrincipalName)+1;
    sz+= n;
    iTotal+= n;

    memcpy(&m_uPrincipalType, sz, sizeof(u32));
    sz+= sizeof(u32);
    iTotal+= sizeof(u32);

    memcpy(&m_fValidated, sz, sizeof(bool));
    sz+= sizeof(bool);
    iTotal+= sizeof(bool);

    p= strdup((char*) sz);
    n= strlen(p)+1;
    sz+= n;
    iTotal+= n;
    pCert= new PrincipalCert();
    if(!pCert->init(p)) {
        fprintf(g_logFile, "Can't find cert for %s in Deserialize\n", m_szPrincipalName);
        return false;
    }
    m_pCert= pCert;
    if(!pCert->parsePrincipalCertElements()) {
        fprintf(g_logFile, "Can't parse cert for %s in Deserialize\n", m_szPrincipalName);
        return false;
    }

    *pi= iTotal;
#ifdef TEST
    printMe();
    fflush(g_logFile);
#endif
    return true;
}


int accessPrincipal::Serialize(byte* szObj)
{
    byte*       sz= szObj;
    int         iTotal= 0;
    int         n;

#ifdef CERTTEST
    fprintf(g_logFile, "accessPrincipal Serialize\n");
#endif
    n= strlen(m_szPrincipalName)+1;
    memcpy(sz, m_szPrincipalName, n);
    sz+= n;
    iTotal+= n;

    memcpy(sz, &m_uPrincipalType, sizeof(u32));
    sz+= sizeof(u32);
    iTotal+= sizeof(u32);

    memcpy(sz, &m_fValidated, sizeof(bool));
    sz+= sizeof(bool);
    iTotal+= sizeof(bool);

    n= strlen(m_pCert->m_szSignature)+1;
    memcpy(sz, m_pCert->m_szSignature, n);
    sz+= n;
    iTotal+= n;

   return iTotal;
}


char*   accessPrincipal::getName()
{
    return m_szPrincipalName;
}


int   accessPrincipal::auxSize()
{
    int                     iTotal= 0;
    PrincipalCert*          pCert= NULL;

    iTotal+= strlen(m_szPrincipalName)+1;
    iTotal+= sizeof(bool)+sizeof(u32);     // validates+principaltype
    pCert= m_pCert;
    iTotal+= strlen(pCert->m_szSignature)+1;
    return iTotal;
}


void  accessPrincipal::printMe()
{
    if(m_szPrincipalName!=NULL) {
        fprintf(g_logFile, "\tPrincipal Name: %s\n", m_szPrincipalName);
    }
    fprintf(g_logFile, "\tPrincipal type: %d\n", m_uPrincipalType);
    if(m_fValidated)
        fprintf(g_logFile, "\tPrincipal validated\n");
    else
        fprintf(g_logFile, "\tPrincipal NOT validated\n");
    //  m_pCert;
    return;
}


accessPrincipal* principalFromCert(PrincipalCert* pCert, bool fValidated)
{
    accessPrincipal*    pPrinc= NULL;

    pPrinc= new accessPrincipal();
    if(pPrinc==NULL) {
        return NULL;
    }
    pPrinc->m_szPrincipalName= strdup(pCert->getPrincipalName());
    pPrinc->m_uPrincipalType= USERPRINCIPAL;
    pPrinc->m_fValidated= fValidated;
    pPrinc->m_pCert= pCert;
        
   return pPrinc;
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


bool evidenceCollection::parseEvidenceCollection(char* szEvidenceCollection)
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    char*           szElt= NULL;
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
        szElt= (char*)((TiXmlElement*)pNode)->Value();
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
        if((pNode1=Search(pNode, (char*)"SignedGrant"))!=NULL) {
            m_rgiEvidenceTypes[n]= SIGNEDGRANT;
        }
        else if((pNode1=Search(pNode, (char*)"Certificate"))!=NULL) {
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
#endif
    return m_fValid;
}


// -------------------------------------------------------------------------------


SignedAssertion::SignedAssertion()
{
    m_szSignature= NULL;
    m_szSignedInfo= NULL;
    m_szSignatureValue= NULL;
    m_szSignatureMethod= NULL;
    m_szCanonicalizationMethod= NULL;
    m_szRevocationInfo= NULL;
    m_pSignerKeyInfo= NULL;
    m_szPrincipalName= NULL;
    m_fSigValuesValid= false;
    m_iNumAssertions= 0;
    m_rgszAssertion= NULL;
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


bool  SignedAssertion::init(char* szSig)
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
    fprintf(g_logFile, "Signature: %s\n", m_szSignature);
    fprintf(g_logFile, "Signed Info: %s\n", m_szSignedInfo);
    fprintf(g_logFile, "SignatureValue: %s\n", m_szSignatureValue);
    fprintf(g_logFile, "%d assertions\n", m_iNumAssertions);
    int i;
    for(i=0;i<m_iNumAssertions; i++)
        fprintf(g_logFile, "\tAssertion %d: %s\n", i, m_rgszAssertion[i]);
}
#endif


bool SignedAssertion::parseSignedAssertionElements()
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement= NULL;
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

    if(!doc.Parse(m_szSignature)) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant parse document from file string\n");
        return false;
    }

    pRootElement= doc.RootElement();
    if(pRootElement==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant get root element of SignedAssertion\n");
        return false;
    }
     
    // make sure it's in signedinfo
    pSignedInfoNode= Search((TiXmlNode*) pRootElement, (char*)"ds:SignedInfo");
    if(pSignedInfoNode==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find SignedInfo\n");
        return false;
    }

    // fill m_szSignedInfo;
    m_szSignedInfo= canonicalize(pSignedInfoNode);


    // fill m_szSignatureMethod;
    pNode= Search(pSignedInfoNode, (char*)"ds:SignatureMethod");
    if(pNode==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find SignatureMethod\n");
        return false;
    }
    m_szSignatureMethod= strdup((char*)((TiXmlElement*) pNode)->Attribute("Algorithm"));

    // fill m_szPrincipalName
    pNode= Search(pSignedInfoNode, (char*)"SubjectName");
    if(pNode==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find SubjectName\n");
        return false;
    }
    pNode1= ((TiXmlElement*)pNode)->FirstChild();
    if(pNode1!=NULL) {
        m_szPrincipalName= strdup((char*)((TiXmlElement*)pNode1)->Value());
    }

    // fill m_szCanonicalizationMethod;
    pNode= Search(pSignedInfoNode, (char*)"ds:CanonicalizationMethod");
    if(pNode==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find CanonicalizationMethod\n");
        return false;
    }
    m_szCanonicalizationMethod= strdup((char*)((TiXmlElement*) pNode)->Attribute("Algorithm"));

    // fill m_szRevocationInfo;
    pNode= Search(pSignedInfoNode, (char*)"RevocationPolicy");
    if(pNode==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find RevocationPolicy\n");
        return false;
    }

    // fill m_ovalidityPeriod;
    pNode= Search((TiXmlNode*) pSignedInfoNode, (char*)"ValidityPeriod");
    if(pNode==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find Validity Period\n");
        return false;
    }
    pNode1= Search(pNode, (char*)"NotBefore");
    if(pNode1==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find NotBefore\n");
        return false;
    }
    pNode2= ((TiXmlElement*)pNode1)->FirstChild();
    if(pNode2) {
        szTimePoint= strdup((char*)((TiXmlElement*)pNode2)->Value());
    }
    else {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant get NotBefore value\n");
        return false;
    }
    if(!UTCtogmTime(szTimePoint, &m_ovalidityPeriod.notBefore)) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant interpret NotBefore value\n");
        return false;
    }
    pNode1= Search(pNode, (char*)"NotAfter");
    if(pNode1==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find NotAfter\n");
        return false;
    }
    pNode2= ((TiXmlElement*)pNode1)->FirstChild();
    if(pNode2) {
        szTimePoint= strdup((char*)((TiXmlElement*)pNode2)->Value());
    }
    else {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant get NotAftervalue\n");
        return false;
    }
    if(!UTCtogmTime(szTimePoint, &m_ovalidityPeriod.notAfter)) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant interpret NotAftervalue\n");
        return false;
    }

    // fill m_szSignatureValue;
    pNode= Search((TiXmlNode*) pRootElement, (char*)"ds:SignatureValue");
    if(pNode==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find SignatureValue\n");
        return false;
    }
    pNode1= ((TiXmlElement*)pNode)->FirstChild();
    if(pNode1!=NULL) {
        m_szSignatureValue= strdup((char*)((TiXmlElement*)pNode1)->Value());
    }
    else {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant get SignatureValue\n");
        return false;
    }

    // Assertions
    pNodeA= Search((TiXmlNode*) pSignedInfoNode, (char*)"Assertions");
    if(pNodeA==NULL) {
        fprintf(g_logFile, "parseSignedAssertionElements: Cant find Assertions\n");
        return false;
    }
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
    return m_pSubjectKeyInfo;
}


// ---------------------------------------------------------------------------


accessPrincipal* registerPrincipalfromCert(PrincipalCert* pSig)
{
    accessPrincipal *pP= NULL;
    if((pP=g_theVault.findPrincipal(pSig->getPrincipalName()))!=NULL) {
        return pP;
    }   

    pP= new accessPrincipal();
    if(pP==NULL) {
        fprintf(g_logFile, "Can't new principal\n");
        return NULL;
    }
    pP->m_szPrincipalName= pSig->getPrincipalName();
    pP->m_uPrincipalType= USERPRINCIPAL;
    pP->m_fValidated= true;
    pP->m_pCert= pSig;

    if(g_theVault.addPrincipal(pP)){
        return pP;
    }
    else {
        fprintf(g_logFile, "Can't add object to principal table\n");
        return NULL;
    }
}


// ---------------------------------------------------------------------------


