//
//  accessControl.cpp
//      John Manferdelli
//
//  Description: Access control implementation
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
#include "resource.h"
#include "request.h"
#include "signedAssertion.h"
#include "accessControl.h"
#include "vault.h"
#include "cryptoHelper.h"
#include "validateEvidence.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>


// ----------------------------------------------------------------------------


/*
 *  Verbs: read | write | own | delete | create | request | has | is-a | get-keys | get-metadata
 *  
 *  Principal says Principal verb resource if condition
 *  Principal says Principal may say other-Principal verb object condition
 *  Example
 *      K-Policy says K-JLM mayread //www.manferdelli.com/Files
 *      K-Policy says K-JLM maywrite //www.manferdelli.com/Files
 *      K-Policy says K-JLM maysay x owns //www.manferdelli.com/Files
 *  <Assertions count='5'>
 *    <Assertion> K-Policy says K-JLM mayread //www.manferdelli.com/Files </Assertion>
 *    <Assertion> K-Policy says K-JLM mayread //www.manferdelli.com/Files </Assertion>
 *    <Assertion> K-Policy says K-JLM mayread //www.manferdelli.com/Files/\* </Assertion>
 *    <Assertion> K-Policy says K-JLM maywrite //www.manferdelli.com/Files </Assertion>
 *    <Assertion> K-Policy says K-JLM maysay x owns //www.manferdelli.com/Files </Assertion>
 *  </Assertions>
 *
 *  Request
 *    read //www.manferdelli.com/Files/MachineName/file
 */


char* verbName(u32 uVerb)
{
    switch(uVerb) {
      case MAYREAD:
        return (char*)"mayread";
      case MAYWRITE:
        return (char*)"maywrite";
      case MAYCREATE:
        return (char*)"maycreate";
      case MAYDELETE:
        return (char*)"maydelete";
      case MAYOWN:
        return (char*)"mayown";
      case SPEAKSFOR:
        return (char*)"speaksfor";
      case SAYS:
        return (char*)"says";
      default:
        return (char*)"unknown verb";
    }
}


u32 verbFlag(const char* pVerbName)
{
   if(strcmp(pVerbName,"mayread")==0)
        return MAYREAD;

   if(strcmp(pVerbName, "maywrite")==0)
        return MAYWRITE;

   if(strcmp(pVerbName, "maycreate")==0)
        return MAYCREATE;

   if(strcmp(pVerbName, "maydelete")==0)
        return MAYDELETE;

   if(strcmp(pVerbName, "mayown")==0)
        return MAYOWN;

   if(strcmp(pVerbName, "speaksfor")==0)
        return SPEAKSFOR;

   if(strcmp(pVerbName, "maysay")==0)
        return SAYS;

   if(strcmp(pVerbName,"read")==0)
        return MAYREAD;

   if(strcmp(pVerbName, "write")==0)
        return MAYWRITE;

   if(strcmp(pVerbName, "create")==0)
        return MAYCREATE;

   if(strcmp(pVerbName, "delete")==0)
        return MAYDELETE;

   if(strcmp(pVerbName, "own")==0)
        return MAYOWN;

   if(strcmp(pVerbName, "speaksfor")==0)
        return SPEAKSFOR;

   if(strcmp(pVerbName, "says")==0)
        return SAYS;

    return 0;
}


// ---------------------------------------------------------------------------


accessRequest::accessRequest()
{
    m_szSubject= NULL;
    m_szRequest= NULL;
    m_szResource= NULL;
}


accessRequest::~accessRequest()
{
    if(m_szSubject==NULL) {
        free(m_szSubject);
        m_szSubject= NULL;
    }
    if(m_szResource==NULL) {
        free(m_szResource);
        m_szResource= NULL;
    }
}


#ifdef TEST
void accessRequest::printMe()
{
    fprintf(g_logFile, "\n\taccessRequest\n");
    if(m_szSubject==NULL)
        fprintf(g_logFile, "\tSubject is NULL\n");
    else
        fprintf(g_logFile, "\tSubject is %s\n", m_szSubject);
    if(m_szRequest==NULL)
        fprintf(g_logFile, "\tRequest is NULL\n");
    else
        fprintf(g_logFile, "\tRequest is %s\n", m_szRequest);
    if(m_szResource==NULL)
        fprintf(g_logFile, "\tResource is NULL\n");
    else
        fprintf(g_logFile, "\tResource is %s\n", m_szResource);
    fprintf(g_logFile, "\n");
}
#endif


accessGuard::accessGuard()
{
    m_fValid= false;
    m_iNumAssertions= 0;
    m_rgAssertions= NULL;
    m_numCurrentPrincipals= 0;
    m_myPrincipals= NULL;
}


accessGuard::~accessGuard()
{
}


// ---------------------------------------------------------------------------


bool accessGuard::includesSubject(const char* szRequested, const char* szGranted)
{
#ifdef TEST
    fprintf(g_logFile, "includesSubject((%s, %s)\n", szRequested, szGranted);
    fflush(g_logFile);
#endif
    if(szRequested==NULL || szGranted==NULL)
        return false;
    if(strcmp(szRequested, szGranted)==0)
        return true;
    return true;
}


bool accessGuard::includesRight(const char* szRequested, const char* szGranted)
{
    if(szRequested==NULL || szGranted==NULL)
        return false;
    u32 uVerb1= verbFlag(szRequested);
    u32 uVerb2= verbFlag(szGranted);
#ifdef TEST
    fprintf(g_logFile, "includesRight((%s, %s) %x %x\n", szRequested, szGranted, uVerb1, uVerb2);
    fflush(g_logFile);
#endif

    // Fix!
    if(uVerb1==uVerb2 || uVerb2==(uVerb1|MAYDELEGATE))
        return true;
    return false;
}


bool accessGuard::includesObject(const char* szRequested, const char* szGranted)
{
#ifdef TEST
    fprintf(g_logFile, "includesObject((%s, %s)\n", szRequested, szGranted);
    fflush(g_logFile);
#endif
    if(szRequested==NULL || szGranted==NULL)
        return false;
    if(strcmp(szRequested, szGranted)==0)
        return true;
    // handle *
    return false;
}


int accessGuard::checkPermitChain(resource* pResource,
                                  tm& pt,
                                  SignedAssertion* pAssert1, 
                                  SignedAssertion* pAssert2)
//  return
//      -1: fail
//       0: ok so far
//       hit owner, succeed
{
    const char*     szrequestedSubject= pAssert1->getGrantSubject();
    PrincipalCert*  pCert= NULL;

    // time period valid?
    if(!checktimeinInterval(pt, pAssert1->m_ovalidityPeriod.notBefore, 
                                pAssert1->m_ovalidityPeriod.notAfter)) {
        return -1;
    }

    // is subject an owner?
    pCert= m_pMetaData->findPrincipal(pAssert1->getGrantObject());
    if(pCert==NULL) {
#ifdef TEST
        fprintf(g_logFile, "checkPermitChain: cant get principal\n");
#endif
        return -1;
    }
    if(pResource->isAnOwner(pCert)) {
#ifdef TEST
        fprintf(g_logFile, "checkPermitChain: The subject is an owner of resource\n");
#endif
        return 1;
    }       
    
    const char* szrequestedVerb= pAssert1->getGrantRight();
    const char* szrequestedObject= pAssert1->getGrantObject();
    const char* szgrantedVerb= pAssert2->getGrantRight();
    const char* szgrantedSubject= pAssert2->getGrantSubject();
    const char* szgrantedObject= pAssert2->getGrantObject();

    if(!includesSubject(szrequestedSubject, szgrantedSubject)) {
        fprintf(g_logFile, "checkPermitChain: requesting subject is not in granted subject\n");
        return -1;
    }
    if(!includesRight(szrequestedVerb, szgrantedVerb)) {
        fprintf(g_logFile, "checkPermitChain: requested right is not in granted right\n");
        return -1;
    }
    if(!includesObject(szrequestedObject, szgrantedObject)) {
        fprintf(g_logFile, "checkPermitChain: requested object is not in granted object\n");
        return -1;
    }
    return 0;
}


bool accessGuard::initGuard(RSAKey* pPolicy, metaData* pMeta, 
                            int numPrincipals, PrincipalCert** rgPrinc)
{
    int i;
#ifdef TEST  
    fprintf(g_logFile, "initGuard %08x %08x %d %08x\n",
            pPolicy, pMeta, numPrincipals, rgPrinc);
    fflush(g_logFile);
#endif
    m_numCurrentPrincipals= numPrincipals;
    m_myPrincipals= new PrincipalCert*[numPrincipals];
    for(i=0; i<numPrincipals; i++) {
        m_myPrincipals[i]= rgPrinc[i];
    }
    // note all principals have been authenticated before they go in
    m_pPolicy= pPolicy;
    m_pMetaData= pMeta;
    m_fValid= true;
    return true;
}


bool accessGuard::permitAccess(accessRequest& req, const char* szEvidence)
{
    resource*           pResource= NULL;
    PrincipalCert*      pSubjectCert= NULL;
    RSAKey*             pSubjectKey= NULL;
    SignedAssertion*    pAssert= NULL;
    int                 i;
#if 0
    bool                fRet= false;
    int                 iPermit= 0;
#endif
    time_t              now;
    tm*                 pt;

#ifdef TEST
    fprintf(g_logFile, "permitAccess: Can %s %s %s\n", req.m_szSubject,
                req.m_szRequest, req.m_szResource);
    fprintf(g_logFile, "Based on: %s\n", szEvidence);
    fflush(g_logFile);
#endif

    if(!m_fValid) {
        fprintf(g_logFile, "permitAccess: accessGuard invalid\n");
        return false;
    }

    UNUSEDVAR(pt);
    time(&now);
    pt= localtime(&now);

    // PrincipalCerts should have been validated by now
    pResource= m_pMetaData->findResource(req.m_szResource);
    if(pResource==NULL) {
        fprintf(g_logFile, "permitAccess resource is NULL\n");
        return false;
    }

    // are any channel keys the owner?
    for(i=0;i<m_numCurrentPrincipals;i++) {
        if(pResource->isAnOwner(m_myPrincipals[i])) {
#ifdef TEST
            fprintf(g_logFile, "permitAccess: The subject is an owner of resource\n");
#endif
            return true;
        }       
    }

    // if request is add or delete owner, return false
    //      only owners have this right.
    if(strcmp(req.m_szRequest, "addOwner")==0 || 
       strcmp(req.m_szRequest, "removeOwner")==0) {
        fprintf(g_logFile, "permitAccess: no Evidence\n");
        return false;
    }

    // Does evidence support access?
    // Note: This does not support compond principals yet
    // eg: JohnManferdelli and fileClient may read.
    if(szEvidence==NULL) {
        fprintf(g_logFile, "permitAccess: no Evidence\n");
        return false;
    }

    // parse evidence
    evidenceCollection  oEvidenceCollection;

    if(!oEvidenceCollection.parseEvidenceCollection(szEvidence)) {
        fprintf(g_logFile, "permitAccess: Can't parse Evidence list\n");
        return false;
    }

    if(!oEvidenceCollection.validateEvidenceCollection(m_pPolicy)) {
        fprintf(g_logFile, "permitAccess: Can't validate Evidence list\n");
        return false;
    }

    if(oEvidenceCollection.m_iNumEvidenceLists<1 || 
            oEvidenceCollection.m_rgiCollectionTypes[0]!=SIGNEDGRANT) {
        fprintf(g_logFile, "permitAccess: No signed grant\n");
        return false;
    }
    pAssert= (SignedAssertion*) oEvidenceCollection.m_rgCollectionList[0]->m_rgEvidence[0];
    if(!pAssert->parseAssertion()) {
        fprintf(g_logFile, "permitAccess: cant parse signed assertion\n");
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "permitAccess: examining assertion\n");
    pAssert->printMe();
    fflush(g_logFile);
#endif

    if(pAssert->m_pAssertion==NULL) {
        fprintf(g_logFile, "permitAccess: Rule is NULL\n");
        return false;
    }

    // subjects of top grant must be channel principals
    char* szSubj= pAssert->getGrantSubject();
#ifdef TEST
    fprintf(g_logFile, "permitAccess: looking up subject %s, %08lx\n", szSubj, m_pMetaData);
    fflush(g_logFile);
#endif
    pSubjectCert= m_pMetaData->findPrincipal(szSubj);
    if(pSubjectCert==NULL)  {
        fprintf(g_logFile, "permitAccess: pSubjectCert is NULL\n");
        return false;
    }
    pSubjectKey= (RSAKey*)(pSubjectCert->getSubjectKeyInfo());
    if(pSubjectKey==NULL)  {
        fprintf(g_logFile, "permitAccess: pSubject is NULL\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "permitAccess: Assertion, got subject key\n");
    pSubjectKey->printMe();
    fflush(g_logFile);
#endif
    for(i=0; i<m_numCurrentPrincipals; i++) {
        if(sameRSAKey(pSubjectKey, (RSAKey*)m_myPrincipals[i]->getSubjectKeyInfo()))
            break;
    }
    if(i==m_numCurrentPrincipals) {
        fprintf(g_logFile, "permitAccess: grantee not represented principal %d\n", 
                m_numCurrentPrincipals);
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "permitAccess: checking rights\n");
    fflush(g_logFile);
#endif

    // top level must name resource and verb
    if(!includesRight(req.m_szRequest, pAssert->getGrantRight())) {
        fprintf(g_logFile, "permitAccess: top level grant does not name right\n");
        return false;
    }
    if(!includesObject(req.m_szResource, pAssert->getGrantObject())) {
        fprintf(g_logFile, "permitAccess: top level grant does not name object\n");
        return false;
    }

    return true;

#if 0
    // Fix
#ifdef TEST
    fprintf(g_logFile, "permitAccess: Evaluating assertion chain of length %d\n", 
            m_iNumAssertions);
    fflush(g_logFile);
#endif
    // succeed when we hit owner
    SignedAssertion*    pParentAssert= NULL;
    for(i=0;i<m_iNumAssertions; i++) {
        if(i<(m_iNumAssertions-1))
            pParentAssert= (SignedAssertion*) oEvidenceCollection.m_rgCollectionList[i+1]->m_rgEvidence[0];
        else
            pParentAssert= NULL;
        iPermit= checkPermitChain(pResource, *pt,
                            (SignedAssertion*) oEvidenceCollection.m_rgCollectionList[i]->m_rgEvidence[0],
                            pParentAssert);
        if(iPermit==1) {
            fRet= true;
            break;
        }
        if(iPermit==-1) {
            fRet= false;
            break;
        }
    }

    // clean up

    return fRet;
#endif
}


// ---------------------------------------------------------------------------


