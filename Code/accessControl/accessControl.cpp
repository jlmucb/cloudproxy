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
 *      K-Policy says K-JLM can read //www.manferdelli.com/Files
 *      K-Policy says K-JLM can write //www.manferdelli.com/Files
 *      K-Policy says K-JLM can say x owns //www.manferdelli.com/Files
 *  <Assertions count='5'>
 *    <Assertion> K-Policy says K-JLM may read //www.manferdelli.com/Files </Assertion>
 *    <Assertion> K-Policy says K-JLM may read //www.manferdelli.com/Files </Assertion>
 *    <Assertion> K-Policy says K-JLM may read //www.manferdelli.com/Files/\* </Assertion>
 *    <Assertion> K-Policy says K-JLM may write //www.manferdelli.com/Files </Assertion>
 *    <Assertion> K-Policy says K-JLM may say x owns //www.manferdelli.com/Files </Assertion>
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



bool accessGuard::initGuard(RSAKey* pPolicy, metaData* pMeta)
{
#ifdef TEST  
    fprintf(g_logFile, "initGuard\n");
    fflush(g_logFile);
#endif

    // note all principals have been authenticated before they go in
    m_pPolicy= pPolicy;
    m_pMetaData= pMeta;
    m_fValid= true;
    return true;
}


bool accessGuard::permitAccess(accessRequest& req, const char* szEvidence)
{
    resource*           pResource= NULL;
    PrincipalCert*      pSubjPrincipal= NULL;
    RSAKey*             pSaysKey= NULL;
    RSAKey*             pSubjectKey= NULL;
    int                 i;
    u32                 uVerb= 0;

#ifdef TEST
    fprintf(g_logFile, "permitAccess: Can %s %s %s\n", req.m_szSubject,
                req.m_szRequest, req.m_szResource);
    fprintf(g_logFile, "Based on: %s\n", szEvidence);
#endif

    if(!m_fValid) {
        fprintf(g_logFile, "permitAccess: accessGuard invalid\n");
        return false;
    }

    // PrincipalCerts should have been validated by now
    pResource= m_pMetaData->findResource(req.m_szResource);
    if(pResource==NULL) {
        fprintf(g_logFile, "permitAccess resource is NULL\n");
        return false;
    }
    // are any channel keys the owner?
    for(i=0;i<m_numCurrentPrincipals;i++) {
        pSubjPrincipal= m_myPrincipals[i];
        if(isAnOwner(pSubjPrincipal, pResource)) {
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
    if(szEvidence==NULL) {
        fprintf(g_logFile, "permitAccess: no Evidence\n");
        return false;
    }

    // parse evidence
    SignedAssertion*    pAssert= NULL; 
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
        fprintf(g_logFile, "permitAccess: No Signed grant\n");
        return false;
    }
    pAssert= (SignedAssertion*) oEvidenceCollection.m_rgCollectionList[0]->m_rgEvidence[0];

    // subjects of top grant must be channel principals
    pSubjectKey= (RSAKey*)pAssert->getSubjectKeyInfo();
    for(i=0; i<m_numCurrentPrincipals; i++) {
        if(sameRSAKey(pSubjectKey, (RSAKey*)m_myPrincipals[i]->getSubjectKeyInfo()))
            break;
    }
    if(i==m_numCurrentPrincipals) {
        fprintf(g_logFile, "permitAccess: grantee not represented principal\n");
        return false;
    }

    // map request to required access
    if(strcmp(req.m_szRequest, "createResource")==0)
        uVerb= MAYCREATE;
    else if(strcmp(req.m_szRequest, "sendResource")==0)
        uVerb= MAYWRITE;
    else if(strcmp(req.m_szRequest, "getResource")==0)
        uVerb= MAYREAD;
    else if(strcmp(req.m_szRequest, "getOwner")==0 || 
            strcmp(req.m_szRequest, "addOwner")==0 ||
            strcmp(req.m_szRequest, "removeOwner")==0)
        uVerb= MAYOWN;
    else if(strcmp(req.m_szRequest, "deleteResource")==0)
        uVerb= MAYDELETE;
    else {
        fprintf(g_logFile, "permitAccess: Unknown request\n");
        return false;
    }

    // request must be subsumed in grant and name resource

    // time period valid?

#ifdef ACCESSTEST
    fprintf(g_logFile, "permitAccess: Checking assertions\n");
    fflush(g_logFile);
#endif
    pSaysKey= (RSAKey*)pAssert->m_pSignerKeyInfo;

    SignedAssertion**  rgpAssertions= 
            (SignedAssertion**) malloc(sizeof(SignedAssertion*)*m_iNumAssertions);
   
    // succeed when we hit owner
    for(i=0;i<m_iNumAssertions; i++) {
    }
    bool fRet= i<m_iNumAssertions;

    // clean up

    return fRet;
}


// ---------------------------------------------------------------------------


