//
//  accessControl.h
//      John Manferdelli
//
//  Description: Access control classes
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


// ------------------------------------------------------------------------


#ifndef _ACCESSCONTROL__H
#define _ACCESSCONTROL__H

#include "jlmTypes.h"
#include "secPrincipal.h"
#include "resource.h"
#include "vault.h"


#define MAXTOKEN  256


/*
 *  read, write, create, delete, own, speaksfor
 *  resource exists flag
 *  K[pol] says K[jlm] maycreate $D
 *  K[jlm] says K[bob] speaksfor K[jlm] on <actions>
 */


#define  MAYREAD    0x001
#define  MAYWRITE   0x002
#define  MAYCREATE  0x004
#define  MAYDELETE  0x008
#define  MAYOWN     0x010
#define  SPEAKSFOR  0x020
#define  SAYS       0x400


class assertionNode {
public:
    bool                    m_fValidated;
    accessPrincipal*        m_pPrincipal;
    assertionNode*          m_pAssertion;
    u32                     m_uVerbs;
    resource*               m_pResource;
    char*                   m_szCondition;   

    assertionNode();
    ~assertionNode();
    bool        parseAssertion(accessPrincipal* pPrincipalSays, const char* szAssertion, 
                                bool fValidated);
#ifdef TEST
    void        printMe();
#endif
    bool        assertionSucceeds(accessPrincipal* pSubject, u32 uVerb, resource* pResouce,
                             int iNumAssertions, assertionNode** rgpAssertions);
    bool        matchAction(u32 uVerb);
    bool        matchResource(resource* pResource);
    bool        matchPrincipal(accessPrincipal* pSubject);
};


class accessRequest {
public:
    char*           m_szSubject;
    int             m_iRequestType;
    char*           m_szResource;

    accessRequest();
    ~accessRequest();

#ifdef TEST
    void            printMe();
#endif
};


class accessGuard {
public:
    bool                    m_fValid;
    int                     m_iNumAssertions;
    assertionNode**         m_rgpAssertions;
    int                     m_iNumSubjects; 
    aList<accessPrincipal>  m_Subjects;

    bool        initChannelAccess(int iNumSubj, PrincipalCert** rgpPrinc);
    bool        permitAccess(accessRequest& req, const char* szEvidence);
    accessGuard();
    ~accessGuard();
};


extern bool isAnOwner(accessPrincipal* pSubject, resource* pResource);
extern bool isPolicyPrincipal(accessPrincipal* pSubject);
bool        initAccessGuard(sessionKeys& oKeys);


#endif


// -------------------------------------------------------------------------


