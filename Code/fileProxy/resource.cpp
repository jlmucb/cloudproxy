//
//  resource.cpp
//      John Manferdelli
//
//  Description: resource class implementations
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


// --------------------------------------------------------------------------


#include "jlmTypes.h"
#include "logging.h"
#include "keys.h"
#include "jlmUtility.h"
#include "cert.h"
#include "resource.h"
#include "objectManager.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>


resource::resource()
{
    m_szResourceName= NULL;
    m_szLocation= NULL;
    m_uType= 0;
    m_fIsPresent= false;
    m_fIsDeleted= false;
    m_fKeyValid= false;
    m_iSize= 0;
    memset(m_rguKey1, 0, GLOBALMAXSYMKEYSIZE);
}


resource::~resource()
{
    if(m_szResourceName==NULL){
        free(m_szResourceName);
        m_szResourceName= NULL;
    }
    if(m_szLocation==NULL){
        free(m_szLocation);
        m_szLocation= NULL;
    }

    // remove owner list
}


bool resource::addOwner(PrincipalCert* pPrincipal)
{
    return m_myOwners.append(pPrincipal);
}


int  resource::getSize()
{
    return m_iSize;
}


char*  resource::getName()
{
    return m_szResourceName;
}


bool resource::removeOwner(PrincipalCert* pPrincipal)
{
    return false;
}


int  resource::auxSize()
{
    int                     iTotal= 0;
    int                     iNumOwners= 0;
    aNode<PrincipalCert>* pNode= NULL;
    PrincipalCert*        pPrinc= NULL;

    iTotal+= strlen(m_szResourceName)+1;
    iTotal+= strlen(m_szLocation)+1;
    iTotal+= 2*sizeof(bool)+sizeof(u16);   // isDeleted+isPresent+type
    iTotal+= sizeof(u32);                  // size
    iTotal+= sizeof(int);                  // numOwners

    pNode=  m_myOwners.pFirst;
    while(pNode!=NULL) {
        iNumOwners++;
        pPrinc= pNode->pElement;
        iTotal+= strlen(pPrinc->m_szPrincipalName)+1;
        pNode= pNode->pNext;
    }

    return iTotal;
}


bool resource::Deserialize(const byte* szObj, int* pi)
{
    const char*             sz= reinterpret_cast<const char*>(szObj);
    int                     iTotal= 0;
    int                     i, n;
    int                     iNumOwners= 0;
    char*                   p= NULL;

#ifdef TEST
    fprintf(g_logFile, "resource Deserialize\n");
    fflush(g_logFile);
#endif
    m_szResourceName= strdup(sz);
    n= strlen(m_szResourceName)+1;
    sz+= n;
    iTotal+= n;
    
    m_szLocation= strdup(sz);
    n= strlen(m_szLocation)+1;
    sz+= n;
    iTotal+= n;

    n= sizeof(u16);
    memcpy(&m_uType, sz, n);
    sz+= n;
    iTotal+= n;

    n= sizeof(bool);
    memcpy(&m_fIsPresent, sz, n);
    sz+= n;
    iTotal+= n;

    n= sizeof(bool);
    memcpy(&m_fIsDeleted, sz, n);
    sz+= n;
    iTotal+= n;

    n= sizeof(u32);
    memcpy(&m_iSize, sz, n);
    sz+= n;
    iTotal+= n;

    n= sizeof(int);                  // numOwners
    memcpy(&iNumOwners, sz, n);
    sz+= n;
    iTotal+= n;

    for(i=0; i<iNumOwners; i++) {
        p= strdup(sz);
        n= strlen(p)+1;
        // name must be converted to access principal afterwards
        m_myOwners.append((PrincipalCert*) p);
        sz+= n;
        iTotal+= n;
    }

    *pi= iTotal;
#ifdef TEST
    fprintf(g_logFile, "resource Deserialize done %s\n", m_szResourceName);
    fflush(g_logFile);
#endif
    return true;
}


int resource::Serialize(byte* szObj)
{
    byte*                   sz= szObj;
    int                     iTotal= 0;
    int                     n;
    int                     iNumOwners= 0;
    aNode<PrincipalCert>*   pNode= NULL;
    PrincipalCert*          pPrinc= NULL;

#ifdef TEST
    fprintf(g_logFile, "resource Serialize\n");
#endif
    pNode=  m_myOwners.pFirst;
    while(pNode!=NULL) {
        iNumOwners++;
        pNode= pNode->pNext;
    }

    n= strlen(m_szResourceName)+1;
    memcpy(sz, m_szResourceName, n);
    sz+= n;
    iTotal+= n;
    
    n= strlen(m_szLocation)+1;
    memcpy(sz, m_szLocation, n);
    sz+= n;
    iTotal+= n;

    n= sizeof(u16);
    memcpy(sz, &m_uType, n);
    sz+= n;
    iTotal+= n;

    n= sizeof(bool);
    memcpy(sz, &m_fIsPresent, n);
    sz+= n;
    iTotal+= n;

    n= sizeof(bool);
    memcpy(sz, &m_fIsDeleted, n);
    sz+= n;
    iTotal+= n;

    n= sizeof(u32);
    memcpy(sz, &m_iSize, n);
    sz+= n;
    iTotal+= n;

    n= sizeof(int);                  // numOwners
    memcpy(sz, &iNumOwners, n);
    sz+= n;
    iTotal+= n;

    pNode=  m_myOwners.pFirst;
    while(pNode!=NULL) {
        pPrinc= pNode->pElement;
        n= strlen(pPrinc->m_szPrincipalName)+1;
        memcpy(sz, pPrinc->m_szPrincipalName, n);
        sz+= n;
        iTotal+= n;
        pNode= pNode->pNext;
    }

    return iTotal;
}


aNode<PrincipalCert>* resource::getFirstOwnerNode()
{
    return m_myOwners.pFirst;
}


aNode<PrincipalCert>*   resource::getNextOwnerNode(aNode<PrincipalCert>* pNode)
{
    return pNode->pNext;
    return NULL;
}


#ifdef TEST
void  resource::printMe()
{
    fprintf(g_logFile, "Resource, type %d:\n", m_uType);
    if(m_szResourceName!=NULL) {
        fprintf(g_logFile, "\tResource Name: %s\n", m_szResourceName);
    }
    if(m_szLocation!=NULL) {
        fprintf(g_logFile, "\tLocation: %s\n", m_szLocation);
    }
    else {
        fprintf(g_logFile, "\tLocation: NULL\n");
    }
    fprintf(g_logFile, "\tSize: %d\n", m_iSize);

    PrincipalCert*    pPrinc= NULL;
    aNode<PrincipalCert>*  pOwnerNode= m_myOwners.pFirst;
    fprintf(g_logFile, "Owners: ");
    while(pOwnerNode!=NULL) {
        pPrinc= pOwnerNode->pElement;
        fprintf(g_logFile, "%s ", pPrinc->getName());
        pOwnerNode= pOwnerNode->pNext;
    }
    fprintf(g_logFile, "\n");

    return;
}
#endif


bool resource::isAnOwner(PrincipalCert* pSubject)
{
#ifdef TEST
    fprintf(g_logFile, "resource::isAnOwner(%08x)\n", pSubject);
    fflush(g_logFile);
#endif
    aNode<PrincipalCert>*   pOwnerNode= m_myOwners.pFirst;
    PrincipalCert*          pOwnerPrincipal= NULL;

    while(pOwnerNode!=NULL) {
        pOwnerPrincipal= pOwnerNode->pElement;
        // Fix: Should check key?
        if(strcmp(pSubject->m_szPrincipalName, pOwnerPrincipal->m_szPrincipalName)==0) {
#ifdef TEST
            fprintf(g_logFile, "resource::isAnOwner returns false\n");
            fflush(g_logFile);
#endif
            return true;
        }
        pOwnerNode= pOwnerNode->pNext;
    }

#ifdef TEST
    fprintf(g_logFile, "resource::isAnOwner returns false\n");
    fflush(g_logFile);
#endif
    return false;
}


bool resource::MakeOwnerList(int* pnOwners, PrincipalCert*** pprgpPrincipalCerts,
                            objectManager<PrincipalCert>* pPp)
{
    int                 iNumOwners= 0;
    int                 i;
    PrincipalCert*      pPrinc= NULL;
    PrincipalCert**     rgpPrinc= NULL;

    aNode<PrincipalCert>*  pOwnerNode= m_myOwners.pFirst;
    while(pOwnerNode!=NULL) {
        iNumOwners++;
        pOwnerNode= pOwnerNode->pNext;
    }

    rgpPrinc= (PrincipalCert**) malloc(iNumOwners*sizeof(PrincipalCert*));
    if(rgpPrinc==NULL)
        return false;
    *pprgpPrincipalCerts= rgpPrinc;
    *pnOwners= iNumOwners;

    i= 0;
    pOwnerNode= m_myOwners.pFirst;
    while(pOwnerNode!=NULL) {
        pPrinc= pOwnerNode->pElement;
        if(pPrinc!=NULL) {
                rgpPrinc[i++]= pPrinc;
                continue;
            }
        pOwnerNode= pOwnerNode->pNext;
    }

    return true;
}


// ------------------------------------------------------------------------


