//
//  accessPrincipal.cpp
//      John Manferdelli
//
//  Description: Access Principal control
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
#include "accessPrincipal.h"
#include "sha256.h"
#include "cryptoHelper.h"

#include <string.h>
#include <time.h>


// ------------------------------------------------------------------------


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


bool accessPrincipal::Deserialize(const byte* szObj, int* pi)
{
    const byte*               sz= szObj;
    int                 iTotal= 0;
    int                 n;
    PrincipalCert*      pCert= NULL;
    char*               p= NULL;

#ifdef TEST
    fprintf(g_logFile, "accessPrincipal Deserialize\n");
    fflush(g_logFile);
#endif
    m_szPrincipalName= strdup(reinterpret_cast<const char*>(sz));
    n= strlen(m_szPrincipalName)+1;
    sz+= n;
    iTotal+= n;

    memcpy(&m_uPrincipalType, sz, sizeof(u32));
    sz+= sizeof(u32);
    iTotal+= sizeof(u32);

    memcpy(&m_fValidated, sz, sizeof(bool));
    sz+= sizeof(bool);
    iTotal+= sizeof(bool);

    p= strdup(reinterpret_cast<const char*>(sz));
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


