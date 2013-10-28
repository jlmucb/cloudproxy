//  File: taoAttest.cpp
//      John Manferdelli
//  Description: Verify attest object
//
//  Copyright (c) 2012, John Manferdelli
//  Some contributions copyright (c) 2012, Intel Corporation
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
#include "jlmUtility.h"
#include "modesandpadding.h"
#include "bignum.h"
#include "sha256.h"
#include "tao.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "cryptoHelper.h"
#include "hashprep.h"
#include "cert.h"
#include "quote.h"
#include "validateEvidence.h"

#include <string.h>
#include <time.h>
#include <unistd.h>


// -------------------------------------------------------------------------


taoAttest::taoAttest()
{
    m_attestType= 0;
    m_pattestCert= NULL;
    m_pquoteKey= NULL;
    m_szQuoteAlg= NULL;
    m_szQuoteInfo= NULL;
    m_szCanonicalQuotedBody= NULL;
    m_sznonce= NULL;
    m_szdigest= NULL;
    m_szQuoteValue= NULL;
    m_szQuoteKeyInfo= NULL;
    m_szQuotedKeyInfo= NULL;
    m_policyKey= NULL;
    m_szQuotedKeyName= NULL;
}


taoAttest::~taoAttest()
{
    m_attestType= 0;
    if(m_pattestCert!=NULL) {
        free(m_pattestCert);
        m_pattestCert= NULL;
    }
    if(m_pquoteKey!=NULL) {
        // delete pquoteKey;
        // this is deleted in cert class
        m_pquoteKey= NULL;
    }
    if(m_szQuoteAlg!=NULL) {
        free(m_szQuoteAlg);
        m_szQuoteAlg= NULL;
    }
    if(m_szQuoteInfo!=NULL) {
        free(m_szQuoteInfo);
        m_szQuoteInfo= NULL;
    }
    if(m_szCanonicalQuotedBody!=NULL) {
        free(m_szCanonicalQuotedBody);
        m_szCanonicalQuotedBody= NULL;
    }
    if(m_sznonce!=NULL) {
        free(m_sznonce);
        m_sznonce= NULL;
    }
    if(m_szdigest!=NULL) {
        free(m_szdigest);
        m_szdigest= NULL;
    }
    if(m_szQuoteValue!=NULL) {
        free(m_szQuoteValue);
        m_szQuoteValue= NULL;
    }
    if(m_szQuoteKeyInfo!=NULL) {
        free(m_szQuoteKeyInfo);
        m_szQuoteKeyInfo= NULL;
    }
    if(m_szQuotedKeyInfo!=NULL) {
        free(m_szQuotedKeyInfo);
        m_szQuotedKeyInfo= NULL;
    }
    if(m_szQuotedKeyName!=NULL) {
        free(m_szQuotedKeyName);
        m_szQuotedKeyName= NULL;
    }
    m_policyKey= NULL;
}


bool taoAttest::init(u32 type, const char *attestation, const char *attestEvidence, 
                     KeyInfo* policyKey) 
{
    if(type!=CPXMLATTESTATION) {
        fprintf(g_logFile, "taoAttest::init: attestation not supported\n");
        return false;
    }
    m_attestType= type;

    if(attestation==NULL) {
        fprintf(g_logFile, "taoAttest::init: no attestation\n");
        return false;
    }
    if(attestEvidence==NULL) {
        fprintf(g_logFile, "taoAttest::init: no evidence\n");
        return false;
    }
    if(policyKey==NULL) {
        fprintf(g_logFile, "taoAttest::init: empty policy key\n");
        return false;
    }
    m_policyKey= (RSAKey*)policyKey;
    if(policyKey->m_ukeyType!=RSAKEYTYPE) {
        fprintf(g_logFile, "taoAttest::init: unsupported policy key type\n");
        return false;
    }
    
#ifdef TEST
    fprintf(g_logFile, "taoAttest::init, attestation\n%s\nEvidence\n%s\n", 
            attestation, attestEvidence);
    fprintf(g_logFile, "Policy Key\n");
    ((RSAKey*)policyKey)->printMe();
    fflush(g_logFile);
#endif

    // Get the information from attestation
    if(!decodeXMLQuote(attestation, &m_szQuoteAlg, &m_sznonce,
                    &m_szdigest, &m_szQuoteInfo, &m_szQuoteValue,
                    &m_szQuoteKeyInfo, &m_szQuotedKeyInfo, &m_szQuotedKeyName)) {
        fprintf(g_logFile, "taoAttest::init: can't decode attest\n");
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "taoAttest::init\n");
    fprintf(g_logFile, "\tszQuoteAlg: %s\n", m_szQuoteAlg);
    fprintf(g_logFile, "\tszdigest: %s\n", m_szdigest);
    fprintf(g_logFile, "\tszQuoteInfo: %s\n", m_szQuoteInfo);
    fprintf(g_logFile, "\tszQuoteValue: %s\n", m_szQuoteValue);
    fprintf(g_logFile, "\tszQuoteKeyInfo: %s\n", m_szQuoteKeyInfo);
    fprintf(g_logFile, "\tszQuotedKeyInfo: %s\n", m_szQuotedKeyInfo);
    fflush(g_logFile);
#endif

    // Cert chain
    if(!m_oEvidence.m_doc.Parse(attestEvidence)) {
        fprintf(g_logFile, "taoAttest::init: can't parse evidence list \n");
        return false;
    }

    m_oEvidence.m_fDocValid= true;
    m_oEvidence.m_pRootElement= m_oEvidence.m_doc.RootElement();
    if(!m_oEvidence.parseEvidenceList(m_oEvidence.m_pRootElement)) {
        fprintf(g_logFile, "taoAttest::init: can't parse evidence list \n");
        return false;
    }

    m_szCanonicalQuotedBody= canonicalizeXML(m_szQuoteInfo);

    return true;
}


bool taoAttest::bytecodeDigest(byte* out, int* psizeout)
{
    char    szDigest[2*GLOBALMAXDIGESTSIZE];
    int     size= *psizeout;

    if(m_szdigest==NULL) 
        return false;
    if(!fromBase64(strlen(m_szdigest), m_szdigest, &size, out))
        return false;
    *psizeout= size;
    return true;
}


char* taoAttest::codeDigest()
{
    if(m_szdigest==NULL)
        return NULL;
    return strdup(m_szdigest);
}


bool taoAttest::verifyAttestation()
{
    int     type= 0;
    bool    fRet= false;

#ifdef TEST
    fprintf(g_logFile, "taoAttest::verifyAttestation\n");
    fflush(g_logFile);
#endif

    // get parse attest cert
    if(!m_oEvidence.getSubjectEvidence(&type, (void**)&m_pattestCert)) {
        fprintf(g_logFile, "taoAttest::verifyAttestation: can't get attest Cert\n");
        return false;
    }
    if(type!=PRINCIPALCERT) {
        fprintf(g_logFile, "taoAttest::verifyAttestation: attest Cert wrong type\n");
        return false;
    }

    // get quoting key
    m_pquoteKey= (RSAKey*) m_pattestCert->getSubjectKeyInfo();
    if(m_pquoteKey==NULL) {
        fprintf(g_logFile, "taoAttest::verifyAttestation: can't get quoting key from Cert\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "taoAttest::verifyAttestation: quote key\n");
    m_pquoteKey->printMe();
    fflush(g_logFile);
#endif

    // finally, check attestation
    fRet= checkXMLQuote(m_szQuoteAlg, m_szCanonicalQuotedBody, m_sznonce,
                m_szdigest, m_pquoteKey, m_szQuoteValue);
#ifdef TEST
    fprintf(g_logFile, "taoAttest::verifyAttestation: checkXMLQuote succeeds\n");
    m_pquoteKey->printMe();
    fflush(g_logFile);
#endif

    if(!m_oEvidence.validateEvidenceList(m_policyKey)) {
        fprintf(g_logFile, "taoAttest::verifyAttestation: can't verify evidence list \n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "taoAttest::verifyAttestation: evidence valid\n");
    fflush(g_logFile);
#endif

    return fRet;
}


u32 taoAttest::attestType()
{
    return m_attestType;
}


char* taoAttest::quoteAlg()
{
    if(m_szQuoteAlg==NULL)
        return NULL;
    return strdup(m_szQuoteAlg);
}


char* taoAttest::quoteInfo()
{
    if(m_szQuoteInfo==NULL)
        return NULL;
    return strdup(m_szQuoteInfo);
}


char* taoAttest::quoteCanonicalQuotedBody()
{
    if(m_szCanonicalQuotedBody==NULL)
        return NULL;
    return strdup(m_szCanonicalQuotedBody);
}


char* taoAttest::quoteValue()
{
    if(m_szQuoteValue==NULL)
        return NULL;
    return strdup(m_szQuoteValue);
}


char* taoAttest::quoteKeyInfo()
{
    if(m_szQuoteKeyInfo==NULL)
        return NULL;
    return strdup(m_szQuoteKeyInfo);
}


char* taoAttest::quotedKeyInfo()
{
    if(m_szQuotedKeyInfo==NULL)
        return NULL;
    return strdup(m_szQuotedKeyInfo);
}


char* taoAttest::quotedKeyName()
{
    if(m_szQuotedKeyName==NULL)
        return NULL;
    return strdup(m_szQuotedKeyName);
}


// -------------------------------------------------------------------------


