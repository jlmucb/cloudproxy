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
#include "attest.h"
#include "validateEvidence.h"

#include <string.h>
#include <time.h>
#include <unistd.h>


// -------------------------------------------------------------------------


taoAttest::taoAttest()
{
    m_attestType= 0;
    m_sznonce= NULL;
    m_szAttestAlg= NULL;
    m_pattestingCert= NULL;
    m_pattestingKey= NULL;
    m_szAttestAlg= NULL;
}


taoAttest::~taoAttest()
{
    m_attestType= 0;
    if(m_pattestingCert!=NULL) {
        free(m_pattestingCert);
        m_pattestingCert= NULL;
    }
    if(m_szdigest!=NULL) {
        free(m_szdigest);
        m_szdigest= NULL;
    }
}


bool taoAttest::bytecodeDigest(byte* out, int* psizeout)
{
    // char    szDigest[2*GLOBALMAXDIGESTSIZE];
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


bool  taoAttest::init(const char *attestation, const char* attestEvidence, 
                      KeyInfo* policyKey)
{
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
    
#ifdef TEST1
    fprintf(g_logFile, "taoAttest::init, attestation\n%s\nEvidence\n%s\n", 
            attestation, attestEvidence);
    fprintf(g_logFile, "Policy Key\n");
    fflush(g_logFile);
#endif

    if(!m_oAttestation.init(attestation)) {
        fprintf(g_logFile, "taoAttest::init: can't decode attestation\n");
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "taoAttest::init\n");
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

    return true;
}


bool  taoAttest::verifyAttestation(int* psizeattestValue, byte* attestValue,
                                      const char** pdigestalg, int* psizeCodeDigest,
                                      byte* codeDigest, const char** phint)
{
    int     type= 0;
    bool    fRet= false;

#ifdef TEST
    fprintf(g_logFile, "taoAttest::verifyAttestation\n");
    fflush(g_logFile);
#endif

    if(!m_oAttestation.isValid()) {
        fprintf(g_logFile, "taoAttest::verifyAttestation: attestation object not valid\n");
        return false;
    }

    // get parse attest cert
    if(!m_oEvidence.getSubjectEvidence(&type, (void**)&m_pattestingCert)) {
        fprintf(g_logFile, "taoAttest::verifyAttestation: can't get attest Cert\n");
        return false;
    }
    if(type!=PRINCIPALCERT) {
        fprintf(g_logFile, "taoAttest::verifyAttestation: attest Cert wrong type\n");
        return false;
    }

    // get attesting key
    m_pattestingKey= (RSAKey*) m_pattestingCert->getSubjectKeyInfo();
    if(m_pattestingKey==NULL) {
        fprintf(g_logFile, "taoAttest::verifyAttestation: can't get attest key from Cert\n");
        return false;
    }
#ifdef TEST1
    fprintf(g_logFile, "taoAttest::verifyAttestation: attest key\n");
    m_pattestingKey->printMe();
    fflush(g_logFile);
#endif

    // verify 
    fRet= m_oAttestation.checkAttest((KeyInfo*)m_pattestingKey);
#ifdef TEST
    fprintf(g_logFile, "taoAttest::verifyAttestation: verify succeeds\n");
    fflush(g_logFile);
#endif

    if(!m_oAttestation.getAttestedTo(psizeattestValue, attestValue)) {
        fprintf(g_logFile, "taoAttest::verifyAttestation: can't get attestedTo\n");
        fRet= false;;
    }
    if((*pdigestalg= m_oAttestation.getAttestAlg())==NULL) {
        fprintf(g_logFile, "taoAttest::verifyAttestation: can't get attest alg\n");
        fRet= false;;
    }
    if(!m_oAttestation.getcodeDigest(psizeCodeDigest, codeDigest)) {
        fprintf(g_logFile, "taoAttest::verifyAttestation: can't get code digest\n");
        fRet= false;;
    }

    if(!m_oEvidence.validateEvidenceList(m_policyKey)) {
        fprintf(g_logFile, "taoAttest::verifyAttestation: can't verify evidence list \n");
        fRet= false;;
    }
#ifdef TEST
    fprintf(g_logFile, "taoAttest::verifyAttestation: evidence valid\n");
    fflush(g_logFile);
#endif
    *phint= m_oAttestation.getHint();

    return fRet;
}


u32 taoAttest::attestType()
{
    return m_attestType;
}


// -------------------------------------------------------------------------


