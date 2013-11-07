//  File: taoInit.cpp
//      John Manferdelli
//  Description: Key negotiation for the Tao.
//               This is the revised version after the paper
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
#include "sha256.h"
#include "sha1.h"
#include "tao.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "trustedKeyNego.h"
#ifdef TPMSUPPORT
#include "TPMHostsupport.h"
#include "hashprep.h"
#endif
#include "linuxHostsupport.h"
#include "cert.h"
// #include "quote.h"
#include "attest.h"
#include "cryptoHelper.h"

#include <string.h>
#include <time.h>


// -------------------------------------------------------------------------


taoInit::taoInit(taoHostServices* host)
{
    m_myHost= host;

    m_symKeyValid= false;
    m_symKeyType= 0;
    m_symKeySize= 0;
    m_symKey= NULL;

    m_privateKeyValid= false;
    m_privateKeyType= 0;
    m_privateKeySize= 0;
    m_privateKey= NULL;

    m_myCertificateValid= false;
    m_myCertificateType= 0;
    m_myCertificateSize= 0;
    m_myCertificate= NULL;

    m_myMeasurementValid= false;
    m_myMeasurementType= 0;
    m_myMeasurementSize= 32;

    m_evidenceValid= false;
    m_evidenceSize= 0;
    m_szevidence= NULL;

    m_sizeserializedPrivateKey= 0;
    m_szserializedPrivateKey= NULL;

    m_publicKeyValid= false;
    m_publicKeySize= 0; 
    m_publicKey= NULL;

    m_serializedpublicKeySize= 0;
    m_serializedpublicKey= NULL;
    m_publicKeyBlockSize= 0;
}


taoInit::~taoInit()
{
}


#ifdef NAMELOCALITY
const char* g_quotedkeyInfoTemplate= 
"<QuotedInfo>\n" \
"    <ds:CanonicalizationMethod Algorithm=\"http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#\"/>  " \
"    <ds:QuoteMethod Algorithm=\"%s\"/>\n" \
"    <Locality locality= \"%02x\"/>\n" \
"%s\n" \
"</QuotedInfo>\n";
#else
const char* g_quotedkeyInfoTemplate= 
"<QuotedInfo>\n" \
"    <ds:CanonicalizationMethod Algorithm=\"http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#\"/>  " \
"    <ds:QuoteMethod Algorithm=\"%s\"/>\n" \
"%s\n" \
"</QuotedInfo>\n";
#endif


bool taoInit::generateandcertifyKey(u32 keyType, const char* szKeyName, 
                                         const char* szSubjectName, const char* szSubjectId)
{
    Attestation     oAttestation;
    AttestInfo      oAttestInfo;
    const char*     szHostCert= NULL;
    const char*     szHostEvidence= NULL;
    const char*     szEvidence= NULL;

#ifdef NAMELOCALITY
    u32             locality= 0x1f;
#endif

#ifdef TEST
    fprintf(g_logFile, "taoInit::generateandcertifyKey(%d)\n", keyType);
#endif
    // attest key valid?
    if(m_myHost==NULL || !m_myHost->isValid()) {
        fprintf(g_logFile, "taoInit::generateandcertifyKey: host invalid\n");
        return false;
    }

    // generate key pair
    if(!genprivateKeyPair(keyType, szKeyName)) {
        fprintf(g_logFile, "taoInit::generateandcertifyKey: Can't generate keypair\n");
        return false;
    }
    RSAKey* pKey= (RSAKey*)m_privateKey;

#ifdef TEST1
    fprintf(g_logFile, "generateandcertifyKey, RSA key generated\n");
    fflush(g_logFile);
    pKey->printMe();
    fflush(g_logFile);
#endif

    // serialize public key
    m_serializedpublicKey= pKey->SerializePublictoString();
    m_publicKeyBlockSize= pKey->m_iByteSizeM;
    if(m_serializedpublicKey==NULL) {
        fprintf(g_logFile, "taoInit::generateandcertifyKey: can't serialize public key\n");
        return false;
    }
    m_serializedpublicKeySize= strlen(m_serializedpublicKey)+1;
#ifdef TEST1
    fprintf(g_logFile, "generateandcertifyKey, serialized public key\n%s\n", 
            m_serializedpublicKey);
    fflush(g_logFile);
#endif

    // get my measurement
    if(!m_myHost->GetHostedMeasurement(&m_myMeasurementSize, &m_myMeasurementType, m_myMeasurement)) {
        fprintf(g_logFile, "generateandcertifyKey: Can't get code digest\n");
        return false;
    }
    m_myMeasurementValid= true;

    // make attestInfo
    const char*   szAttestInfo= oAttestInfo.makeKeyAttestInfo(m_serializedpublicKey);
    if(szAttestInfo==NULL) {
        fprintf(g_logFile, "taoInit::generateandcertifyKey: can't make attestInfo\n");
        return false;
    }

    // FIX: Locality
    if(!oAttestInfo.init(szAttestInfo)) {
        fprintf(g_logFile, "taoInit::generateandcertifyKey: can't initialize attestInfor from string\n");
        return false;
    }
#ifdef TEST1
    fprintf(g_logFile, "generateandcertifyKey, attestInfo\n%s\n", szAttestInfo);
    fflush(g_logFile);
#endif

    int     sizeHash= 32;
    byte    attestInfoHash[32];
    switch(m_myHost->hostType()) {
      case PLATFORMTYPEHW:
        if(!oAttestInfo.getAttestInfoHash(SHA1HASH, &sizeHash, attestInfoHash)) {
            fprintf(g_logFile,
                    "taoInit::generateandcertifyKey: can't get AttestInfo hash\n");
            return false;
        }
        break;
      default:
        if(!oAttestInfo.getAttestInfoHash(SHA256HASH, &sizeHash, attestInfoHash)) {
            fprintf(g_logFile, "taoInit::generateandcertifyKey: can't get AttestInfo hash\n");
            return false;
        }
        break;
    }
#ifdef TEST1
    PrintBytes("attestInfo hash: ", attestInfoHash, sizeHash);
    fflush(g_logFile);
#endif

    // make attest
    const char* szAttestation= m_myHost->makeAttestation(sizeHash, attestInfoHash, szAttestInfo);
    if(szAttestation==NULL) {
        fprintf(g_logFile, "taoInit::generateandcertifyKey: can't attestation from host\n");
        return false;
    }

    // free szAttestInfo
    if(szAttestInfo!=NULL) {
        free((char*)szAttestInfo);
        szAttestInfo= NULL;
    }
#ifdef TEST1
    fprintf(g_logFile, "taoInit::generateandcertifyKey: attestation\n%s\n", szAttestation);
    fflush(g_logFile);
#endif

    // Evidence is concatination of host cert and host evidence
    szHostCert= m_myHost->GetCertificateString();
    if(szHostCert==NULL) {
        fprintf(g_logFile, "taoInit::generateandcertifyKey: no host cert\n");
        return false;
    }
    szHostEvidence= m_myHost->GetEvidenceString();
    szEvidence= consttoEvidenceList(szHostCert, szHostEvidence);
#ifdef TEST1
    fprintf(g_logFile, "taoInit::generateandcertifyKey: cert\n%s\nHost evidence:\n%s\n", 
            szHostCert, szHostEvidence);
    fprintf(g_logFile, "Final evidence:\n%s\n", szEvidence);
    fflush(g_logFile);
#endif

    // Certify it
    bool fRet= KeyNego(szAttestation, szEvidence, (char**)&m_myCertificate);
    if(szAttestation!=NULL) {
        free((char*)szAttestation);
        szAttestation= NULL;
    }
    if(szHostCert!=NULL) {
        free((char*)szHostCert);
        szHostCert= NULL;
    }
    if(szHostEvidence!=NULL) {
        free((char*)szHostEvidence);
        szHostEvidence= NULL;
    }
    if(szEvidence!=NULL) {
        free((char*)szEvidence);
        szEvidence= NULL;
    }
    if(!fRet) {
        fprintf(g_logFile, "taoInit::generateandcertifyKey: key nego failed\n");
        return false;
    }
    m_myCertificateValid= true;
    m_myCertificateType= EVIDENCECERT;
    m_myCertificateSize= strlen(m_myCertificate)+1;

    // Serialize private key
    m_szserializedPrivateKey= pKey->SerializetoString();
    if(m_szserializedPrivateKey==NULL) {
        fprintf(g_logFile, "taoInit::generateandcertifyKey: Can't serialize private key\n");
        return false;
    }
#ifdef TEST1
    fprintf(g_logFile, 
            "generateandcertifyKey returns true, serialized private key\n%s\n",
            m_szserializedPrivateKey);
    fflush(g_logFile);
#endif
    return true;
}


bool taoInit::initKeys(u32 symType, u32 pubkeyType, const char* szKeyName, 
                       const char* szSubjectName, const char* szSubjectId)
{
    bool        fRet= false;

#ifdef TEST
    fprintf(g_logFile, "taoInit::initKeys\n");
    fflush(g_logFile);
#endif
    fRet= gensymKey(symType);
    if(!fRet)
        return false;

    fRet= generateandcertifyKey(pubkeyType, szKeyName, 
                                     szSubjectName, szSubjectId);
    if(!fRet)
        goto cleanup;

cleanup:
    // if false clean up private key and cert
    return fRet;
}


bool taoInit::gensymKey(u32 symType)
{
    if(symType!=KEYTYPEAES128PAIREDENCRYPTINTEGRITY)
        return false;
    m_symKeyValid= true;
    m_symKeySize= 32;
    m_symKey= (byte*) malloc(m_symKeySize);
    if(m_symKey==NULL)
        return false;
    if(!getCryptoRandom(m_symKeySize*NBITSINBYTE, m_symKey))
        return false;
    return true;
}


bool taoInit::genprivateKeyPair(u32 keyType, const char* szKeyName)
{
    int         ikeySize= 0;
    RSAKey*     pKey= NULL;

#ifdef TEST
    fprintf(g_logFile, "genprivateKeyPair(%d)\n", (int) keyType);
#endif
    if(keyType==KEYTYPERSA1024INTERNALSTRUCT) {
        ikeySize= 1024;
    }
    else if(keyType==KEYTYPERSA2048INTERNALSTRUCT) {
       ikeySize= 2048;
    }
    else
        return false;

    pKey= RSAGenerateKeyPair(ikeySize);
    if(pKey==NULL) {
        fprintf(g_logFile, "taoEnvironment::genprivateKeyPair: Can't generate RSA key pair\n");
        return false;
    }
    if(szKeyName!=NULL) {
        pKey->m_ikeyNameSize= strlen(szKeyName);
        pKey->m_rgkeyName= strdup(szKeyName);
    }

    m_privateKeyType= keyType;
    m_privateKeySize= sizeof(RSAKey);
    m_privateKey= (byte*)pKey;
    if(m_privateKey==NULL)
        return false;

    m_privateKeyValid= true;
    return true;
}


// --------------------------------------------------------------------------


