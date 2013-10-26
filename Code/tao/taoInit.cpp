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
#include "quote.h"
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

    m_ancestorEvidenceValid= false;
    m_ancestorEvidenceSize= 0;
    m_ancestorEvidence= NULL;

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


const char* g_EvidenceListTemplate= 
"<EvidenceList count='%d'>\n" \
"%s\n"
"</EvidenceList>\n";


char* constructEvidenceList(const char* szEvidence, const char* szEvidenceSupport)
{
    int     sizeList;
    char*   szEvidenceList= NULL;
    char*   szReturn= NULL;

    if(szEvidence==NULL)
        return NULL;

    if(szEvidenceSupport==NULL)
        sizeList= strlen(szEvidence)+256;
    else
        sizeList= strlen(szEvidence)+strlen(szEvidenceSupport)+256;

    szEvidenceList= (char*) malloc(sizeList);
    if(szEvidenceList==NULL)
        return NULL;

    // Fix: later include evidence support
    sprintf(szEvidenceList, g_EvidenceListTemplate, 1, szEvidence);
    szReturn= canonicalizeXML(szEvidenceList);
    if(szEvidenceList!=NULL)
        free(szEvidenceList);
    return szReturn;
}


bool taoInit::generatequoteandcertifyKey(u32 keyType, const char* szKeyName, 
                                const char* szSubjectName, const char* szSubjectId)
{
    // this is the host certificate
    int             sizeHostCert= 0;
    u32             typeHostCert;
    char*           szHostCert= NULL;
    char*           szHostKey= NULL;
    PrincipalCert   hostCert;

    // this is host key evidence
    int             sizeEvidence= 0;
    char*           szEvidence= NULL;                   

    // this is the Quote XML
    char            quotedInfo[4096];   // FIX

    // this is the canonicalize Quote XML
    char*           szCanonicalQuotedBody= NULL;        
    Sha256          oHash;

    // this is the hash of the Quote XML
    int             sizequotedHash= SHA256DIGESTBYTESIZE;
    byte            rgHash[SHA256DIGESTBYTESIZE];       

    // this is the TPM signed quote value
    int             sizequoteValue= 512;    // FIX
    byte            quoteValue[512];        // FIX      

    // this is my measurement
    u32             codeDigestType= 0;
    int             sizeCodeDigest= SHA256DIGESTBYTESIZE;
    byte            codeDigest[SHA256DIGESTBYTESIZE];   
    Sha1            oSha1Hash;

    // this is the final formatted Quote
    u32             quoteType=0;
    char*           szQuote= NULL;                      

#ifdef NAMELOCALITY
    u32             locality= 0x1f;
#endif

#ifdef TEST
    fprintf(g_logFile, "taoInit::generatequoteandcertifyKey(%d)\n", keyType);
#endif
    quotedInfo[0]= 0;
    // quote key valid?
    if(m_myHost==NULL || !m_myHost->m_hostValid) {
        fprintf(g_logFile, "GenerateQuoteAndCertifyKey: host invalid\n");
        return false;
    }

    // compute quote type from host type and key type
    switch(m_myHost->m_hostType) {
      default:
      case PLATFORMTYPENONE:
      case PLATFORMTYPEHYPERVISOR:
        return false;

      case PLATFORMTYPEHW:
        quoteType= QUOTETYPETPM12RSA2048;
        break;

      case PLATFORMTYPEKVMHYPERVISOR:
      case PLATFORMTYPELINUX:
      case PLATFORMTYPEGUESTLINUX:
        if(keyType==KEYTYPERSA1024INTERNALSTRUCT)
            quoteType= QUOTETYPESHA256FILEHASHRSA1024;
        else if(keyType==KEYTYPERSA2048INTERNALSTRUCT)
            quoteType= QUOTETYPESHA256FILEHASHRSA2048;
        else
            return false;
        break;

      case PLATFORMTYPEKVMHOSTEDLINUXGUESTOS:
      case PLATFORMTYPELINUXAPP:
        if(keyType==KEYTYPERSA1024INTERNALSTRUCT)
            quoteType= QUOTETYPESHA256FILEHASHRSA1024;
        else if(keyType==KEYTYPERSA2048INTERNALSTRUCT)
            quoteType= QUOTETYPESHA256FILEHASHRSA2048;
        else
            return false;
        break;
    }

    // generate key pair
    if(!genprivateKeyPair(keyType, szKeyName)) {
        fprintf(g_logFile, "GenerateQuoteAndCertifyKey: Can't generate keypair\n");
        return false;
    }
    RSAKey* pKey= (RSAKey*)m_privateKey;
#ifdef TEST1
    fprintf(g_logFile, "generatequoteandcertifyKey, RSA key generated\n");
    fflush(g_logFile);
    pKey->printMe();
    fflush(g_logFile);
#endif

    // serialize public key
    m_serializedpublicKey= pKey->SerializePublictoString();
    m_publicKeyBlockSize= pKey->m_iByteSizeM;
    if(m_serializedpublicKey==NULL) {
        fprintf(g_logFile, "GenerateQuoteAndCertifyKey: can't serialize public key\n");
        return false;
    }
    m_serializedpublicKeySize= strlen(m_serializedpublicKey)+1;
#ifdef TEST
    fprintf(g_logFile, "generatequoteandcertifyKey, serialized public key\n%s\n", 
            m_serializedpublicKey);
    fflush(g_logFile);
#endif

    // get code digest
    if(!m_myHost->GetHostedMeasurement(&sizeCodeDigest, &codeDigestType, codeDigest)) {
        fprintf(g_logFile, "generatequoteandcertifyKey: Can't get code digest\n");
        return false;
    }
    m_myMeasurementType= codeDigestType;
    if(sizeCodeDigest>m_myMeasurementSize) {
        fprintf(g_logFile, "generatequoteandcertifyKey: code digest too big\n");
        return false;
    }
    m_myMeasurementSize= sizeCodeDigest;
    memcpy(m_myMeasurement, codeDigest, m_myMeasurementSize);
    m_myMeasurementValid= true;

#ifdef TEST
    fprintf(g_logFile, "GenerateQuoteAndCertifyKey\n");
    PrintBytes("Code digest: ", codeDigest, sizeCodeDigest);
    fflush(g_logFile);
#endif

    switch(quoteType) {

      default:
      case QUOTETYPENONE:
      case QUOTETYPETPM12RSA1024:
        fprintf(g_logFile, "GenerateQuoteAndCertifyKey: bad quote type\n");
        return false;

      case QUOTETYPETPM12RSA2048:
        // Construct quote body
#ifdef NAMELOCALITY
        sprintf(quotedInfo, g_quotedkeyInfoTemplate, QUOTEMETHODTPM12RSA2048, 
                locality, m_serializedpublicKey);
#else
        sprintf(quotedInfo, g_quotedkeyInfoTemplate, QUOTEMETHODTPM12RSA2048, 
                m_serializedpublicKey);
#endif
        szCanonicalQuotedBody= canonicalizeXML(quotedInfo);
        if(szCanonicalQuotedBody==NULL) {
            fprintf(g_logFile, 
                "GenerateQuoteAndCertifyKey: Can't canonicalize quoted info\n");
            return false;
        }
        // hash it
        oSha1Hash.Init();
        oSha1Hash.Update((byte*) szCanonicalQuotedBody, strlen(szCanonicalQuotedBody));
        oSha1Hash.Final();
        oSha1Hash.getDigest(rgHash);
        sizequotedHash= SHA1DIGESTBYTESIZE;
        break;

      case QUOTETYPESHA256FILEHASHRSA1024:
        // Construct quote body
        sprintf(quotedInfo, g_quotedkeyInfoTemplate, QUOTEMETHODSHA256FILEHASHRSA1024, 
                m_serializedpublicKey);
        szCanonicalQuotedBody= canonicalizeXML(quotedInfo);
        if(szCanonicalQuotedBody==NULL) {
            fprintf(g_logFile, "GenerateQuoteAndCertifyKey: Can't canonicalize quoted info\n");
            return false;
        }
        // hash it
        oHash.Init();
        oHash.Update((byte*) szCanonicalQuotedBody, 
                     strlen(szCanonicalQuotedBody));
        oHash.Final();
        oHash.GetDigest(rgHash);
        sizequotedHash= SHA256DIGESTBYTESIZE;
        break;

      case QUOTETYPESHA256FILEHASHRSA2048:
        // Construct quote body
        sprintf(quotedInfo, g_quotedkeyInfoTemplate, 
                QUOTEMETHODSHA256FILEHASHRSA2048, m_serializedpublicKey);
        szCanonicalQuotedBody= canonicalizeXML(quotedInfo);
        if(szCanonicalQuotedBody==NULL) {
            fprintf(g_logFile, 
                "GenerateQuoteAndCertifyKey: Can't canonicalize quoted info\n");
            return false;
        }
        // hash it
        oHash.Init();
        oHash.Update((byte*) szCanonicalQuotedBody, 
                     strlen(szCanonicalQuotedBody));
        oHash.Final();
        oHash.GetDigest(rgHash);
        sizequotedHash= SHA256DIGESTBYTESIZE;
        break;
    }

#ifdef TEST
    fprintf(g_logFile, "Hash of Quote Body\n");
    PrintBytes("Quote Body hash: ", rgHash, sizequotedHash);
    fflush(g_logFile);
#endif
    // Do attest
    if(!m_myHost->Attest(sizequotedHash, rgHash, &sizequoteValue, quoteValue)) {
        fprintf(g_logFile, "GenerateQuoteAndCertifyKey: Can't Attest Key\n");
        return false;
    }
#ifdef TEST1
    fprintf(g_logFile, "GenerateQuoteAndCertifyKey: Quotevalue size %d\n", 
                       sizequoteValue);
    PrintBytes("Quotevalue: ", quoteValue, sizequoteValue);
#endif

    // Get the certificate
    if(!m_myHost->GetAttestCertificate(&sizeHostCert, &typeHostCert, (byte**)&szHostCert)) {
        fprintf(g_logFile, "GenerateQuoteAndCertifyKey: Can't get Host cert\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "GenerateQuoteAndCertifyKey: Host certificate\n%s\n", 
                szHostCert);
#endif

    // Get evidence list
    if(!m_myHost->GetEvidence(&sizeEvidence, (byte**)&szEvidence)) 
        szEvidence= NULL;
#ifdef TEST
    fprintf(g_logFile, "GenerateQuoteAndCertifyKey: Host evidence\n%s\n", szEvidence);
#endif

    m_ancestorEvidence= constructEvidenceList(szHostCert, szEvidence);
    if(m_ancestorEvidence==NULL) {
        fprintf(g_logFile, "GenerateQuoteAndCertifyKey: Can't construct new cert evidence\n");
        return false;
    }
    m_ancestorEvidenceValid= true;
    m_ancestorEvidenceSize= strlen(m_ancestorEvidence)+1;
#ifdef TEST1
    fprintf(g_logFile, "GenerateQuoteAndCertifyKey: Constructed evidence\n%s\n", m_ancestorEvidence);
#endif

    if(!hostCert.init(szHostCert)) {
        fprintf(g_logFile, "GenerateQuoteAndCertifyKey: Can't init host key\n");
        return false;
    }
    if(!hostCert.parsePrincipalCertElements()) {
        fprintf(g_logFile, "GenerateQuoteAndCertifyKey: Can't parse host key\n");
        return false;
    }
    RSAKey* hostKey= (RSAKey*)  hostCert.getSubjectKeyInfo();
    if(hostKey==NULL) {
        fprintf(g_logFile, "GenerateQuoteAndCertifyKey: Can't get host subject key\n");
        return false;
    }
    szHostKey= hostKey->SerializePublictoString();
    if(szHostKey==NULL) {
        fprintf(g_logFile, "GenerateQuoteAndCertifyKey: Can't serialize host subject key\n");
        return false;
    }
#ifdef TEST1
    fprintf(g_logFile, "GenerateQuoteAndCertifyKey: Host Key\n%s\n", szHostKey);
#endif

    // Format quote
    szQuote= encodeXMLQuote(0, NULL, sizeCodeDigest, codeDigest, szCanonicalQuotedBody, 
                            szHostKey, sizequoteValue, quoteValue);
    if(szQuote==NULL) {
        fprintf(g_logFile, "GenerateQuoteAndCertifyKey: Can't encode quote\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "GenerateQuoteAndCertifyKey: Quote\n%s\n", szQuote);
#endif

    // Certify it
    if(!KeyNego(szQuote, m_ancestorEvidence, (char**)&m_myCertificate)) {
        fprintf(g_logFile, "GenerateQuoteAndCertifyKey: key nego failed\n");
        return false;
    }
    m_myCertificateValid= true;
    m_myCertificateType= EVIDENCECERT;
    m_myCertificateSize= strlen(m_myCertificate)+1;
#ifdef TEST
    fprintf(g_logFile, "GenerateQuoteAndCertifyKey: my Cert\n%s\n", m_myCertificate);
#endif

    // Serialize private key
    m_szserializedPrivateKey= pKey->SerializetoString();
    if(m_szserializedPrivateKey==NULL) {
        fprintf(g_logFile, "GenerateQuoteAndCertifyKey: Can't serialize private key\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, 
            "generatequoteandcertifyKey returns true, serialized private key\n%s\n",
            m_szserializedPrivateKey);
    fflush(g_logFile);
#endif
    // Fix: clean up szHostCert and szEvidence
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

    fRet= generatequoteandcertifyKey(pubkeyType, szKeyName, 
                                     szSubjectName, szSubjectId);
    if(!fRet)
        goto cleanup;

#ifdef TEST
    fprintf(g_logFile, "taoInit::initKeys succeeded, public key\n%s\n", 
            m_serializedpublicKey);
#endif
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
    if(szKeyName!=NULL && strlen(szKeyName)<(KEYNAMEBUFSIZE-1)) {
        pKey->m_ikeyNameSize= strlen(szKeyName);
        memcpy(pKey->m_rgkeyName, szKeyName, pKey->m_ikeyNameSize+1);
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


