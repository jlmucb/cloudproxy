//
//  claims.h
//      John Manferdelli
//
//  Description: trusted computing interfaces
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


#ifndef _CLAIMS__H
#define _CLAIMS__H

#include "jlmTypes.h"
#include "jlmcrypto.h"
#include "keys.h"
#include "claims.h"
#include "time.h"
#include "rsaHelper.h"
#include "sha256.h"
#include "sha1.h"
#include "tinyxml.h"
#include <time.h>


#define QUOTEMETHODNONE                     "none"
#define QUOTEMETHODTPM12RSA2048             "Quote-TPM1.2-RSA2048"
#define QUOTEMETHODTPM12RSA1024             "Quote-TPM1.2-RSA1024"
#define QUOTEMETHODSHA256FILEHASHRSA1024    "Quote-Sha256FileHash-RSA1024"
#define QUOTEMETHODSHA256FILEHASHRSA2048    "Quote-Sha256FileHash-RSA2048"

#define RSA1024SIGALG  "http://www.manferdelli.com/2011/Xml/algorithms/rsa1024-sha256-pkcspad#"
#define RSA2048SIGALG "http://www.manferdelli.com/2011/Xml/algorithms/rsa2048-sha256-pkcspad#"


class Quote {
public:
    TiXmlDocument   m_doc;
    TiXmlNode*      m_pNodeQuote;
    TiXmlNode*      m_pNodeNonce;
    TiXmlNode*      m_pNodeCodeDigest;
    TiXmlNode*      m_pNodeQuotedInfo;
    TiXmlNode*      m_pNodeQuoteValue;
    TiXmlNode*      m_pNodequoteKeyInfo;
    TiXmlNode*      m_pNodequotedKeyInfo;
    char*           m_szQuotealg;

    Quote();
    ~Quote();

    bool        init(const char* szXMLQuote);
    char*       getCanonicalQuoteInfo();
    char*       getQuoteValue();
    char*       getnonceValue();
    char*       getcodeDigest();
    char*       getQuoteAlgorithm();
    char*       getquotekeyInfo();
    char*       getquotedkeyInfo();
};


#define MAXNUMEVIDENCE 25


bool    sameRSAKey(RSAKey* pKey1, RSAKey* pKey2);
bool    checkXMLSignature(const char* szSigAlgorithm, const char* szCanonicalSignedBody, 
                          KeyInfo* pKeyInfo, const char* szSignatureValue);
bool    checkXMLQuote(const char* szQuoteAlg, const char* szCanonicalQuotedBody, const char* sznonce, 
                const char* szdigest, KeyInfo* pKeyInfo, const char* szQuoteValue);

char*   keyInfofromKey(RSAKey* pKey);
RSAKey* keyfromkeyInfo(const char* szKeyInfo);

char*   encodeXMLQuote(int sizenonce, byte* nonce, int sizeCodeDigest, 
            byte* codeDigest, const char* szQuotedInfo, const char* szKeyInfo, 
            int sizeQuote, byte* quote);
bool    decodeXMLQuote(const char* szXMLQuote, char** pszAlg, char** psznonce, 
            char** pszDigest, char** pszQuotedInfo, char** pszQuoteValue, 
            char** pszquoteKeyInfo, char** pszquotedKeyInfo);

char*   getSerializedKeyfromCert(const char* szCert);
char*   formatCert(const char* szSignedInfo, const char* szSig);
char*   formatSignedInfo(RSAKey* pKey, 
            const char* szCertid, int serialNo, const char* szPrincipalType, 
            const char* szIssuerName, const char* szIssuerID, const char* szNotBefore, 
            const char* szNotAfter, const char* szSubjName, const char* szKeyInfo, 
            const char* szDigest, const char* szSubjKeyID);
char*   consttoEvidenceList(const char* szEvidence, const char* szEvidenceSupport);
bool	sha256quoteHash(int sizenonce, byte* nonce, 
                     int sizetobeSignedHash, byte* tobesignedHash, 
                     int sizecodeHash, byte* codeHash, byte* outputHash);
#endif


// --------------------------------------------------------------------------


