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


#define QUOTEMETHODNONE                     (char*)"none"
#define QUOTEMETHODTPM12RSA2048             (char*)"Quote-TPM1.2-RSA2048"
#define QUOTEMETHODTPM12RSA1024             (char*)"Quote-TPM1.2-RSA1024"
#define QUOTEMETHODSHA256FILEHASHRSA1024    (char*)"Quote-Sha256FileHash-RSA1024"
#define QUOTEMETHODSHA256FILEHASHRSA2048    (char*)"Quote-Sha256FileHash-RSA2048"

#define RSA1024SIGALG  (char*)"http://www.manferdelli.com/2011/Xml/algorithms/rsa1024-sha256-pkcspad#"
#define RSA2048SIGALG (char*)"http://www.manferdelli.com/2011/Xml/algorithms/rsa2048-sha256-pkcspad#"


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

    bool        init(char* szXMLQuote);
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
bool    checkXMLSignature(char* szSigAlgorithm, char* szCanonicalSignedBody, 
                          KeyInfo* pKeyInfo, char* szSignatureValue);
bool    checkXMLQuote(char* szQuoteAlg, char* szCanonicalQuotedBody, char* sznonce, 
                char* szdigest, KeyInfo* pKeyInfo, char* szQuoteValue);

char*   keyInfofromKey(RSAKey* pKey);
RSAKey* keyfromkeyInfo(char* szKeyInfo);

char*   encodeXMLQuote(int sizenonce, byte* nonce, int sizeCodeDigest, 
            byte* codeDigest, char* szQuotedInfo, char* szKeyInfo, 
            int sizeQuote, byte* quote);
bool    decodeXMLQuote(char* szXMLQuote, char** pszAlg, char** psznonce, 
            char** pszDigest, char** pszQuotedInfo, char** pszQuoteValue, 
            char** pszquoteKeyInfo, char** pszquotedKeyInfo);

char*   getSerializedKeyfromCert(char* szCert);
char*   formatCert(char* szSignedInfo, char* szSig);
char*   formatSignedInfo(RSAKey* pKey, 
            char* szCertid, int serialNo, char* szPrincipalType, 
            char* szIssuerName, char* szIssuerID, char* szNotBefore, 
            char* szNotAfter, char* szSubjName, char* szKeyInfo, 
            char* szDigest, char* szSubjKeyID);
char*   consttoEvidenceList(char* szEvidence, char* szEvidenceSupport);
bool	sha256quoteHash(int sizenonce, byte* nonce, 
                     int sizetobeSignedHash, byte* tobesignedHash, 
                     int sizecodeHash, byte* codeHash, byte* outputHash);
#endif


// --------------------------------------------------------------------------


