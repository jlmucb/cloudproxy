//
//  File: cryptSupport.h
//      John Manferdelli
//
//  Description:
//
//  Copyright (c) 2011, Intel Corporation. All rights reserved.
//  Incorporates contributions  (c) John Manferdelli.  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without 
//  modification, are permitted provided that the following conditions 
//  are met:
//    Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the disclaimer below.
//    Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the disclaimer below in the 
//      documentation and/or other materials provided with the distribution.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
//  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
//  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//  HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
//  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
//  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
//  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
//  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


// ---------------------------------------------------------------------------------


#ifndef _CRYPTSUPPORT__H
#define _CRYPTSUPPORT__H

#include "sha1.h"
#include "tinyxml.h"


#define QUOTEMETHODNONE                     (char*)"none"
#define QUOTEMETHODTPM12RSA2048             (char*)"Quote-TPM1.2-RSA2048"
#define QUOTEMETHODTPM12RSA1024             (char*)"Quote-TPM1.2-RSA2048"
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
      

class PrincipalCert {
public:
    bool        m_fSigValuesValid;
    char*       m_szSignature;
    char*       m_szSignedInfo;
    char*       m_szSignatureValue;
    char*       m_szSignatureMethod;
    char*       m_szCanonicalizationMethod;
    char*       m_szPrincipalName;
    char*       m_szRevocationInfo;
    KeyInfo*    m_pSignerKeyInfo;
    RSAKey*     m_pSubjectKeyInfo;
    Period      m_ovalidityPeriod;

    PrincipalCert();
    ~PrincipalCert();

    bool        init(char* szSig);
    KeyInfo*    getSubjectKeyInfo();
    bool        parsePrincipalCertfromRoot(TiXmlElement*  pRootElement);
    bool        parsePrincipalCertElements();
    bool        getvalidityPeriod(Period& period);
    char*       getCanonicalwasSigned();
    char*       getCanonicalizationMethod();
    char*       getRevocationPolicy();
    char*       getSignatureValue();
    char*       getSignatureAlgorithm();
    char*       getPrincipalName();
#ifdef TEST
    void        printMe();
#endif
};


RSAKey* keyfromkeyInfo(char* szKeyInfo);
bool verifyXMLQuote(char* szQuoteAlg, char* szCanonicalQuotedBody, char* sznonce, 
                char* szdigest, KeyInfo* pKeyInfo, char* szQuoteValue);


#endif


// -------------------------------------------------------------------------------------


