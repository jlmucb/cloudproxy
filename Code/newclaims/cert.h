//
//  cert.h
//      John Manferdelli
//
//  Description: certificate principal classes
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
#include "keys.h"
#include "cryptoHelper.h"
#include "tinyxml.h"
#include <time.h>


// ---------------------------------------------------------------------


#ifndef _CERT__H
#define _CERT__H


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

    bool        init(const char* szSig);
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
    bool        sameAs(PrincipalCert& oPrinc);
#ifdef TEST
    void        printMe();
#endif
};

char*   formatCert(const char* szSignedInfo, const char* szSig);
char*   formatSignedInfo(RSAKey* pKey, 
            const char* szCertid, int serialNo, const char* szPrincipalType, 
            const char* szIssuerName, const char* szIssuerID, const char* szNotBefore, 
            const char* szNotAfter, const char* szSubjName, const char* szKeyInfo, 
            const char* szDigest, const char* szSubjKeyID);

#endif


// ----------------------------------------------------------------------------


