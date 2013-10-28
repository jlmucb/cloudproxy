//
//  signedAssertion.h
//      John Manferdelli
//
//  Description: Signed Assertion classes
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
#include "tinyxml.h"
#include <time.h>


// ---------------------------------------------------------------------


#ifndef _SIGNEDASSERTION__H
#define _SIGNEDASSERTION__H


#define MAXPRINCIPALNAME  512


class Assertion {
public:
    char*   m_szSubject;
    char*   m_szRight;
    char*   m_szObject;

    Assertion();
    ~Assertion();

    bool   parseMe(const char* szAssert);
#ifdef TEST
    void   printMe();
#endif
};


class SignedAssertion {
public:
    bool            m_fDocValid;
    TiXmlDocument   m_doc;
    TiXmlElement*   m_pRootElement;

    bool            m_fSigValuesValid;
    char*           m_szSignature;
    char*           m_szSignedInfo;
    char*           m_szSignatureValue;
    char*           m_szSignatureMethod;
    char*           m_szCanonicalizationMethod;
    char*           m_szPrincipalName;
    char*           m_szRevocationInfo;
    KeyInfo*        m_pSignerKeyInfo;
    RSAKey*         m_pSubjectKeyInfo;
    Period          m_ovalidityPeriod;
    Assertion*      m_pAssertion;

    SignedAssertion();
    ~SignedAssertion();

    bool            init(const char* szSig);
    KeyInfo*        getSubjectKeyInfo();
    bool            parseSignedAssertionElements();
    bool            getvalidityPeriod(Period& period);
    char*           getCanonicalwasSigned();
    char*           getCanonicalizationMethod();
    char*           getRevocationPolicy();
    char*           getSignatureValue();
    char*           getSignatureAlgorithm();
    char*           getPrincipalName();

    char*           getGrantSubject();
    char*           getGrantRight();
    char*           getGrantObject();

    bool            parseAssertion();

#ifdef TEST
    void            printMe();
#endif
};


#endif


// ----------------------------------------------------------------------------


