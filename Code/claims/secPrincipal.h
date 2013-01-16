//
//  secPrincipal.h
//      John Manferdelli
//
//  Description: security principal classes
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


#ifndef _SECPRINCIPAL__H
#define _SECPRINCIPAL__H


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
    bool        sameAs(PrincipalCert& oPrinc);
#ifdef TEST
    void        printMe();
#endif
};


class certificateInfo {
public:
    char*       szId;
    char*       szSerialNumber;
    char*       szPrincipalType;
    char*       szIssuerName;
    char*       szIssuerId;
    Period      ValidityPeriod;
    char*       szSubjectName;
    char*       szSubjectKeyID;
    char*       szSubjectKeyType;
    void*       pSubjectKey;
    char*       szAuthorityKeyId;
    char*       szKeyUsage;
    Period      PrivateKeyValidityPeriod;
    char*       szCertificateEvaluationPolicy;
    char*       szAlternateSubjectName;
    char*       szAlternateIssuerName;
    char*       szRevocationPolicy;
    char*       szConstraints;

};


#define  NOPRINCIPAL        0
#define  COMPOUNDPRINCIPAL  1
#define  CODEPRINCIPAL      2
#define  USERPRINCIPAL      3
#define  MACHINEPRINCIPAL   4
#define  CHANNELPRINCIPAL   5
#define  POLICYPRINCIPAL    6


class accessPrincipal {
public:
    char*               m_szPrincipalName;
    u32                 m_uPrincipalType; 
    bool                m_fValidated;
    PrincipalCert*      m_pCert;

    accessPrincipal();
    ~accessPrincipal();
    void                printMe();
    char*               getName();
    int                 auxSize();
    bool                Deserialize(byte* szObj, int* pi);
    int                 Serialize(byte* sz);
};


#define NOEVIDENCE              0
#define EMBEDDEDPOLICYPRINCIPAL 1
#define PRINCIPALCERT           2
#define KEYINFO                 3
#define SIGNEDGRANT             4
#define SIGNEDX509CERT          5
#define ATTESTATION             6


#define VALID               1
#define INVALIDSIG       (-1)
#define INVALIDPRINCIPAL (-2)
#define INVALIDPERIOD    (-3)
#define INVALIDREVOKED   (-4)
#define INVALIDPARENT    (-5)
#define INVALIDRIGHTS    (-6)
#define INVALIDEVIDENCE  (-7)


int              VerifyEvidenceList(tm* pt, int npieces, int* rgType, void** rgObject, 
                                    RSAKey* pRootKey, RSAKey* pTopKey=NULL);
accessPrincipal* principalFromCert(PrincipalCert* pCert, bool fValidated);


#define STATICNUMLISTELTS 8


class evidenceList {
public:
    bool            m_fParsed;
    bool            m_fValid;
    int             m_iNumPiecesofEvidence;

    int             m_rgistaticEvidenceTypes[STATICNUMLISTELTS];
    void*           m_rgstaticEvidence[STATICNUMLISTELTS];
    int*            m_rgiEvidenceTypes;
    void**          m_rgEvidence;

    evidenceList();
    ~evidenceList();

    bool    parseEvidenceList(TiXmlElement* pRootElement);
    bool    validateEvidenceList(RSAKey* pRootKey, RSAKey* pTopKey);
};


#define STATICNUMCOLLECTIONELTS  20


class evidenceCollection {
public:
    bool            m_fParsed;
    bool            m_fValid;
    int             m_iNumEvidenceLists;

    int             m_rgistaticCollectionTypes[STATICNUMCOLLECTIONELTS];
    evidenceList*   m_rgstaticCollectionList[STATICNUMCOLLECTIONELTS];

    int*            m_rgiCollectionTypes;
    evidenceList**  m_rgCollectionList;

    evidenceCollection();
    ~evidenceCollection();

    bool            parseEvidenceCollection(char* szEvidenceCollection);
    bool            validateEvidenceCollection(RSAKey* pRootKey);
};


class SignedAssertion {
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
    int         m_iNumAssertions;
    char**      m_rgszAssertion;

    SignedAssertion();
    ~SignedAssertion();

    bool        init(char* szSig);
    KeyInfo*    getSubjectKeyInfo();
    bool        parseSignedAssertionElements();
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


#endif


// ----------------------------------------------------------------------------


