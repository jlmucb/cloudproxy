//
//  validateEvidence.h
//      John Manferdelli
//
//  Description: evidence validation classes
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


#ifndef _VALIDATEEVIDENCE__H
#define _VALIDATEEVIDENCE__H


// evidence types
#define NOEVIDENCE              0
#define EMBEDDEDPOLICYPRINCIPAL 1
#define PRINCIPALCERT           2
#define KEYINFO                 3
#define SIGNEDGRANT             4
#define QUOTECERTIFICATE        5


// validation errors
#define VALID                   1
#define INVALIDSIG           (-1)
#define INVALIDPRINCIPAL     (-2)
#define INVALIDPERIOD        (-3)
#define INVALIDREVOKED       (-4)
#define INVALIDPARENT        (-5)
#define INVALIDRIGHTS        (-6)
#define INVALIDEVIDENCE      (-7)
#define INVALIDROOT          (-8)
#define INVALIDPURPOSE       (-9)


int  VerifyChain(RSAKey& rootKey, const char* szPurpose, tm* pt,
                 int npieces, int* rgType, void** rgObject);


#define STATICNUMLISTELTS 8
#define STATICNUMCOLLECTIONELTS  20


class evidenceList {
public:
    bool            m_fParsed;
    bool            m_fValid;

    bool            m_fDocValid;
    TiXmlDocument   m_doc;
    TiXmlElement*   m_pRootElement;

    int             m_iNumPiecesofEvidence;
    int             m_rgistaticEvidenceTypes[STATICNUMLISTELTS];
    void*           m_rgstaticEvidence[STATICNUMLISTELTS];
    int*            m_rgiEvidenceTypes;
    void**          m_rgEvidence;

    evidenceList();
    ~evidenceList();

    bool    parseEvidenceList(TiXmlElement* pRootElement);
    bool    validateEvidenceList(RSAKey* pRootKey);
};


class evidenceCollection {
public:
    bool            m_fValid;

    TiXmlDocument   m_doc;

    bool            m_fParsed;
    TiXmlElement*   m_pRootElement;

    int             m_iNumEvidenceLists;
    int             m_rgistaticCollectionTypes[STATICNUMCOLLECTIONELTS];
    evidenceList*   m_rgstaticCollectionList[STATICNUMCOLLECTIONELTS];

    int*            m_rgiCollectionTypes;
    evidenceList**  m_rgCollectionList;

    evidenceCollection();
    ~evidenceCollection();

    bool            parseEvidenceCollection(const char* szEvidenceCollection);
    bool            validateEvidenceCollection(RSAKey* pRootKey);
};


#endif


// ----------------------------------------------------------------------------


