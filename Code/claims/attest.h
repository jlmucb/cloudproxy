//
//  attest.h
//      John Manferdelli
//
//  Description: attest interfaces
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


#ifndef _ATTEST__H
#define _ATTEST__H

#include "jlmTypes.h"
#include "jlmcrypto.h"
#include "keys.h"
#include "attest.h"
#include "time.h"
#include "cryptoHelper.h"
#include "sha256.h"
#include "sha1.h"
#include "tinyxml.h"
#include <time.h>


#define ATTESTMETHODNONE                     "none"
#define ATTESTMETHODTPM12RSA2048             "Attest-TPM1.2-RSA2048"
#define ATTESTMETHODTPM12RSA1024             "Attest-TPM1.2-RSA1024"
#define ATTESTMETHODSHA256FILEHASHRSA1024    "Attest-Sha256FileHash-RSA1024"
#define ATTESTMETHODSHA256FILEHASHRSA2048    "Attest-Sha256FileHash-RSA2048"

#define RSA1024SIGALG  "http://www.manferdelli.com/2011/Xml/algorithms/rsa1024-sha256-pkcspad#"
#define RSA2048SIGALG "http://www.manferdelli.com/2011/Xml/algorithms/rsa2048-sha256-pkcspad#"

// maximum string size of a quote
#define MAXATTESTDINFOSIZE  8192


class Attest {
private:
    TiXmlDocument   m_doc;
    TiXmlNode*      m_pNodeAttest;
    TiXmlNode*      m_pNodeNonce;
    TiXmlNode*      m_pNodeCodeDigest;
    TiXmlNode*      m_pNodeInterpretationHint;
    TiXmlNode*      m_pNodeAttestedValue;
    TiXmlNode*      m_pNodeAttestValue;
    TiXmlNode*      m_pNodeattestingKeyInfo;
    char*           m_szAttestalg;

public:
    Attest();
    ~Attest();

    bool            init(const char* attestation);
    const char*     getAttestAlg();
    const char*     getAttestValue();
    const char*     getnonceValue();
    const char*     getattestingkeyInfo();
    const char*     getInterpretationHint();

    const char*     encodeAttest();
    bool            decodeAttest(); 
    bool            checkAttest();
};


class AttestInfo {
private:
    TiXmlDocument   m_doc;
    TiXmlNode*      m_pNodeAttestInfo;
    TiXmlNode*      m_pKeyInfo;

public:
    AttestInfo();
    ~AttestInfo();

    bool            init(const char* attestInfo);
    const char*     getSerializedKey();
    bool            getAttestInfoHash();
};


bool    sha256quoteHash(int sizenonce, byte* nonce, 
                     int sizetobeSignedHash, byte* tobesignedHash, 
                     int sizecodeHash, byte* codeHash, byte* outputHash);
#endif


// --------------------------------------------------------------------------


