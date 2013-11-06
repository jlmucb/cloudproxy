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


class Attestation {
private:
    bool            m_fValid;
    TiXmlDocument   m_doc;
    TiXmlNode*      m_pNodeAttest;
    TiXmlNode*      m_pNodeNonce;
    TiXmlNode*      m_pNodeCodeDigest;
    TiXmlNode*      m_pNodeAttestedValue;
    TiXmlNode*      m_pNodeAttestation;
    TiXmlNode*      m_pNodeattestingKeyInfo;
    TiXmlNode*      m_pNodeInterpretationHint;

    char*           m_szAttestType;
    char*           m_szAttestalg;
    char*           m_szCanonicalizationalg;
    char*           m_szcodeDigest;
    char*           m_szattestedValue;
    char*           m_szattestation;
    char*           m_szNonce;
    char*           m_typeDigest;
    char*           m_szKeyInfo;
    char*           m_szHint;
    int             m_sizecodeDigest;
    byte*           m_codeDigest;
    int             m_sizeattestedTo;
    byte*           m_attestedTo;
    int             m_sizeattestation;
    byte*           m_attestation;
    int             m_locality;
    u32             m_pcrMask;

public:
    Attestation();
    ~Attestation();

    bool            isValid() {return m_fValid;};
    bool            init(const char* attestation);
    const char*     getAttestAlg();
    const char*     getAttestation();
    const char*     getAttestedTo();
    const char*     getNonce();
    const char*     getattestingkeyInfo();

    bool            setTypeDigest(const char* szTypeDigest);
    bool            setAttestAlg(const char* alg);
    bool            setKeyInfo(const char* szKeyInfo);
    bool            setAttestedTo(int size, byte* attestedTo);
    bool            getAttestedTo(int* psize, byte* attestedTo);
    bool            setAttestation(int size, byte* attestation);
    bool            getAttestation(int* psize, byte* attestation);
    bool            setcodeDigest(int size, byte* codeDigest);
    bool            getcodeDigest(int* psize, byte* codeDigest);
    bool            setHint(const char* hint);
    const char*     getHint();
    const char*     getbase64codeDigest();
    bool            setLocality(int loc);
    int             getLocality();
    bool            setpcrMask(u32 loc);
    u32             getpcrMask();


    bool            converttoBinary();
    bool            convertfromBinary();

    const char*     encodeAttest();
    bool            checkAttest(KeyInfo* pKeyInfo);
};


class AttestInfo {
private:
    bool            m_fValid;
    TiXmlDocument   m_doc;
    TiXmlNode*      m_pNodeAttestInfo;
    TiXmlNode*      m_pKeyInfo;
    int             m_sizeHash;
    u32             m_hashType;
    byte            m_hash[GLOBALMAXDIGESTSIZE];
    const char*     m_szHash;

public:
    AttestInfo();
    ~AttestInfo();

    bool            isValid() {return m_fValid;};
    const char*     makeKeyAttestInfo(const char* szSerializedKey);
    bool            init(const char* attestInfo);
    const char*     getSerializedKey();
    const char*     getKeyName();
    bool            getAttestInfoHash(u32 type, int* psize, byte* hash);
};


bool    sha256quoteHash(int sizenonce, byte* nonce, 
                     int sizetobeSignedHash, byte* tobesignedHash, 
                     int sizecodeHash, byte* codeHash, byte* outputHash);
#endif


// --------------------------------------------------------------------------


