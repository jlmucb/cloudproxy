//
//  File: encapsulate.h
//  Description: Seal key with PK, encrypt file
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


#ifndef _ENCAPSULATE__H
#define _ENCAPSULATE__H

#include "common.h"
#include "logging.h"
#include "jlmcrypto.h"
#include "jlmUtility.h"
#include "algs.h"
#include "keys.h"
#include "tinyxml.h"
#include "sha256.h"
#ifdef NOAESNI
#include "aes.h"
#else
#include "aesni.h"
#endif
#include "bignum.h"
#include "mpFunctions.h"
#include "modesandpadding.h"


#define RSA1024SIGNALG  "http://www.manferdelli.com/2011/Xml/algorithms/rsa1024-sha256-pkcspad#"
#define RSA2048SIGNALG "http://www.manferdelli.com/2011/Xml/algorithms/rsa2048-sha256-pkcspad#"
#define RSA1024SEALALG  "http://www.manferdelli.com/2011/Xml/algorithms/rsa1024-sha256-pkcspad#"
#define RSA2048SEALALG "http://www.manferdelli.com/2011/Xml/algorithms/rsa2048-sha256-pkcspad#"
#define AESCBCENCRYPTALG  "http://www.manferdelli.com/2011/Xml/algorithms/aes128-sha256-pkcspad#"

//
//  Metadata format
//
//  <EncapsulatedMessage>
//      <SealAlgorithm> </SealAlgorithm>
//      <SignAlgorithm> </SignAlgorithm>
//      <EncryptAlgorithm> </SealAlgorithm>
//      <SealedKey></SealedKey>
//      <Cert></Cert>
//  </EncapsulatedMessage>


class encapsulatedMessage {
public:
    char*       m_szSignerKeyInfo;
    char*       m_szSubjectKeyInfo;

    char*       m_szXMLmetadata;
    char*       m_szSignAlg;
    char*       m_szSealAlg;
    char*       m_szEncryptAlg;
    char*       m_szSealedKey;

    char*       m_szCert;

    int         m_sizeEncKey;
    byte*       m_encKey;
    int         m_sizeIntKey;
    byte*       m_intKey;
    int         m_sizePlain;
    byte*       m_rgPlain;
    int         m_sizeEncrypted;
    byte*       m_rgEncrypted;
    int         m_sizePackageSignature;
    byte*       m_rgPackageSignature;
    

                encapsulatedMessage();
                ~encapsulatedMessage();

    char*       serializeMetaData();
    bool        parseMetaData();
    bool        sealKey(RSAKey* pSealKey);          // FIX (non-RSA key types)
    bool        unSealKey(RSAKey* pSealKey);        // FIX
    bool        encryptMessage();
    bool        decryptMessage();
    bool        getencryptedMessage(byte* out);
    bool        setencryptedMessage(int size, byte* in);
    bool        getplainMessage(byte* out);
    bool        setplainMessage(int size, byte* in);
    int         encryptedMessageSize();
    int         plainMessageSize();
    bool        signPackage(RSAKey* pSignKey);      // FIX
    bool        verifyPackage(RSAKey* pSignKey);    // FIX

    char*       getSignerKeyInfo();
    char*       getSubjectKeyInfo();

#ifdef TEST
    void        printMe();
#endif
};


#endif


// -------------------------------------------------------------------------------------


