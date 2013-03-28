//
//  session.h
//      John Manferdelli
//
//  Description: channel session for authProxy and authClient
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


// ------------------------------------------------------------------------


#ifndef _SESSION__H
#define _SESSION__H

#include "jlmTypes.h"
#include "keys.h"
#include "sha256.h"
#include "secPrincipal.h"
#include "objectManager.h"
#include "secPrincipal.h"
#include "policyglobals.h"

// Key sizes
#define BIGNONCESIZE     64
#define BIGHASHSIZE     128
#define BIGSIGNEDSIZE   256

#define SMALLNONCESIZE   32
#define SMALLHASHSIZE    32
#define SMALLSIGNEDSIZE 128

#define MAXPRINCIPALS    25


class sessionKeys {
public:
    bool            m_fClient;
    int             m_iSessionId;

    bool            m_myProgramKeyValid;
    RSAKey*         m_myProgramKey;

    bool            m_myCertValid;
    char*           m_myCert;

    bool            m_policyCertValid;
    u32             m_policyCertType;
    int             m_sizepolicyCert;
    char*           m_policyCert;

    bool            m_fClientCertValid;
    char*           m_szXmlClientCert;              // Client Cert
    PrincipalCert*  m_pclientCert;
    RSAKey*         m_pclientPublicKey;             // Client public key

    bool            m_fServerCertValid;
    char*           m_szXmlServerCert;              // Server Cert
    PrincipalCert*  m_pserverCert;
    RSAKey*         m_pserverPublicKey;             // Server public key

    bool            m_fPrincipalCertsValid;
    char*           m_szPrincipalCerts;
    int             m_iNumPrincipals;
    PrincipalCert*  m_rgPrincipalCerts[MAXPRINCIPALS];
    RSAKey*         m_rgPrincipalPublicKeys[MAXPRINCIPALS];

    bool            m_fPrincipalPrivateKeysValid;   // Principal Private Keys
    char*           m_szPrincipalPrivateKeys;
    int             m_iNumPrincipalPrivateKeys;     // Principal Private Keys
    RSAKey*         m_rgPrincipalPrivateKeys[MAXPRINCIPALS];

    Sha256          m_oMessageHash;

    bool            m_fClientMessageHashValid;
    byte            m_rgClientMessageHash[SHA256DIGESTBYTESIZE]; 
    bool            m_fServerMessageHashValid;
    byte            m_rgServerMessageHash[SHA256DIGESTBYTESIZE]; 
    bool            m_fDecodedServerMessageHashValid;
    byte            m_rgDecodedServerMessageHash[SHA256DIGESTBYTESIZE]; 

    bool            m_fSignedMessageValid;
    int             m_sizeSignedMessage;
    byte            m_rgSignedMessage[BIGKEYSIZE]; 

    bool            m_fbase64SignedMessageHashValid;
    char*           m_szbase64SignedMessageHash;
    bool            m_fbase64ClientMessageHashValid;
    char*           m_szbase64ClientMessageHash;
    bool            m_fbase64ServerMessageHashValid;
    char*           m_szbase64ServerMessageHash;

    bool            m_fChallengeValid;
    char*           m_szChallengeSignAlg;

    char*           m_szChallenge;
    byte            m_rguChallenge[SMALLNONCESIZE];  
    char*           m_szSignedChallenges;

    bool            m_fClientRandValid;
    byte            m_rguClientRand[SMALLNONCESIZE];
    bool            m_fServerRandValid;
    byte            m_rguServerRand[SMALLNONCESIZE];

    bool            m_fPreMasterSecretValid;
    byte            m_rguPreMasterSecret[BIGSYMKEYSIZE];
    bool            m_fEncPreMasterSecretValid;
    byte            m_rguEncPreMasterSecret[BIGSIGNEDSIZE];

    char*           m_szSuite;
    int             m_iSuiteIndex;

    bool            m_fChannelKeysEstablished;

    byte            m_rguEncryptionKey1[SMALLSYMKEYSIZE];  // Confidentiality key
    byte            m_rguIntegrityKey1[SMALLSYMKEYSIZE];   // HMAC key
    byte            m_rguEncryptionKey2[SMALLSYMKEYSIZE];  // Confidentiality key
    byte            m_rguIntegrityKey2[SMALLSYMKEYSIZE];   // HMAC key

                    sessionKeys();
                    ~sessionKeys();

    void            clearKeys();
    bool            getServerCert(const char* szXml);
    bool            getClientCert(const char* szXml);
    bool            getMyProgramCert(const char* szCert);
    bool            getMyProgramKey(RSAKey* pKey);

    bool            getPrincipalCertsFromString(const char* szXml);
    bool            getPrincipalCertsFromFile(const char* fileName);
    bool            getPrincipalPrivateKeysFromFile(const char* fileName);

    bool            clientcomputeMessageHash();
    bool            servercomputeMessageHash();
    bool            initMessageHash();
    bool            updateMessageHash(int size, byte* pBuf);
    bool            clientsignMessageHash();
    bool            checkclientSignedHash();

    bool            initializePrincipalPrivateKeys();
    bool            initializePrincipalCerts();

    bool            computeServerKeys();
    bool            computeClientKeys();
    bool            checkPrincipalChallenges();
    bool            validateChannelData(bool fClient=true);
    bool            generatePreMaster();
#if TEST
    void            printMe();
#endif
};


#endif


// -----------------------------------------------------------------------


