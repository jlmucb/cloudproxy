//
//  File: session.h
//  Description: channel session defines for server and client
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
#include "cert.h"
#include "safeChannel.h"

#define BIGSIGNEDSIZE   256
#define SMALLNONCESIZE   32
#define PREMASTERSIZE    64
#define BIGSYMKEYSIZE    64


#define MAXPRINCIPALS    25


class session {
public:

    //      Session setup and state variables

    bool            m_fClient;
    int             m_iSessionId;
    int             m_sessionState;

    bool            m_myProgramKeyValid;
    RSAKey*         m_myProgramKey;
    bool            m_myCertValid;
    char*           m_myCert;

    RSAKey*         m_policyKey;
    bool            m_policyCertValid;
    int             m_sizepolicyCert;
    char*           m_szpolicyCert;


    //      Channel setup variables

    bool            m_fClientCertValid;
    char*           m_szXmlClientCert;              // Client Cert
    PrincipalCert*  m_pclientCert;
    RSAKey*         m_pclientPublicKey;             // Client public key

    bool            m_fServerCertValid;
    char*           m_szXmlServerCert;              // Server Cert
    PrincipalCert*  m_pserverCert;
    RSAKey*         m_pserverPublicKey;             // Server public key

    bool            getClientCert(const char* szXml);
    bool            getServerCert(const char* szXml);

    bool            m_fPrincipalCertsValid;
    char*           m_szPrincipalCerts;
    int             m_iNumPrincipals;
    PrincipalCert*  m_rgPrincipalCerts[MAXPRINCIPALS];          // FIX
    RSAKey*         m_rgPrincipalPublicKeys[MAXPRINCIPALS];

    bool            m_fPrincipalPrivateKeysValid;   // Principal Private Keys
    int             m_iNumPrincipalPrivateKeys;     // Principal Private Keys
    RSAKey*         m_rgPrincipalPrivateKeys[MAXPRINCIPALS];    // FIX

    Sha256          m_oMessageHash;

    bool            m_fClientMessageHashValid;
    byte            m_rgClientMessageHash[SHA256DIGESTBYTESIZE]; 

    bool            m_fServerMessageHashValid;
    byte            m_rgServerMessageHash[SHA256DIGESTBYTESIZE]; 

    bool            m_fDecodedServerMessageHashValid;
    byte            m_rgDecodedServerMessageHash[SHA256DIGESTBYTESIZE]; 

    bool            m_fSignedMessageValid;
    int             m_sizeSignedMessage;
    byte            m_rgSignedMessage[GLOBALMAXPUBKEYSIZE];

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
    byte            m_rguPreMasterSecret[PREMASTERSIZE];

    bool            m_fEncPreMasterSecretValid;
    byte            m_rguEncPreMasterSecret[GLOBALMAXPUBKEYSIZE];

    char*           m_szSuite;
    int             m_iSuiteIndex;

    bool            m_fChannelKeysEstablished;

    byte            m_rguEncryptionKey1[GLOBALMAXSYMKEYSIZE];  // Confidentiality key
    byte            m_rguIntegrityKey1[GLOBALMAXSYMKEYSIZE];   // HMAC key
    byte            m_rguEncryptionKey2[GLOBALMAXSYMKEYSIZE];  // Confidentiality key
    byte            m_rguIntegrityKey2[GLOBALMAXSYMKEYSIZE];   // HMAC key


                    session();
                    ~session();

    int             maxPrincipals(){return MAXPRINCIPALS;};

    //      Session setup functions
    bool            serverNegoMessage1(char* buf, int maxSize, int iSessionId, 
                            const char* szAlg, const char* szRand, 
                            const char* szServerCert);
    bool            serverNegoMessage2(char* buf, int maxSize, const char* szAlg,
                         const char* szChallenge, const char* szHash);
    bool            serverNegoMessage3(char* buf, int maxSize, bool fSucceed);

    bool            clientNegoMessage1(char* buf, int maxSize, const char* szAlg, 
                                       const char* szRand);
    bool            clientNegoMessage2(char* buf, int maxSize, 
                                       const char* szEncPreMasterSecret,
                                       const char* szClientCert, int iSessionId);
    bool            clientNegoMessage3(char* buf, int maxSize, const char* szSignedHash);
    bool            clientNegoMessage4(char* buf, int maxSize, const char* szPrincipalCerts,
                           int principalCount, const char* szSignedChallenges);

    bool            getDatafromServerMessage1(int n, char* request);
    bool            getDatafromServerMessage2(int n, char* request);
    bool            getDatafromServerMessage3(int n, char* request);

    bool            getDatafromClientMessage1(int n, char* request);
    bool            getDatafromClientMessage2(int n, char* request);
    bool            getDatafromClientMessage3(int n, char* request);
    bool            getDatafromClientMessage4(int n, char* request);

    bool            clientInit(const char* szPolicyCert, KeyInfo* policyKey,
                               const char* szmyCert, KeyInfo* pmyKey);
    bool            clientprotocolNego(int fd, safeChannel& fc,
                                       const char* szPrincipalKeys, 
                                       const char* szPrincipalCerts);

    bool            serverInit(const char* szPolicyCert, KeyInfo* policyKey,
                               const char* szmyCert, KeyInfo* pmyKey);
    bool            serverprotocolNego(int fd, safeChannel& fc);

    //      Channel negotiation functions
    void            clearKeys();

    bool            clientcomputeMessageHash();
    bool            servercomputeMessageHash();
    bool            initMessageHash();
    bool            updateMessageHash(int size, byte* pBuf);
    bool            clientsignMessageHash();
    bool            checkclientSignedHash();

    bool            initializePrincipalPrivateKeys(const char* szPrincipalPrivateKeys);
    bool            initializePrincipalCerts(const char* szPrincipalCerts);

    bool            computeServerKeys();
    bool            computeClientKeys();
    bool            checkPrincipalChallenges();
    bool            generatePreMaster();

#if TEST
    void            printMe();
#endif
};


#endif


// -----------------------------------------------------------------------


