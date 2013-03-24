//  File: session.cpp
//      John Manferdelli
//
//  Description: Channel session Management for fileServer and fileClient
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


// -----------------------------------------------------------------------------


#include "jlmTypes.h"
#include "logging.h"
#include "jlmcrypto.h"
#include "keys.h"
#include "session.h"
#include "jlmUtility.h"
#include "modesandpadding.h"
#include "rsaHelper.h"
#include "secPrincipal.h"
#include "tinyxml.h"
#include "objectManager.h"
#include "secPrincipal.h"
#include "resource.h"
#include "vault.h"
#include "policyglobals.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>


// ------------------------------------------------------------------------


sessionKeys::sessionKeys()
{
    m_myProgramKeyValid= false;
    m_myProgramKey= NULL;

    m_fChannelKeysEstablished= false;
    m_fClientCertValid= false;
    m_fServerCertValid= false;
    m_fChallengeValid= false;
    m_fPreMasterSecretValid= false;
    m_fEncPreMasterSecretValid= false;
    m_fPrincipalCertsValid= false;
    m_iNumPrincipals= 0;
    m_fPrincipalPrivateKeysValid= false;
    m_iNumPrincipalPrivateKeys= 0;
    m_iSuiteIndex= -1;
    m_fClientRandValid= false;
    m_fServerRandValid= false;
    m_myCertValid= false;
    m_iSessionId= 0;
    m_fClient= false;
    m_policyCertValid= false;

    m_fClientMessageHashValid= false;
    m_fServerMessageHashValid= false;
    m_fDecodedServerMessageHashValid= false;
    m_fbase64SignedMessageHashValid= false;
    m_fbase64ClientMessageHashValid= false;
    m_fbase64ServerMessageHashValid= false;
    m_szbase64SignedMessageHash= NULL;
    m_szbase64ClientMessageHash= NULL;
    m_szbase64ServerMessageHash= NULL;
    m_fSignedMessageValid= false;
    m_sizeSignedMessage= BIGKEYSIZE;

    m_pclientCert= NULL;
    m_pserverCert= NULL;
    m_pclientPublicKey= NULL;
    m_pserverPublicKey= NULL;
    m_szXmlClientCert= NULL;
    m_szXmlServerCert= NULL;
    m_szSuite= NULL;
    m_szPrincipalPrivateKeys= NULL;
    m_szPrincipalCerts= NULL;
    m_szChallengeSignAlg= NULL;
    m_szChallenge= NULL;
    m_szSignedChallenges= NULL;
    m_myCert= NULL;
    m_policyCert= NULL;
    m_szChallengeSignAlg= strdup("TLS_RSA1024_WITH_AES128_CBC_SHA256");
}


sessionKeys::~sessionKeys()
{
    clearKeys();
}


void sessionKeys::clearKeys()
{
    memset(m_rgClientMessageHash, 0, SHA256DIGESTBYTESIZE);
    memset(m_rgServerMessageHash,0, SHA256DIGESTBYTESIZE);
    memset(m_rguChallenge,0, SMALLNONCESIZE);  
    memset(m_rguClientRand,0, SMALLNONCESIZE);
    memset(m_rguServerRand,0, SMALLNONCESIZE);
    memset(m_rguPreMasterSecret,0, BIGSYMKEYSIZE);
    memset(m_rguEncPreMasterSecret,0, BIGSIGNEDSIZE);
    memset(m_rguEncryptionKey1,0, SMALLSYMKEYSIZE);
    memset(m_rguIntegrityKey1,0, SMALLSYMKEYSIZE);
    memset(m_rguEncryptionKey2,0, SMALLSYMKEYSIZE);
    memset(m_rguIntegrityKey2,0, SMALLSYMKEYSIZE);

    if(m_szXmlClientCert!=NULL) {
        free(m_szXmlClientCert);
        m_szXmlClientCert= NULL;
    }
    if(m_szXmlServerCert!=NULL) {
        free(m_szXmlServerCert);
        m_szXmlServerCert= NULL;
    }
    if(m_szPrincipalCerts!=NULL) {
        free(m_szPrincipalCerts);
        m_szPrincipalCerts= NULL;
    }
    if(m_szPrincipalPrivateKeys!=NULL) {
        free(m_szPrincipalPrivateKeys);
        m_szPrincipalPrivateKeys= NULL;
    }
    if(m_szChallengeSignAlg!=NULL) {
        free(m_szChallengeSignAlg);
        m_szChallengeSignAlg= NULL;
    }
    if(m_szChallenge!=NULL) {
        free(m_szChallenge);
        m_szChallenge= NULL;
    }
    if(m_szSignedChallenges!=NULL) {
        free(m_szSignedChallenges);
        m_szSignedChallenges= NULL;
    }
    if(m_szSuite!=NULL) {
        free(m_szSuite);
        m_szSuite= NULL;
    }

    m_myCert= NULL;

    m_fChannelKeysEstablished= false;
    m_fClientCertValid= false;
    m_fServerCertValid= false;
    m_fChallengeValid= false;
    m_fPreMasterSecretValid= false;
    m_fEncPreMasterSecretValid= false;
    m_szChallengeSignAlg= NULL;
    m_szChallenge= NULL;
    m_szSignedChallenges= NULL;
    m_fPrincipalCertsValid= false;
    m_szPrincipalCerts= NULL;
    m_iNumPrincipals= 0;
    m_fPrincipalPrivateKeysValid= false;
    m_szPrincipalPrivateKeys= NULL;
    m_iNumPrincipalPrivateKeys= 0;
    m_szXmlClientCert= NULL;
    m_szXmlServerCert= NULL;
    m_szSuite= NULL;
    m_iSuiteIndex= -1;
    m_fClientMessageHashValid= false;
    m_fServerMessageHashValid= false;
    m_fClientRandValid= false;
    m_fServerRandValid= false;
    m_pclientPublicKey= NULL;
    m_pserverPublicKey= NULL;

    if(m_pclientPublicKey!=NULL) {
        delete m_pclientPublicKey;
        m_pclientPublicKey= NULL;
    }
    if(m_pserverPublicKey!=NULL) {
        delete m_pserverPublicKey;
        m_pserverPublicKey= NULL;
    }
}


bool sessionKeys::getMyProgramKey(RSAKey* pKey)
{
    if(pKey==NULL)
        return false;

    m_myProgramKeyValid= true;
    m_myProgramKey= pKey;

#ifdef TEST
    fprintf(g_logFile, "sessionKeys::getMyProgramKey: program key set\n");
    fflush(g_logFile);
    pKey->printMe();
    fflush(g_logFile);
#endif
    return true;
}


bool sessionKeys::getMyProgramCert(const char* szCert)
{
    if(szCert==NULL)
        return false;
    m_myCert= strdup(szCert);
    m_myCertValid= true;
    return true;
}


bool    sessionKeys::getClientCert(const char* szXml)
{
#ifdef TEST
    fprintf(g_logFile, "getClientCert\n");
    fflush(g_logFile);
#endif
    m_szXmlClientCert= strdup(szXml);
    if(m_szXmlClientCert==NULL) {
        fprintf(g_logFile, "sessionKeys::getClientCert: Client cert string is null\n");
        return false;
    }
    
    m_pclientCert= new PrincipalCert();
    if(m_pclientCert==NULL) {
        fprintf(g_logFile, "sessionKeys::getClientCert: Cant create client signature\n");
        return false;
    }
    if(!m_pclientCert->init(m_szXmlClientCert)) {
        fprintf(g_logFile, "sessionKeys::getClientCert: Cant init client Cert\n");
        return false;
    }
    if(!m_pclientCert->parsePrincipalCertElements()) {
        fprintf(g_logFile, "sessionKeys::getClientCert: Cant parsePrincipalCertElements\n");
        return false;
    }
    m_pclientPublicKey= (RSAKey*)m_pclientCert->getSubjectKeyInfo();
    if(m_pclientPublicKey==NULL) {
        fprintf(g_logFile, "sessionKeys::getClientCert: Cant get client Subject Key\n");
        return false;
    }
    if(g_policyKey==NULL) {
        fprintf(g_logFile, "sessionKeys::getClientCert: invalid policy key\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "sessionKeys::getClientCert: Validating cert chain\n");
    fflush(g_logFile);
#endif

    // Validate cert chain
    int     rgType[2]={PRINCIPALCERT, EMBEDDEDPOLICYPRINCIPAL};
    void*   rgObject[2]={m_pclientCert, g_policyKey};
    int     iChain= VerifyEvidenceList(NULL, 2, rgType, rgObject, NULL);
    if(iChain<0) {
        fprintf(g_logFile, "sessionKeys::getClientCert: Invalid client certificate chain\n");
        return false;
    }
    m_fClientCertValid= true;

#ifdef TEST
    fprintf(g_logFile, "sessionKeys::getClientCert: Client Key\n");
    m_pclientPublicKey->printMe();
    fprintf(g_logFile, "\n");
    fflush(g_logFile);
#endif
    return true;
}


bool sessionKeys::getServerCert(const char* szXml)
{
    m_szXmlServerCert= strdup(szXml);
    if(m_szXmlServerCert==NULL)
        return false;
    m_pserverCert= new PrincipalCert();
    if(m_pserverCert==NULL) {
        fprintf(g_logFile, "sessionKeys::getServerCert: Cant create server signature\n");
        return false;
    }
    if(!m_pserverCert->init(m_szXmlServerCert)) {
        fprintf(g_logFile, "sessionKeys::getServerCert: Cant init server cert\n");
        return false;
    }
    if(!m_pserverCert->parsePrincipalCertElements()) {
        fprintf(g_logFile, "sessionKeys::getServerCert: Cant parsePrincipalCertElements server cert\n");
        return false;
    }
    m_pserverPublicKey= (RSAKey*)m_pserverCert->getSubjectKeyInfo();
    if(m_pserverPublicKey==NULL) {
        fprintf(g_logFile, "Cant sessionKeys::getServerCert: get server Subject Key\n");
        return false;
    }

    // Validate cert chain
    int     rgType[2]={PRINCIPALCERT, EMBEDDEDPOLICYPRINCIPAL};
    void*   rgObject[2]={m_pserverCert, g_policyKey};
    extern  bool revoked(const char*, const char*);
    int     iChain= VerifyEvidenceList(NULL, 2, rgType, rgObject, NULL);
    if(iChain<0) {
        fprintf(g_logFile, "sessionKeys::getServerCert: Invalid server certificate chain\n");
        return false;
    }
    m_fServerCertValid= true;
    
#ifdef TEST1
    fprintf(g_logFile, "sessionKeys::getServerCert: Server public Key\n");
    m_pserverPublicKey->printMe();
    fprintf(g_logFile, "\n");
#endif
    return true;
}


bool sessionKeys::getPrincipalCertsFromFile(const char* fileName)
{
    if (m_fPrincipalCertsValid)
        return true;
    if (m_szPrincipalCerts==NULL)
        m_szPrincipalCerts= readandstoreString(fileName);
    if(m_szPrincipalCerts==NULL) {
        m_iNumPrincipals= 0;
    }

#ifdef TEST1
    if(m_szPrincipalCerts==NULL)
        fprintf(g_logFile, "sessionKeys::getPrincipalCertsFromFile: Principal Certs from file: %s\n", m_szPrincipalCerts);
    else
        fprintf(g_logFile, "sessionKeys::getPrincipalCertsFromFile: No principal certs\n");
#endif
    return true;
}


bool sessionKeys::getPrincipalPrivateKeysFromFile(const char* fileName)
{
    if (m_fPrincipalPrivateKeysValid)
        return true;
    if(m_szPrincipalPrivateKeys==NULL)
        m_szPrincipalPrivateKeys= readandstoreString(fileName);
    return true;
}


bool sessionKeys::initializePrincipalCerts()
{
    int     i;

#ifdef TEST
    if(m_szPrincipalCerts==NULL)
        fprintf(g_logFile, "initializePrincipalCerts is NULL\n");
    else
        fprintf(g_logFile, "initializePrincipalCerts:\n%s\n", m_szPrincipalCerts);
    fflush(g_logFile);
#endif
    if(m_szPrincipalCerts==NULL) {
        m_iNumPrincipals= 0;
        m_fPrincipalCertsValid= true;
        return true;
    }

    evidenceCollection  oEvidenceCollection;

    if(!oEvidenceCollection.parseEvidenceCollection(m_szPrincipalCerts)) {
        fprintf(g_logFile, "sessionKeys::initializePrincipalCerts: Cannot parse Principal Public Keys\n");
        return false;
    }

    if(!oEvidenceCollection.validateEvidenceCollection(g_policyKey)) {
        fprintf(g_logFile,  "sessionKeys::initializePrincipalCerts: Cannot validate Principal Public Keys\n");
        return false;
    }

    m_iNumPrincipals= oEvidenceCollection.m_iNumEvidenceLists;
    for(i=0; i<m_iNumPrincipals; i++) {
        if(oEvidenceCollection.m_iNumEvidenceLists<1 ||
                oEvidenceCollection.m_rgiCollectionTypes[0]!=PRINCIPALCERT) {
            fprintf(g_logFile, "sessionKeys::initializePrincipalCerts: No Signed principal\n");
            return false;
        }

        // cert
        m_rgPrincipalCerts[i]= (PrincipalCert*)
                                 oEvidenceCollection.m_rgCollectionList[i]->m_rgEvidence[0];
        m_rgPrincipalPublicKeys[i]= (RSAKey*) (m_rgPrincipalCerts[i]->getSubjectKeyInfo());
    }

#ifdef TEST
    fprintf(g_logFile, "%d Principal Certs\n", m_iNumPrincipals);
    fflush(g_logFile);
#endif

    if(m_iNumPrincipals>MAXPRINCIPALS) {
        fprintf(g_logFile, "Too many principal private keys\n");
        return false;
    }

    m_fPrincipalCertsValid= true;
    return true;
}


bool sessionKeys::initializePrincipalPrivateKeys()
{
    if(m_szPrincipalPrivateKeys==NULL) {
        m_iNumPrincipalPrivateKeys= 0;
        m_fPrincipalPrivateKeysValid= true;
        return true;
    }

    int             iNumKeys= 0;
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement;
    TiXmlNode*      pNode;

    if(!doc.Parse(m_szPrincipalPrivateKeys)) {
        fprintf(g_logFile,  "sessionKeys::initializePrincipalPrivateKeys: Cannot parse Principal Private Keys\n");
        return false;
    }

    pRootElement= doc.RootElement();
    if(strcmp(pRootElement->Value(),"PrivateKeys")!=0) {
        fprintf(g_logFile, "sessionKeys::initializePrincipalPrivateKeys: Should be list of private keys\n");
        return false;
    }
    pRootElement->QueryIntAttribute ("count", &iNumKeys);

#ifdef TEST
    fprintf(g_logFile, "%d principal private keys\n", iNumKeys);
#endif

    if(iNumKeys>MAXPRINCIPALS) {
        fprintf(g_logFile, "sessionKeys::initializePrincipalPrivateKeys: Too many principal private keys\n");
        return false;
    }

    int iKeyList= 0;
    pNode= pRootElement->FirstChild();
    while(pNode) {
        if(pNode->Type()==TiXmlNode::TINYXML_ELEMENT) {
            if(strcmp(((TiXmlElement*)pNode)->Value(),"ds:KeyInfo")==0) {
                if(!initRSAKeyFromKeyInfo(&m_rgPrincipalPrivateKeys[iKeyList], pNode)) {
                    fprintf(g_logFile, "sessionKeys::initializePrincipalPrivateKeys: Cant init private key\n");
                    return false;
                }
                iKeyList++;
            }
        }
        pNode= pNode->NextSibling();
    }

    if(iKeyList!=iNumKeys) {
        fprintf(g_logFile, "sessionKeys::initializePrincipalPrivateKeys: Count mismatch in private keys\n");
        return false;
    }

    m_iNumPrincipalPrivateKeys= iKeyList;
    m_fPrincipalPrivateKeysValid= true;
    return true;
}


bool sessionKeys::initMessageHash()
{   
#ifdef TEST
    fprintf(g_logFile, "sessionKeys::initMessageHash\n");
    fflush(g_logFile);
#endif
    m_oMessageHash.Init();
    return true;
}


bool sessionKeys::updateMessageHash(int size, byte* buf)
{
#ifdef TEST
    fprintf(g_logFile, "sessionKeys::updateMessageHash %d bytes\n", size);
    fflush(g_logFile);
#endif
    m_oMessageHash.Update(buf, size);
    return true;
}


bool sessionKeys::clientcomputeMessageHash()
{
#ifdef TEST
    fprintf(g_logFile, "sessionKeys::clientcomputeMessageHash\n");
    fflush(g_logFile);
#endif
    Sha256 oHash;
    memcpy((byte*)&oHash, (byte*)&m_oMessageHash, sizeof(oHash));
    oHash.Final();
    oHash.GetDigest(m_rgClientMessageHash);
    m_fClientMessageHashValid= true;
#ifdef TEST
    PrintBytes("client hash: ", m_rgClientMessageHash, SHA256DIGESTBYTESIZE);
    fflush(g_logFile);
#endif
    return true;
}


bool sessionKeys::clientsignMessageHash()
{
#ifdef TEST
    fprintf(g_logFile, "sessionKeys::clientsignMessageHash\n");
    fflush(g_logFile);
#endif
    if(!m_myProgramKeyValid || m_myProgramKey==NULL) {
        fprintf(g_logFile, "sessionKeys::clientsignMessageHash: program key invalid\n");
        return false;
    }

    // Client signs Message hash
    if(!m_fClientMessageHashValid) {
        fprintf(g_logFile, "sessionKeys::clientsignMessageHash: client message invalid\n");
        return false;
    }
    m_szbase64SignedMessageHash= rsaXmlEncodeChallenge(false, *m_myProgramKey, 
                                    m_rgClientMessageHash, SHA256DIGESTBYTESIZE);
    if(m_szbase64SignedMessageHash==NULL) {
    	fprintf(g_logFile, "sessionKeys::clientsignMessageHash: no base64SignedMessageHash\n");
    	fflush(g_logFile);
        return false;
    }
    m_fbase64SignedMessageHashValid= true;
    return true;
}


bool sessionKeys::checkclientSignedHash()
{
#ifdef TEST
    fprintf(g_logFile, "sessionKeys::checkclientSignedHash\n");
    fflush(g_logFile);
#endif
    if(!m_fClientCertValid) {
        fprintf(g_logFile, "sessionKeys::checkclientSignedHash: client cert invalid\n");
        return false;
    }
    if(!m_fClientMessageHashValid) {
        fprintf(g_logFile, "sessionKeys::checkclientSignedHash: client hash invalid\n");
        return false;
    }
    if(!m_fbase64SignedMessageHashValid) {
        fprintf(g_logFile, "sessionKeys::checkclientSignedHash: signed hash string invalid\n");
        return false;
    }

    // decode and verify hash
    if(!rsaXmlDecodeandVerifyChallenge(true, *m_pclientPublicKey, m_szbase64SignedMessageHash,
                                       SHA256DIGESTBYTESIZE, m_rgClientMessageHash)) {
        fprintf(g_logFile, "sessionKeys::checkclientSignedHash: bad encrypted hash\n");
        return false;
    }

#ifdef TEST
    PrintBytes("Hash: ", m_rgClientMessageHash, SHA256DIGESTBYTESIZE);
#endif
    return true;
}


bool sessionKeys::servercomputeMessageHash()
{
#ifdef TEST
    fprintf(g_logFile, "sessionKeys::servercomputeMessageHash\n");
    fflush(g_logFile);
#endif
    m_oMessageHash.Final();
    m_oMessageHash.GetDigest(m_rgServerMessageHash);
    m_fServerMessageHashValid= true;
#ifdef TEST
    PrintBytes("server hash: ", m_rgServerMessageHash, SHA256DIGESTBYTESIZE);
    fflush(g_logFile);
#endif
    return true;
}


bool sessionKeys::computeServerKeys()
{
    bool    fRet= false;

    if(!m_myProgramKeyValid)
        return false;

    fRet= rsaXmlDecryptandGetNonce(false, *m_myProgramKey, m_myProgramKey->m_iByteSizeM, 
                        m_rguEncPreMasterSecret, BIGSYMKEYSIZE, m_rguPreMasterSecret);
     if(!fRet)
         return false;
    m_fPreMasterSecretValid= true;
    return computeClientKeys();
}


bool sessionKeys::computeClientKeys()
{
    byte    rgSeed[2*SMALLNONCESIZE];
    byte    rgKeys[4*SMALLSYMKEYSIZE];

    if(!m_fPreMasterSecretValid) {
        fprintf(g_logFile, "sessionKeys::computeClientKeys: Premaster not valid\n");
        return false;
    }
    if(!m_fClientRandValid) {
        fprintf(g_logFile, "sessionKeys::computeClientKeys: Client random not valid\n");
        return false;
    }
    if(!m_fServerRandValid) {
        fprintf(g_logFile, "sessionKeys::computeClientKeys: Server random not valid\n");
        return false;
    }

    memcpy(rgSeed, m_rguServerRand, SMALLNONCESIZE);
    memcpy(&rgSeed[SMALLNONCESIZE], m_rguClientRand, SMALLNONCESIZE);
    if(!prf_SHA256(BIGSYMKEYSIZE, m_rguPreMasterSecret, 2*SMALLNONCESIZE, rgSeed,
                       "fileServer keyNego protocol", 4*AES128BYTEKEYSIZE, rgKeys)) {
        fprintf(g_logFile, "sessionKeys::computeClientKeys: Cannot apply prf\n");
        return false;
   }

#ifdef TEST
    fprintf(g_logFile,"sessionKeys::computeClientKeys()\n");
    PrintBytes("client rand: ",  m_rguClientRand, SMALLNONCESIZE);
    PrintBytes("server rand: ",  m_rguServerRand, SMALLNONCESIZE);
    PrintBytes("Premaster : ",  m_rguPreMasterSecret, 2*SMALLNONCESIZE);
#endif

    memcpy(m_rguEncryptionKey1, &rgKeys[0], AES128BYTEKEYSIZE);
    memcpy(m_rguIntegrityKey1, &rgKeys[AES128BYTEKEYSIZE], AES128BYTEKEYSIZE);
    memcpy(m_rguEncryptionKey2, &rgKeys[2*AES128BYTEKEYSIZE], AES128BYTEKEYSIZE);
    memcpy(m_rguIntegrityKey2, &rgKeys[3*AES128BYTEKEYSIZE], AES128BYTEKEYSIZE);

    m_fChannelKeysEstablished= true;
    return true;
}


bool sessionKeys::checkPrincipalChallenges()
{
    byte            rguOriginalChallenge[BIGSIGNEDSIZE];
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement;
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;
    int             iNumChecked= 0;
    bool            fRet= true;
    const char*     szSignedChallenge= NULL;
    int             iNumSignedChallenges= 0;

    if(!doc.Parse(m_szSignedChallenges)) {
        fprintf(g_logFile,  "sessionKeys::checkPrincipalChallenges: Can't parse SignedChallenges\n");
        return false;
    }

    pRootElement= doc.RootElement();
    if(strcmp(pRootElement->Value(),"SignedChallenges")!=0) {
        fprintf(g_logFile, "sessionKeys::checkPrincipalChallenges: Should be SignedChallenges: %s\n", 
                m_szSignedChallenges);
        return false;
    }
    pRootElement->QueryIntAttribute ("count", &iNumSignedChallenges);

#ifdef TEST
    fprintf(g_logFile, "checkPrincipalChallenges %d signed challenges\n", iNumSignedChallenges);
#endif

    if(m_iNumPrincipals!=iNumSignedChallenges) {
        fprintf(g_logFile, "sessionKeys::checkPrincipalChallenges: Number of challenges is not number of principals\n");
        return false;
    }

    if(!m_fChallengeValid) {
        fprintf(g_logFile, "sessionKeys::checkPrincipalChallenges: Challenge not valid\n");
        return false;
    }

    memcpy(rguOriginalChallenge, m_rguChallenge, SMALLNONCESIZE);

    pNode= pRootElement->FirstChild();
    while(pNode!=NULL) {
        if(pNode->Type()==TiXmlNode::TINYXML_ELEMENT) {
            if(strcmp(((TiXmlElement*)pNode)->Value(),"SignedChallenge")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1==NULL) {
                    fprintf(g_logFile, "sessionKeys::checkPrincipalChallenges: Empty signed challenge\n");
                    return false;
                }
                szSignedChallenge= pNode1->Value();
                if(!rsaXmlDecodeandVerifyChallenge(true, *m_rgPrincipalPublicKeys[iNumChecked], 
                        szSignedChallenge, SMALLNONCESIZE, rguOriginalChallenge)) {
                    fprintf(g_logFile, "sessionKeys::checkPrincipalChallenges: bad encrypted challenge\n");
                    fRet= false;
                    break;
                }
                // bump
                if(!bumpChallenge(SMALLNONCESIZE, rguOriginalChallenge)) {
                    fprintf(g_logFile, "sessionKeys::checkPrincipalChallenges: Can't bump challenge\n");
                    return false;
                }
            iNumChecked++;
            }
        }
        pNode= pNode->NextSibling();
    }

    if(fRet && m_iNumPrincipals!=iNumChecked) {
        fprintf(g_logFile, "sessionKeys::checkPrincipalChallenges: Number of signed challenges is not number of principals\n");
        return false;
    }

    return fRet;
}


bool sessionKeys::validateChannelData(bool fClient)
{
    // set the principals
    m_fClient= fClient;
    return m_fChannelKeysEstablished;
}


bool sessionKeys::generatePreMaster()
{
    if(!getCryptoRandom(BIGSYMKEYSIZE*NBITSINBYTE, m_rguPreMasterSecret))
        return false;
    m_fPreMasterSecretValid= true;
    return true;
}


// ------------------------------------------------------------------------


#ifdef TEST
void sessionKeys::printMe()
{
    int     i;
    char    szMessage[128];

    fprintf(g_logFile, "\n\nSession Key Data\n");

    fprintf(g_logFile, "\n");
    if(m_fClientCertValid) {
        fprintf(g_logFile, "Client Cert valid\n");
        fprintf(g_logFile, "%s\n", m_szXmlClientCert);
        m_pclientPublicKey->printMe();
    }
    if(m_fServerCertValid) {
        fprintf(g_logFile, "Server Cert valid\n");
        fprintf(g_logFile, "%s\n", m_szXmlServerCert);
        m_pserverPublicKey->printMe();
    }

    fprintf(g_logFile, "\n");
    if(m_fPrincipalCertsValid) {
        fprintf(g_logFile, "Principal Certs valid, %d keys\n", m_iNumPrincipals);
        for(i=0;i<m_iNumPrincipals;i++) {
            m_rgPrincipalPublicKeys[i]->printMe();
        }
    }
    else {
        fprintf(g_logFile, "No principal certs\n");
    }

    fprintf(g_logFile, "\n");
    if(m_fPrincipalPrivateKeysValid) {
        fprintf(g_logFile, "Principal Keys valid, %d keys\n", m_iNumPrincipals);
        for(i=0;i<m_iNumPrincipals;i++) {
            m_rgPrincipalPrivateKeys[i]->printMe();
        }
    }
    else {
        fprintf(g_logFile, "No principal private keys\n");
    }

    fprintf(g_logFile, "\n");
    if(m_fClientMessageHashValid) {
        PrintBytes("Client Message Hash: ", m_rgClientMessageHash, SHA256DIGESTBYTESIZE);
    }
    else {
        fprintf(g_logFile, "Client Message Hash invalid\n");
    }
    if(m_fServerMessageHashValid) {
        PrintBytes("Server Message Hash: ", m_rgServerMessageHash, SHA256DIGESTBYTESIZE);
    }
    else {
        fprintf(g_logFile, "Server Message Hash invalid\n");
    }

    fprintf(g_logFile, "\n");
    if(m_fChallengeValid) {
        fprintf(g_logFile, "Challenge valid, alg: %s\n", m_szChallengeSignAlg);
        sprintf(szMessage, "Challenge(%d)" , SMALLNONCESIZE);
        PrintBytes(szMessage, m_rguChallenge, SMALLNONCESIZE);
    }
    if(m_szSignedChallenges!=NULL)
        fprintf(g_logFile, "Signed challenges: %s\n", m_szSignedChallenges);

    fprintf(g_logFile, "\n");
    if(m_fClientRandValid) {
        sprintf(szMessage, "Client rand valid(%d)" , SMALLNONCESIZE);
        PrintBytes(szMessage, m_rguClientRand, SMALLNONCESIZE);
    }
    if(m_fServerRandValid) {
        sprintf(szMessage, "Server rand valid(%d)" , SMALLNONCESIZE);
        PrintBytes(szMessage, m_rguServerRand, SMALLNONCESIZE);
    }

    fprintf(g_logFile, "\n");
    if(m_fbase64SignedMessageHashValid) {
        fprintf(g_logFile, "Signed message hash: %s\n" , m_szbase64SignedMessageHash);
    }

    fprintf(g_logFile, "\n");
    if(m_fClientMessageHashValid) {
        PrintBytes("Client hash:" , m_rgClientMessageHash, SHA256DIGESTBYTESIZE);
    }

    fprintf(g_logFile, "\n");
    if(m_fServerMessageHashValid) {
        PrintBytes("Server hash:" , m_rgServerMessageHash, SHA256DIGESTBYTESIZE);
    }

    fprintf(g_logFile, "\n");
    if(m_fSignedMessageValid) {
        PrintBytes("Server hash:" , m_rgSignedMessage, BIGSYMKEYSIZE);
    }

    fprintf(g_logFile, "\n");
    if(m_fPreMasterSecretValid) {
        sprintf(szMessage, "Pre-Master valid(%d)" , BIGSYMKEYSIZE);
        PrintBytes(szMessage, m_rguPreMasterSecret, BIGSYMKEYSIZE);
    }
    if(m_fEncPreMasterSecretValid) {
        sprintf(szMessage, "Encrypted Pre-Master valid(%d)" , BIGSIGNEDSIZE);
        PrintBytes(szMessage, m_rguEncPreMasterSecret, BIGSIGNEDSIZE);
    }

    fprintf(g_logFile, "\n");
    if(m_szSuite!=NULL)
        fprintf(g_logFile, "Suite: %s\n", m_szSuite);
    fprintf(g_logFile, "Suite index %d\n",m_iSuiteIndex);

    fprintf(g_logFile, "\n");
    if(m_fChannelKeysEstablished) {
        fprintf(g_logFile, "Channel established\n");
        sprintf(szMessage, "Encryption Key 1 (%d)" , AES128BYTEKEYSIZE);
        PrintBytes(szMessage, m_rguEncryptionKey1, AES128BYTEKEYSIZE);
        sprintf(szMessage, "Integrity Key 1 (%d) " , AES128BYTEKEYSIZE);
        PrintBytes(szMessage, m_rguIntegrityKey1, AES128BYTEKEYSIZE);
        sprintf(szMessage, "Encryption Key 2 (%d)" , AES128BYTEKEYSIZE);
        PrintBytes(szMessage, m_rguEncryptionKey2, AES128BYTEKEYSIZE);
        sprintf(szMessage, "Integrity Key 2 (%d) " , AES128BYTEKEYSIZE);
        PrintBytes(szMessage, m_rguIntegrityKey2, AES128BYTEKEYSIZE);
    }
    fprintf(g_logFile, "\nEnd of Session Key Data\n");

    return;
}
#endif


// -----------------------------------------------------------------------


