//  File: authClient.cpp
//      John Manferdelli
//
//  Description: Client for authServer.
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


#include "jlmTypes.h"
#include "logging.h"
#include "jlmcrypto.h"
#include "authClient.h"
#include "session.h"
#include "channel.h"
#include "safeChannel.h"
#include "channelstate.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "jlmUtility.h"
#include "request.h"
#include "sha256.h"
#include "tinyxml.h"
#include "rsaHelper.h"
#include "domain.h"
#include "tcIO.h"
#include "timer.h"
#include "authTester.h"

#include "objectManager.h"
#include "tao.h"

#include "trustedKeyNego.h"
#include "encryptedblockIO.h"
#include "secPrincipal.h"
#include "hashprep.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <dirent.h>

#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
using std::string;
using std::ifstream;
using std::ofstream;
using std::istreambuf_iterator;
using std::stringstream;
const char* szServerHostAddr= "127.0.0.1";

bool             g_globalpolicyValid= false;
// metaData         g_theVault;
PrincipalCert*   g_policyPrincipalCert= NULL;
RSAKey*          g_policyKey= NULL;
accessPrincipal* g_policyAccessPrincipal= NULL;

#include "./policyCert.inc"

const char* g_szClientPrincipalCertsFile= "authClient/principalPublicKeys.xml";
const char* g_szClientPrincipalPrivateKeysFile= "authClient/principalPrivateKeys.xml";


accessPrincipal* registerPrincipalfromCert(PrincipalCert* pSig);


// ------------------------------------------------------------------------


authClient::authClient ()
{
    m_clientState= NOSTATE;
    m_fChannelAuthenticated= false;
    m_szPort= NULL;
    m_szAddress= NULL;
    m_fd= 0;

    m_fEncryptFiles= false;
    m_szSealedKeyFile= NULL;
    m_fKeysValid= true;
    m_uAlg= 0;
    m_uMode= 0;
    m_uPad= 0;
    m_uHmac= 0;
    m_sizeKey= SMALLKEYSIZE;
}


authClient::~authClient ()
{
    m_clientState= NOSTATE;
    m_fChannelAuthenticated= false;

    if(m_szPort!=NULL) {
        free(m_szPort);
        m_szPort= NULL;
    }
    if(m_szAddress!=NULL) {
        free(m_szAddress);
        m_szAddress= NULL;
    }
    m_sizeKey= SMALLKEYSIZE;
    if(m_fKeysValid)
        memset(m_authKeys, 0, m_sizeKey);
    m_fKeysValid= false;
    if(m_szSealedKeyFile!=NULL)
        free(m_szSealedKeyFile);
    m_szSealedKeyFile= NULL;
}


bool authClient::initPolicy()
{
#ifdef TEST
    fprintf(g_logFile, "authClient::initPolicy\n");
    fflush(g_logFile);
#endif
    if(!m_tcHome.m_envValid) {
        fprintf(g_logFile, "authClient::initPolicy(): environment invalid\n");
        return false;
    }

    if(!m_tcHome.m_policyKeyValid)  {
        fprintf(g_logFile, "authClient::initPolicy(): policyKey invalid\n");
        return false;
    }

#ifdef TEST1
    fprintf(g_logFile, "authClient::initPolicy, about to initpolicy Cert\n%s\n",
            m_tcHome.m_policyKey);
    fflush(g_logFile);
    if(g_policyPrincipalCert==NULL)
        g_policyPrincipalCert= new PrincipalCert();
#endif
    if(!g_policyPrincipalCert->init(reinterpret_cast<char*>(m_tcHome.m_policyKey))) {
        fprintf(g_logFile, "initPolicy: Can't init policy cert 1\n");
        return false;
    }
    if(!g_policyPrincipalCert->parsePrincipalCertElements()) {
        fprintf(g_logFile, "initPolicy: Can't init policy key 2\n");
        return false;
    }
    g_policyKey= (RSAKey*)g_policyPrincipalCert->getSubjectKeyInfo();
    if(g_policyKey==NULL) {
        fprintf(g_logFile, "initPolicy: Can't init policy key 3\n");
        return false;
    }
    g_policyAccessPrincipal= registerPrincipalfromCert(g_policyPrincipalCert);
    if(g_policyAccessPrincipal==NULL) {
        fprintf(g_logFile, "initPolicy: Can't init policy key 3\n");
        return false;
    }

    g_globalpolicyValid= true;
    return true;
}


bool authClient::initFileKeys()
{
    struct stat statBlock;
    char        szName[256];
    int         size= 0;
    byte        keyBuf[SMALLKEYSIZE];
    int         n= 0;
    int         m= 0;
    byte        sealedkeyBuf[BIGKEYSIZE];
   
    if(m_tcHome.m_fileNames.m_szdirectory==NULL) {
        fprintf(g_logFile, "initFileKeys: No home directory for keys\n");
        return false;
    }
    sprintf(szName, "%s/fileKeys", m_tcHome.m_fileNames.m_szdirectory);
    m_szSealedKeyFile= strdup(szName);
    if(stat(m_szSealedKeyFile, &statBlock)<0) {
        // Keys don't exist, generate and save them
        m_uAlg= AES128;
        m_uMode= CBCMODE;
        m_uPad= SYMPAD;
        m_uHmac= HMACSHA256;
        if(m_sizeKey<32) {
            fprintf(g_logFile, "initFileKeys: key size too small %d\n", m_sizeKey);
            return false;
        }
        m_sizeKey= 32;
        if(!getCryptoRandom(m_sizeKey*NBITSINBYTE, m_authKeys)) {
            fprintf(g_logFile, "initFileKeys: cant generate keys\n");
            return false;
        }

        // key buf: sizeKey,alg,mode,pad,hmac, key
        memcpy(&keyBuf[n], &m_sizeKey, sizeof(int));
        n+= sizeof(int);
        memcpy(&keyBuf[n], &m_uAlg, sizeof(u32));
        n+= sizeof(u32);
        memcpy(&keyBuf[n], &m_uMode, sizeof(u32));
        n+= sizeof(u32);
        memcpy(&keyBuf[n], &m_uPad, sizeof(u32));
        n+= sizeof(u32);
        memcpy(&keyBuf[n], &m_uHmac, sizeof(u32));
        n+= sizeof(u32);
        memcpy(&keyBuf[n], m_authKeys, m_sizeKey);
        n+= m_sizeKey;

        if(!m_tcHome.m_myMeasurementValid) {
            fprintf(g_logFile, "initFileKeys: measurement invalid\n");
            return false;
        }
        // seal and save
        size= BIGKEYSIZE;
        m_sealTimer.Start();
        if(!m_tcHome.Seal(m_tcHome.m_myMeasurementSize, m_tcHome.m_myMeasurement,
                        n, keyBuf, &size, sealedkeyBuf)) {
            fprintf(g_logFile, "initFileKeys: cant seal keys\n");
            return false;
        }
        m_sealTimer.Stop();
        if(!saveBlobtoFile(m_szSealedKeyFile, sealedkeyBuf, size)) {
            fprintf(g_logFile, "initFileKeys: cant save sealed keys\n");
            return false;
        }
        m_fKeysValid= true;
    }
    else {
        // keys exist, unseal them
        size= BIGKEYSIZE;
        if(!getBlobfromFile(m_szSealedKeyFile, sealedkeyBuf, &size)) {
            fprintf(g_logFile, "initFileKeys: cant get sealed keys\n");
            return false;
        }
        if(!m_tcHome.m_myMeasurementValid) {
            fprintf(g_logFile, "initFileKeys: measurement invalid\n");
            return false;
        }
        m= SMALLKEYSIZE;
        m_unsealTimer.Start();
        if(!m_tcHome.Unseal(m_tcHome.m_myMeasurementSize, m_tcHome.m_myMeasurement,
                        size, sealedkeyBuf, &m, keyBuf)) {
            fprintf(g_logFile, "initFileKeys: cant unseal keys\n");
            return false;
        }
        m_unsealTimer.Stop();

        memcpy(&m_sizeKey, &keyBuf[n], sizeof(int));
        n+= sizeof(int);
        memcpy(&m_uAlg, &keyBuf[n], sizeof(u32));
        n+= sizeof(u32);
        memcpy(&m_uMode, &keyBuf[n], sizeof(u32));
        n+= sizeof(u32);
        memcpy(&m_uPad, &keyBuf[n], sizeof(u32));
        n+= sizeof(u32);
        memcpy(&m_uHmac, &keyBuf[n], sizeof(u32));
        n+= sizeof(u32);
        memcpy(m_authKeys, &keyBuf[n], m_sizeKey);
        n+= m_sizeKey;
        if(n>m) {
            fprintf(g_logFile, "initFileKeys: unsealed keys wrong size\n");
            return false;
        }
        m_fKeysValid= true;
    }

#ifdef  TEST
    fprintf(g_logFile, "initFileKeys\n");
    PrintBytes("fileKeys\n", m_authKeys, m_sizeKey);
    fflush(g_logFile);
#endif
    return true;
}


bool authClient::initClient(const char* configDirectory, const char* serverAddress, u_short serverPort)
{
    struct sockaddr_in  server_addr;
    int                 slen= sizeof(struct sockaddr_in);
    int                 iError;
    bool                fRet= true;
    const char*         directory= NULL;

#ifdef  TEST
    fprintf(g_logFile, "initClient\n");
#endif

    try {
        const char** parameters= NULL;
        int parameterCount= 0;
        if(configDirectory==NULL) {
            directory= DEFAULTDIRECTORY;
        } else {
            directory= configDirectory;
            parameters= &directory;
            parameterCount= 1;
        }

        if(!initAllCrypto()) {
            throw "authClient::Init: can't initcrypto\n";
        }
        m_oKeys.m_fClient= true;

        // init Host and Environment
        m_taoHostInitializationTimer.Start();
        if(!m_host.HostInit(PLATFORMTYPELINUX, parameterCount, parameters)) {
            throw "authClient::Init: can't init host\n";
        }
        m_taoHostInitializationTimer.Stop();
#ifdef TEST
        fprintf(g_logFile, "authClient::Init: after HostInit, pid: %d\n",
            getpid());
#endif

        // init environment
        m_taoEnvInitializationTimer.Start();
        if(!m_tcHome.EnvInit(PLATFORMTYPELINUXAPP, "authClient",
                                DOMAIN, directory, 
                                &m_host, 0, NULL)) {
            throw "authClient::Init: can't init environment\n";
        }
        m_taoEnvInitializationTimer.Stop();
#ifdef TEST
        fprintf(g_logFile, "authClient::Init: after EnvInit\n");
        m_tcHome.printData();
#endif

        // Initialize file encryption keys
        if(!initFileKeys())
            throw "authClient::Init: can't init file keys\n";
#ifdef TEST
        fprintf(g_logFile, "authClient::Init: after initFileKeys\n");
        m_tcHome.printData();
#endif

        // Initialize program private key and certificate for session
        if(!m_tcHome.m_privateKeyValid || 
               !m_oKeys.getMyProgramKey((RSAKey*)m_tcHome.m_privateKey))
            throw "authClient::Init: Cant get my private key\n";
        if(!m_tcHome.m_myCertificateValid || 
               !m_oKeys.getMyProgramCert(m_tcHome.m_myCertificate))
            throw "authClient::Init: Cant get my Cert\n";
    
        // Initialize resource and principal tables
#if 0
        if(!g_theVault.initMetaData(m_tcHome.m_fileNames.m_szdirectory, "authClient"))
            throw "authClient::Init: Cant init metadata\n";
        if(!g_theVault.initFileNames())
            throw "authClient::Init: Cant init file names\n";
#endif

        // Init global policy 
        if(!initPolicy())
            throw "authClient::Init: Cant init policy objects\n";

        // open sockets
        m_fd= socket(AF_INET, SOCK_STREAM, 0);
        if(m_fd<0) 
            throw  "Can't get socket\n";
        memset((void*) &server_addr, 0, sizeof(struct sockaddr_in));

#ifdef  TEST
        fprintf(g_logFile, "initClient: socket opened\n");
#endif

        server_addr.sin_family= AF_INET;

        // Fix: set up authClient and authServer to pass arguments down to
        // their measured versions so we can control this by arguments
        if (!inet_aton(serverAddress, &server_addr.sin_addr)) {
          throw "Can't create the address for the authServer";
        }
        server_addr.sin_port= htons(serverPort);
    
        iError= connect(m_fd, (const struct sockaddr*) &server_addr, (socklen_t) slen);
        if(iError!=0)
            throw  "authClient::Init: Can't connect";

#ifdef TEST
        fprintf(g_logFile, "initClient: connect completed\n");
        fflush(g_logFile);
#endif
    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "Error: %s\n", szError);
        fflush(g_logFile);
        m_tcHome.EnvClose();
        m_host.HostClose();
    }

    return fRet;
}


// -------------------------------------------------------------------------


/*
 *  Key/Principal protocol
 *
 *  client phase 1  client-->server:
 *      clientMsg1(rand, ciphersuites)
 *  server phase 1  server-->client:
 *      serverMsg1(rand, ciphersuite, server-cert)
 *  client phase 2  client-->server:
 *      clientMsg2(E_S(premaster), D_C(rand1||rand2), client-cert)
 *  server phase 2  server-->client:
 *      serverMsg2(Principal cert requests, challenge)
 *  ----- Encrypted from here on
 *  client phase 3  client-->server:
 *      clientMsg4(Principal-certs, D_P1(challenge), D_P2(challenge+1),...)
 *  server phase 4  server-->client serverMsg3(Successful nego)
 *
 *  Secret Keys:[64]:= 
 *      PRF(premaster, "keyNego protocol", Client Rand, Server-Rand, client-Hash, server-Hash)
 *
 *  Notes:
 *      1. Should use DH for perfect forward secrecy
 *      2. If you use GCM, don't need seperate auth key
 *
 *  MAC(text)_t= HMAC(K, text)_t= H((K0⊕opad)||H((K0⊕ipad)||text))_t
 *      ipad: Inner pad; the byte 0x36 repeated B times.
 *      opad: Outer pad; the byte 0x5c repeated B times.
 *      B-block size of hash.
 *      If the length of K=B: set  K0 =K.
 *      If the length of K>B: hash K to obtain an L byte string, then
 *      append (B-L) 0's to create a B-byte string K0 (i.e., 
 *        K0= H(K)|| 00...00).
 *      If the length K<B: append zeros to the end of K to create a B-byte
 *      string K0 (e.g., if K is 20 bytes in length and B=64, then K will
 *        be appended with 44 zero bytes 0x00).
 *
 *  For now just PKCS-pad.  Should use PSS later.
 */


// Client Nego messages
const char* szMsg1= "<ClientNego phase='1'>\n<Random size='32'> %s </Random>\n"\
  "<CipherSuites>\n <CipherSuite> %s </CipherSuite>\n</CipherSuites>\n"\
  " <ProtocolVersion> 1 </ProtocolVersion>\n</ClientNego>\n";

const char* szMsg2a= 
  "<ClientNego phase='2' sessionId='%d'>\n<EncryptedPreMasterSecret>\n";
const char* szMsg2b= "\n</EncryptedPreMasterSecret>\n";
const char* szMsg2c= "\n<ClientCertificate>\n";
const char* szMsg2d= "\n</ClientCertificate>\n</ClientNego>\n";

const char* szMsg3a= "<ClientNego phase='3'>\n<SignedChallenge>\n";
const char* szMsg3b= "</SignedChallenge>\n";
const char* szMsg3c= "\n</ClientNego>\n"; 

const char* szMsg4aa= "<ClientNego phase='4'>\n<EvidenceCollection count='0'/>\n";
const char* szMsg4a= "<ClientNego phase='4'>\n";
const char* szMsg4d= "\n</ClientNego>\n"; 


// -----------------------------------------------------------------------


bool clientNegoMessage1(char* buf, int maxSize, const char* szAlg, const char* szRand)
//  client phase 1  client-->server:
//      clientMsg1(rand, ciphersuites)
{
    sprintf(buf,szMsg1, szRand, szAlg);
    return true;
}


bool clientNegoMessage2(char* buf, int maxSize, const char* szEncPreMasterSecret, 
                                   const char* szClientCert, int iSessionId)
//  client phase 2  client-->server:
//      clientMsg2(E_S(premaster), D_C(rand1||rand2), client-cert)
{
    int     iLeft= maxSize;
    char*   p= buf;
    int     i= 0;

    sprintf(buf, szMsg2a, iSessionId);
    i= strlen(buf);
    p+= i;
    iLeft-= i;

    if(!safeTransfer(&p, &iLeft, szEncPreMasterSecret))
        return false;
    if(!safeTransfer(&p, &iLeft, szMsg2b))
        return false;
    if(!safeTransfer(&p, &iLeft, szMsg2c))
        return false;
    if(!safeTransfer(&p, &iLeft, szClientCert))
        return false;
    if(!safeTransfer(&p, &iLeft, szMsg2d))
        return false;

    return true;
}


bool clientNegoMessage3(char* buf, int maxSize, const char* szSignedHash)
//  client phase 3  client-->server:
//      clientMsg2(signed hash)
{
    int     iLeft= maxSize;
    char*   p= buf;

    if(!safeTransfer(&p, &iLeft, szMsg3a))
        return false;
    if(!safeTransfer(&p, &iLeft, szSignedHash))
        return false;
    if(!safeTransfer(&p, &iLeft, szMsg3b))
        return false;
    if(!safeTransfer(&p, &iLeft, szMsg3c))
        return false;

    return true;
}


bool clientNegoMessage4(char* buf, int maxSize, const char* szPrincipalCerts,
                           int principalCount, const char* szSignedChallenges)
//  client phase 4  client-->server:
//      clientMsg4(Principal-certs, D_P1(challenge), D_P2(challenge+1),... )
{
    int     iLeft= maxSize;
    char*   p= buf;

#ifdef TEST
    fprintf(g_logFile, "clientNegoMessage4(%d), principals: %d\nCerts: %s\nSignedChallenges: %s\n",
            maxSize, principalCount, szPrincipalCerts,szSignedChallenges);
#endif
    if(principalCount==0) {
        if(!safeTransfer(&p, &iLeft, szMsg4aa))
            return false;
    }
    else {
        if(!safeTransfer(&p, &iLeft, szMsg4a))
            return false;
        if(!safeTransfer(&p, &iLeft, szPrincipalCerts))
            return false;
        if(!safeTransfer(&p, &iLeft, szSignedChallenges))
            return false;
    }

    if(!safeTransfer(&p, &iLeft, szMsg4d))
        return false;
    
    return true;
}


bool getDatafromServerMessage1(int n, char* request, sessionKeys& oKeys)
{
    TiXmlDocument   doc;
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;
    TiXmlElement*   pRootElement= NULL;
    char*           szCipherSuite= NULL;
    const char*     szRandom= NULL;
    char*           szServerCert= NULL;
    const char*     szProposedSuite= NULL;
    int             iOutLen= 128;
    int             iIndex= -1;
    bool            fRet= true;

#ifdef  TEST
    fprintf(g_logFile, "ServerMessage 1\n%s\n", request);
    fprintf(g_logFile, "MAXREQUESTSIZE = %d\n", MAXREQUESTSIZE);
    fflush(g_logFile);
#endif
    try {
        // Parse document
        if(!doc.Parse(request)) 
            throw "getDatafromServerMessage1: parse failure\n";
        pRootElement= doc.RootElement();
        if(pRootElement==NULL) 
            throw "getDatafromServerMessage1: Cant find root\n";
        pRootElement->QueryIntAttribute("sessionId", &oKeys.m_iSessionId);
        pNode= Search((TiXmlNode*) pRootElement, "Random");
        if(pNode==NULL)
            throw "getDatafromServerMessage1: Cant find random1\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw  "getDatafromServerMessage1: Bad random value";
        szRandom= pNode1->Value();
        if(szRandom==NULL)
            throw  "getDatafromServerMessage1: Bad random value";
        iOutLen= SMALLNONCESIZE;
        if(!fromBase64(strlen(szRandom), szRandom, &iOutLen, (byte*)oKeys.m_rguServerRand)) 
            throw "getDatafromServerMessage1: Cant base64 decode random number\n";
        oKeys.m_fServerRandValid= true;

        // get ciphersuite
        iIndex= -1;
        pNode= Search((TiXmlNode*) pRootElement, "CipherSuite");
        if(pNode==NULL)
            throw  "getDatafromServerMessage1: No ciphersuite\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw  "getDatafromServerMessage1: Bad ciphersuite\n";
        szProposedSuite= ((TiXmlElement*)pNode1)->Value();
        if(szProposedSuite==NULL)
            throw "getDatafromServerMessage1: Unsupported cipher suite\n";
        iIndex =cipherSuiteIndexFromName(szProposedSuite);
        if(iIndex<0)
            throw "getDatafromServerMessage1: Unsupported cipher suite\n";
        szCipherSuite= cipherSuiteNameFromIndex(iIndex);
        if(szCipherSuite==NULL)
            throw "getDatafromServerMessage1: No ciphersuite";
        oKeys.m_szSuite= strdup(szCipherSuite);

        // ServerCertificate
        pNode= Search((TiXmlNode*) pRootElement, "ServerCertificate");
        if(pNode==NULL)
            throw "getDatafromServerMessage1: No ServerCertificate\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw "getDatafromServerMessage1: No ServerCertificate\n";
        szServerCert= canonicalize(pNode1);
        if(szServerCert==NULL)
            throw  "getDatafromServerMessage1: Can't canonicalize Server Certificate\n";
        oKeys.m_szXmlServerCert= szServerCert;
        oKeys.m_pserverCert= new PrincipalCert();
        if(!oKeys.m_pserverCert->init(szServerCert))
            throw "getDatafromServerMessage1: Cant initialize server certificate\n";
        if(!oKeys.m_pserverCert->parsePrincipalCertElements())
            throw "getDatafromServerMessage1: Cant parse client certificate\n";
        oKeys.m_pserverPublicKey= (RSAKey*)oKeys.m_pserverCert->getSubjectKeyInfo();
        if(oKeys.m_pserverPublicKey==NULL)
            throw "getDatafromServerMessage1: Cant init client public RSA key\n";
        oKeys.m_fServerCertValid= true;
    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "%s", szError);
    }

    return fRet;
}


// <RequestPrincipalCertificates/>
// <Challenge> </Challenge>
bool getDatafromServerMessage2(int n, char* request, sessionKeys& oKeys)
{
    TiXmlDocument   doc;
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;
    TiXmlElement*   pRootElement= NULL;
    int             iOutLen= 128;
    bool            fRet= true;

#ifdef  TEST
    fprintf(g_logFile, "ServerMessage 2\n%s\n", request);
    fflush(g_logFile);
#endif
    try {
        if(!doc.Parse(request))
            throw "getDatafromServerMessage2: parse failure\n";
        pRootElement= doc.RootElement();
        if(pRootElement==NULL)
            throw "getDatafromServerMessage2: No root element\n";
        pNode= Search((TiXmlNode*) pRootElement, "RequestAuthentication");
        if(pNode==NULL)
            throw "getDatafromServerMessage2: No RequestAuthentication\n";
        const char* p= ((TiXmlElement*) pNode)->Attribute("Algorithm");
        if(p!=NULL)
            oKeys.m_szChallengeSignAlg= strdup(p);

#ifdef  TEST
        fprintf(g_logFile, "getDatafromServerMessage2: hash processing\n");
        fflush(g_logFile);
#endif
        pNode= Search((TiXmlNode*) pRootElement, "Challenge");
        if(pNode==NULL)
            throw "getDatafromServerMessage2: No challenge element\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw "getDatafromServerMessage2: Bad challenge element\n";
        const char* szRandom= pNode1->Value();
        if(szRandom==NULL)
            throw "getDatafromServerMessage2: No random element\n";
        iOutLen= SMALLNONCESIZE;
        if(!fromBase64(strlen(szRandom), szRandom, &iOutLen, (byte*)oKeys.m_rguChallenge))
            throw "getDatafromServerMessage2: Cant base64 decode random number\n";
        oKeys.m_fChallengeValid= true;

        pNode= Search((TiXmlNode*) pRootElement, "Hash");
        if(pNode==NULL)
            throw "getDatafromServerMessage2: No hash element\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw "getDatafromServerMessage2: Bad hash element\n";
        oKeys.m_szbase64ServerMessageHash= strdup( pNode1->Value());
        oKeys.m_fbase64ServerMessageHashValid= true;
        if(oKeys.m_szbase64ServerMessageHash==NULL)
            throw "getDatafromServerMessage2: No hash element\n";
        iOutLen= SHA256DIGESTBYTESIZE;
        if(!fromBase64(strlen(oKeys.m_szbase64ServerMessageHash), 
                              oKeys.m_szbase64ServerMessageHash, &iOutLen, 
                              (byte*)oKeys.m_rgDecodedServerMessageHash))
            throw "getDatafromServerMessage2: Cant base64 decode hash\n";
        oKeys.m_fDecodedServerMessageHashValid= true;
    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "%s", szError);
    }

    return fRet;
}


bool getDatafromServerMessage3(int n, char* request, sessionKeys& oKeys)
{
    TiXmlDocument   doc;
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;
    TiXmlElement*   pRootElement= NULL;
    bool            fRet= true;

#ifdef  TEST
    fprintf(g_logFile, "ServerMessage 3\n%s\n", request);
    fflush(g_logFile);
#endif
    try {
        if(!doc.Parse(request))
            throw "getDatafromServerMessage3: parse failure\n";
        pRootElement= doc.RootElement();
        if(pRootElement==NULL)
            throw "getDatafromServerMessage3: No root element\n";

        pNode= Search((TiXmlNode*) pRootElement, "Status");
        if(pNode==NULL)
            throw "getDatafromServerMessage3: No status element\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw "getDatafromServerMessage3: Bad status element\n";
        const char*   szStatus= pNode1->Value();
        if(szStatus==NULL)
            throw "getDatafromServerMessage3: Bad status element\n";
        if(strcmp(szStatus, "Succeed")!=0)
           fRet= false;
    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "%s", szError);
    }

    return fRet;
}


// ------------------------------------------------------------------------


bool authClient::protocolNego(int fd, safeChannel& fc, const char* keyFile, const char* certFile)
{
    char    request[MAXREQUESTSIZEWITHPAD];
    char    rgszBase64[256];
    int     i, n;
    int     type= CHANNEL_NEGO;
    byte    multi= 0;
    byte    final= 0;
    int     iOut64= 256;
    char*   szSignedNonce= NULL;
    char*   szEncPreMasterSecret= NULL;
    char*   szSignedChallenges= NULL;
    char*   szAlg= (char*) "TLS_RSA1024_WITH_AES128_CBC_SHA256";
    bool    fRet= true;


    m_clientState= KEYNEGOSTATE;
    request[0]= '\0';
#ifdef TEST
    fprintf(g_logFile, "authClient: protocol negotiation\n");
    fflush(g_logFile);
#endif

    try {

        // init message hash
        if(!m_oKeys.initMessageHash())
            throw  "authClient::protocolNego: Can't init message hash";

        // Phase 1, send
        iOut64= 256;
        if(!getBase64Rand(SMALLNONCESIZE, m_oKeys.m_rguClientRand, &iOut64, rgszBase64))
            throw  "authClient::protocolNego: Can't generated first nonce";
        m_oKeys.m_fClientRandValid= true;

        if(!clientNegoMessage1(request, MAXREQUESTSIZE, szAlg, rgszBase64))
            throw  "authClient::protocolNego: Can't format negotiation message 1";
        if(!m_oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw  "authClient::protocolNego: Can't update message hash";
        if((n=sendPacket(fd, (byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw  "authClient::protocolNego: Can't send packet 1";
    
        // Phase 1, receive
        if((n=getPacket(fd, (byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw  "authClient::protocolNego: Can't get packet 1";
        if(!m_oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw  "authClient::protocolNego: Can't update message hash";
        if(!getDatafromServerMessage1(n, request, m_oKeys))
            throw  "authClient::protocolNego: Can't decode server message 1";

        // Phase 2, send
        if(!m_oKeys.generatePreMaster())
            throw  "authClient::protocolNego: Cant generate premaster";
        if(!m_oKeys.computeClientKeys())
            throw "authClient::protocolNego: Cant compute client keys";

        // Pre-master secret
        if(!m_oKeys.m_fPreMasterSecretValid)
            throw  "authClient: No Pre-master string";
        if(!m_oKeys.m_fServerCertValid)
            throw  "authClient: Server key invalid";

        szEncPreMasterSecret= rsaXmlEncodeChallenge(true, *m_oKeys.m_pserverPublicKey,
                                    m_oKeys.m_rguPreMasterSecret, BIGSYMKEYSIZE);
#ifdef TEST
        fprintf(g_logFile, "authClient: pre-master encoded %s\n", 
                szEncPreMasterSecret);
        fflush(g_logFile);
#endif
        if(szEncPreMasterSecret==NULL)
            throw "authClient: Cant encrypt premaster secret";
        m_oKeys.m_fEncPreMasterSecretValid= true;

        if(!clientNegoMessage2(request, MAXREQUESTSIZE, szEncPreMasterSecret,
                               m_oKeys.m_szXmlClientCert, m_oKeys.m_iSessionId))
            throw  "authClient: Can't format negotiation message 2";
        if(!m_oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw  "authClient::protocolNego: Can't update message hash";
        if((n=sendPacket(fd, (byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw  "authClient: Can't send packet 2";

        if(!m_oKeys.clientcomputeMessageHash()) 
            throw "authClient::protocolNego: client cant compute message hash";
        if(!m_oKeys.clientsignMessageHash()) 
            throw "authClient::protocolNego: client cant sign message hash";
        if(!clientNegoMessage3(request, MAXREQUESTSIZE, m_oKeys.m_szbase64SignedMessageHash))
            throw  "authClient: Can't format negotiation message 3";
        if(!m_oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw  "authClient::protocolNego: Can't update message hash";
        if((n=sendPacket(fd, (byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw  "authClient: Can't send packet 2";

        // encrypted from here on
        if(!initSafeChannel(fc))
            throw  "authClient: Can't init safe channel";
#ifdef TEST
        fprintf(g_logFile, "authClient: initsafeChannel succeeded\n");
#endif

        // Assume CBC
        if((n=getPacket(fd, fc.lastgetBlock, AES128BYTEBLOCKSIZE, &type, &multi, &final))<0)
            throw "authClient: Cant get IV\n";
        fc.fgetIVReceived= true;
        if((n=sendPacket(fd, fc.lastsendBlock, AES128BYTEBLOCKSIZE, CHANNEL_NEGO_IV, 0, 1))<0)
            throw "authClient: Cant send IV\n";
        fc.fsendIVSent= true;
#ifdef  TEST
        fprintf(g_logFile, "authClient::protocolNego: Encrypted mode on\n");
        PrintBytes((char*)"Received IV: ", fc.lastgetBlock, AES128BYTEBLOCKSIZE);
        PrintBytes((char*)"Sent     IV: ", fc.lastsendBlock, AES128BYTEBLOCKSIZE);
        fflush(g_logFile);
#endif

        // Phase 2, receive
        if((n=fc.safegetPacket((byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw  "authClient: Can't get server packet 2";
        if(!m_oKeys.servercomputeMessageHash())
            throw  "authClient::protocolNego: Can't compute server hash";
        if(!getDatafromServerMessage2(n, request, m_oKeys))
            throw  "authClient::protocolNego: Can't decode server message 2";

        // do hashes match?
#ifdef TEST
        fprintf(g_logFile, "authClient::protocolNego: server hases\n");
    PrintBytes("Computed: ", m_oKeys.m_rgServerMessageHash, 
                    SHA256DIGESTBYTESIZE);
    PrintBytes("Received: ", m_oKeys.m_rgDecodedServerMessageHash, 
                    SHA256DIGESTBYTESIZE);
    fflush(g_logFile);
#endif
        if(!m_oKeys.m_fServerMessageHashValid || 
           !m_oKeys.m_fDecodedServerMessageHashValid ||
           memcmp(m_oKeys.m_rgServerMessageHash, m_oKeys.m_rgDecodedServerMessageHash, 
                  SHA256DIGESTBYTESIZE)!=0)
            throw  "authClient::protocolNego: server hash does not match";

        // Phase 4, send
        if(!m_oKeys.getPrincipalPrivateKeysFromFile(keyFile))  
            throw  "authClient: Cant principal private keys from file";
#ifdef TEST
        fprintf(g_logFile, "authClient: got principal keys\n");
#endif
        if(!m_oKeys.getPrincipalCertsFromFile(certFile))
            throw  "authClient: Cant get principal private keys from file";
        if(!m_oKeys.initializePrincipalPrivateKeys())
            throw  "authClient: Cant initialize principal private keys";
#ifdef TEST
        fprintf(g_logFile, "authClient: got principal private keys\n");
#endif
        if(!m_oKeys.initializePrincipalCerts())
            throw  "authClient: Cant initialize principal certs\n";

        if(strcmp(m_oKeys.m_szChallengeSignAlg, "TLS_RSA2048_WITH_AES128_CBC_SHA256")!=0 &&
           strcmp(m_oKeys.m_szChallengeSignAlg, "TLS_RSA1024_WITH_AES128_CBC_SHA256")!=0)
            throw  "authClient: Unsupported challenge algorithm\n";
        
        szSignedChallenges= 
                rsaXmlEncodeChallenges(false, m_oKeys.m_iNumPrincipalPrivateKeys,
                                                 m_oKeys.m_rgPrincipalPrivateKeys,
                                                 m_oKeys.m_rguChallenge, SMALLNONCESIZE);
#ifdef TEST
        fprintf(g_logFile, "authClient: challenges encoded\n");
#endif
        if(szSignedChallenges==NULL)
            throw  "authClient: Can't sign principal challenges";
        if(!clientNegoMessage4(request, MAXREQUESTSIZE, m_oKeys.m_szPrincipalCerts, 
                               m_oKeys.m_iNumPrincipalPrivateKeys, szSignedChallenges))
            throw  "authClient: Can't format negotiation message 3";
        if((n=fc.safesendPacket((byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw  "authClient: Can't send packet 3";

        // Phase 3, receive
        if((n=fc.safegetPacket((byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw  "authClient: Can't get packet 3";

        if(!getDatafromServerMessage3(n, request, m_oKeys))
            throw  "authClient: Can't decode client message 3";

        m_oKeys.validateChannelData(true);
#ifdef TEST
        fprintf(g_logFile, "authClient: channel data validated\n");
#endif

        // register principals
        if(m_oKeys.m_pserverCert!=NULL) {
            if(registerPrincipalfromCert(m_oKeys.m_pserverCert)==NULL)
                throw "authClient: Can't register server principal\n";
        }
#ifdef TEST
        fprintf(g_logFile, "authClient: server principal registered\n");
#endif

        if(registerPrincipalfromCert(m_oKeys.m_pclientCert)==NULL)
            throw "authClient: Can't register client principal\n";
#ifdef TEST
        fprintf(g_logFile, "authClient: server principal registered\n");
#endif

        for(i=0;i<m_oKeys.m_iNumPrincipals; i++) {
            if(m_oKeys.m_rgPrincipalCerts[i]!=NULL) {
                if(registerPrincipalfromCert(m_oKeys.m_rgPrincipalCerts[i])==NULL)
                    throw "authClient: Can't register client principal\n";
            }
        }
        m_clientState= REQUESTSTATE;
#ifdef TEST
        fprintf(g_logFile, "authClient: protocol nego succesfully completed\n");
        fflush(g_logFile);
#endif
    }
    catch(const char* szError) {
        fprintf(g_logFile, "authClient: Protocol Nego error: %s\n", szError);
        fRet= false;
        fflush(g_logFile);
    }

    if(szSignedNonce==NULL) {
        free(szSignedNonce);
        szSignedNonce= NULL;
    }
    if(szEncPreMasterSecret==NULL) {
        free(szEncPreMasterSecret);
        szEncPreMasterSecret= NULL;
    }
    if(szSignedChallenges!=NULL) {
        free(szSignedChallenges);
        szSignedChallenges= NULL;
    }
    m_clientState= REQUESTSTATE;

    return fRet;
}


bool authClient::closeClient()
{

    m_clientState= SERVICETERMINATESTATE;

#ifdef TEST
    fprintf(g_logFile,"in closeClient()\n");
    fflush(g_logFile);
#endif

    if(m_fd>0) {
#if 0
        packetHdr oPH;
        oPH.len= 0;
        write(m_fd, (byte*)&oPH,sizeof(packetHdr));
#endif
        close(m_fd);
        m_fd= 0;
    }

#ifdef TEST
    fprintf(g_logFile,"closeClient returning\n");
    fflush(g_logFile);
#endif
    return true;
}


bool authClient::initSafeChannel(safeChannel& fc)
{
    return fc.initChannel(m_fd, AES128, CBCMODE, HMACSHA256, 
                          AES128BYTEKEYSIZE, AES128BYTEKEYSIZE,
                          m_oKeys.m_rguEncryptionKey1, m_oKeys.m_rguIntegrityKey1, 
                          m_oKeys.m_rguEncryptionKey2, m_oKeys.m_rguIntegrityKey2);
}


// ------------------------------------------------------------------------


const char*  g_szTerm= "terminate channel\n";


#define AUTHCLIENTTEST
#ifdef  AUTHCLIENTTEST

bool authClient::establishConnection(safeChannel& fc, 
                                    const char* keyFile, 
                                    const char* certFile, 
                                    const char* directory,
                                    const char* serverAddress,
                                    u_short serverPort) {
    try {
        if (g_policyPrincipalCert==NULL) {
            g_policyPrincipalCert= new PrincipalCert();
            if(g_policyPrincipalCert==NULL)
                throw "authClient main: failed to new Principal\n";
        }

#ifdef  TEST
        fprintf(g_logFile, "authClient main: inited g_policyPrincipalCert\n");
        fflush(g_logFile);
#endif
        // init logfile, crypto, etc
        if(!initClient(directory, serverAddress, serverPort))
            throw "authClient main: initClient() failed\n";

        // copy my public key into client public key
        if(!m_tcHome.m_myCertificateValid || 
               !m_oKeys.getClientCert(m_tcHome.m_myCertificate))
            throw "authClient main: Cant load client public key structures\n";

#ifdef  TEST
        fprintf(g_logFile, "authClient main: protocol nego\n");
        fflush(g_logFile);
#endif
        // protocol Nego
        m_protocolNegoTimer.Start();
        if(!protocolNego(m_fd, fc, keyFile, certFile))
            throw "authClient main: Cant negotiate channel\n";
        m_protocolNegoTimer.Stop();

#ifdef TEST
        m_oKeys.printMe();
        fflush(g_logFile);
#endif
    }
    catch(const char* szError) {
        fprintf(g_logFile, "Error: %s\n", szError);
        fflush(g_logFile);
        return false;
    }

  return true;
}

void authClient::closeConnection(safeChannel& fc) {
        if(fc.fd>0) {
                fc.safesendPacket((byte*) g_szTerm, strlen(g_szTerm)+1, CHANNEL_TERMINATE, 0, 1);
        }
}


// ------------------------------------------------------------------------

//
//  Application specific logic
// 

bool authClient::readCredential(safeChannel& fc, const string& subject, const string& evidenceFileName, 
                                const string& remoteCredential, const string& localOutput) 
{
#if 0
    int             encType= NOENCRYPT;
    char*           szEvidence= readandstoreString(evidenceFileName.c_str());
 
    if(clientgetCredentialfromserver(fc, 
                                   remoteCredential.c_str(),
                                   szEvidence,
                                   localOutput.c_str(),
                                   encType, 
                                   m_authKeys, 
                                   m_encTimer)) {
        fprintf(g_logFile, "authClient authTest: read file successful\n");
        fflush(g_logFile);
    } 
    else {
        fprintf(g_logFile, "authClient fileTest: read file unsuccessful\n");
        fflush(g_logFile);
        return false;
    }
#endif
    return true;
}


bool authClient::compareFiles(const string& firstFile, const string& secondFile) {
    // compare the two files to see if the file returned by the server is exactly the file we sent
    ifstream origFile;
    ifstream newFile;
    int pos = 0;
    bool failed = false;
    origFile.open(firstFile.c_str(), ifstream::in);
    newFile.open(secondFile.c_str(), ifstream::in);
    
    while(origFile.good() && newFile.good()) {
        char co = origFile.get();
        char cn = newFile.get();
        if (co != cn) {
#ifdef TEST
            fprintf(g_logFile, "The file returned by the server failed to match the file sent at byte %d\n", pos);
#endif
            failed = true;
            break;
        }

        ++pos;
    }

    // when we get here without hitting a character mismatch, one of the streams is no longer good
    // if one is still good, then the files are not the same length
    if (!failed && (origFile.good() || newFile.good())) {
#ifdef TEST
        fprintf(g_logFile, "The file returned by the server was not the same length as the file sent to the server\n");
#endif
        failed = true;
    } 

#ifdef TEST
    if (!failed) {
        fprintf(g_logFile, "The file returned by the server is identical to the one sent to the server\n");
    }
#endif

    return !failed;
}


// ------------------------------------------------------------------------


int main(int an, char** av)
{
    authClient      oAuthClient;
    safeChannel     fc;
    int             iRet= 0;
    int             i;
    bool            fInitProg= false;
    const char*     directory= NULL;
    string          testPath("authClient/tests/");
    string          testFileName("tests.xml");
    initLog(NULL);

#ifdef  TEST
    fprintf(g_logFile, "authClient test\n");
    fflush(g_logFile);
#endif

    if(an>1) {
        for(i=0;i<an;i++) {
            if(strcmp(av[i],"-initProg")==0) {
                fInitProg= true;
            }
            if(strcmp(av[i],"-port")==0 && an>(i+1)) {
                oAuthClient.m_szPort= strdup(av[++i]);
            }
            if(strcmp(av[i],"-address")==0) {
                oAuthClient.m_szAddress= strdup(av[++i]);
            }
            if (strcmp(av[i],"-directory")==0) {
                directory= strdup(av[++i]);
            }
        }
    }
    UNUSEDVAR(directory);

    if(fInitProg) {
#ifdef  TEST
        fprintf(g_logFile, "authClient main starting measured %s\n", av[0]);
#endif
        if(!startMeAsMeasuredProgram(an, av)) {
#ifdef TEST
            fprintf(g_logFile, "main: measured program failed, exiting\n");
            fflush(g_logFile);
#endif
            return 1;
        }
#ifdef TEST
        fprintf(g_logFile, "main: measured program started, exiting\n");
        fflush(g_logFile);
#endif
        return 0;
    }

    initLog("authClient.log");
#ifdef  TEST
    fprintf(g_logFile, "authClient main in measured loop\n");
    fflush(g_logFile);
#endif
    try {

        // read the testPath and iterate through the set of tests, running each in turn
        DIR* testDir = opendir(testPath.c_str());
        if (NULL == testDir) {
            throw "Could not open the test directory\n";
        }

#ifdef TEST
        fprintf(g_logFile, "reading directory %s\n", testPath.c_str());    
#endif
        // each child directory is a test
        struct dirent* entry = NULL;
        string curDir(".");
        string parentDir("..");
        while((entry = readdir(testDir))) {
            if (curDir.compare(entry->d_name) == 0 || 
                parentDir.compare(entry->d_name) == 0) {
                continue;
            }
#ifdef TEST
            fprintf(g_logFile, "Got entry with name %s\n", entry->d_name);
#endif
            if (DT_DIR == entry->d_type) {
                string path = testPath + string(entry->d_name) + string("/");
                
                // get the three files from tests.xml
                string identityCertFile;
                string userCertFile;
                string keyFile;
                authClient::getKeyFiles(path,
                            testFileName,
                            identityCertFile,
                            userCertFile,
                            keyFile);

                string identityCert = authClient::getFileContents(identityCertFile);
                string userCert = authClient::getFileContents(userCertFile);
                string key = authClient::getFileContents(keyFile);

                // DO SOMETHING HERE TO RUN THE TEST, using, e.g., key.c_str() for const char* of key
                printf("Got the file contents: \nidentityCert = %s\nuserCert = %s\nkey = %s\n", identityCert.c_str(), userCert.c_str(), key.c_str());
                
            }
        }

#ifdef TEST
        if (0 != errno) {
            fprintf(g_logFile, "Got error %d\n", errno);
        } 
        else {
            fprintf(g_logFile, "Finished reading test directory without error\n");
        }
        
        fprintf(g_logFile, "authClient main: At close client\n");
#endif
        closeLog();

    } 
    catch (const char* err) {
        fprintf(g_logFile, "execution failed with error %s\n", err);
        iRet= 1;
    }

    return iRet;
}
#endif

void authClient::printTimers(FILE* log) {
    if (m_sealTimer.GetMeasurements().size() > 0) {
        fprintf(log, "clientSealTimes = ");
        m_sealTimer.print(log);
    }

    if (m_unsealTimer.GetMeasurements().size() > 0) {
        fprintf(log, "clientUnsealTimes =  ");
        m_unsealTimer.print(log);
    }

    if (m_taoEnvInitializationTimer.GetMeasurements().size() > 0) {
        fprintf(log, "clientTaoEnvInitTimes = ");
        m_taoEnvInitializationTimer.print(log);
    }

    if (m_taoHostInitializationTimer.GetMeasurements().size() > 0) {
        fprintf(log, "clientTaoHostInitTimes = ");
        m_taoHostInitializationTimer.print(log);
    }

    if (m_protocolNegoTimer.GetMeasurements().size() > 0) {
        fprintf(log, "clientProtocolNegoTimes = ");
        m_protocolNegoTimer.print(log);
    }

    if (m_encTimer.GetMeasurements().size() > 0) {
        fprintf(log, "clientEncTimes = ");
        m_encTimer.print(log);
    }

    if (m_decTimer.GetMeasurements().size() > 0) {
        fprintf(log, "clientDecTimes = ");
        m_decTimer.print(log);
    }
}

void authClient::resetTimers() {
    m_sealTimer.Clear();
    m_unsealTimer.Clear();
    m_taoEnvInitializationTimer.Clear();
    m_taoHostInitializationTimer.Clear();
    m_protocolNegoTimer.Clear();
    m_encTimer.Clear();
    m_decTimer.Clear();
}

void authClient::getKeyFiles(const string& directory,
                             const string& testFile,
                             string& identityCertFile,
                             string& userCertFile,
                             string& keyFile)
{
    string path = directory + testFile;
    TiXmlDocument doc(path.c_str());
    doc.LoadFile();

    const TiXmlElement* curElt = doc.RootElement();
    const TiXmlNode* child = NULL;
    while((child = curElt->IterateChildren(child))) {
        const string& name = child->ValueStr();
        const TiXmlElement* childElt = child->ToElement();
        const string& text(childElt->GetText());
        if (name.compare("IdentityCert") == 0) {
            identityCertFile = directory + text; 
        } else if (name.compare("UserCert") == 0) {
            userCertFile = directory + text;
        } else if (name.compare("Key") == 0) {
            keyFile = directory + text;
        } else {
            throw "Unknown child node of Test\n";
        }
    }

    return;
}

string authClient::getFileContents(const string& filename) {
    // read the file and output the text
    ifstream file(filename.c_str());
    string fileContents((istreambuf_iterator<char>(file)),
                        (istreambuf_iterator<char>()));
    return fileContents;
}

// ------------------------------------------------------------------------



