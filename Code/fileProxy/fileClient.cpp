//  File: fileClient.cpp
//      John Manferdelli
//
//  Description: Client for fileServer.
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
#include "fileClient.h"
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

#include "objectManager.h"
#include "resource.h"
#include "tao.h"

#include "trustedKeyNego.h"
#include "vault.h"
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


const char* szServerHostAddr= "127.0.0.1";

bool             g_globalpolicyValid= false;
metaData         g_theVault;
PrincipalCert*   g_policyPrincipalCert= NULL;
RSAKey*          g_policyKey= NULL;
accessPrincipal* g_policyAccessPrincipal= NULL;

#include "./policyCert.inc"

char* g_szClientPrincipalCertsFile= (char*)"fileClient/principalPublicKeys.xml";
char* g_szClientPrincipalPrivateKeysFile= (char*)"fileClient/principalPrivateKeys.xml";


accessPrincipal* registerPrincipalfromCert(PrincipalCert* pSig);


// ------------------------------------------------------------------------


fileClient::fileClient ()
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


fileClient::~fileClient ()
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
        memset(m_fileKeys, 0, m_sizeKey);
    m_fKeysValid= false;
    if(m_szSealedKeyFile!=NULL)
        free(m_szSealedKeyFile);
    m_szSealedKeyFile= NULL;
}


bool fileClient::initPolicy()
{
#ifdef TEST
    fprintf(g_logFile, "fileClient::initPolicy\n");
    fflush(g_logFile);
#endif
    if(!m_tcHome.m_envValid) {
        fprintf(g_logFile, "fileClient::initPolicy(): environment invalid\n");
        return false;
    }

    if(!m_tcHome.m_policyKeyValid)  {
        fprintf(g_logFile, "fileClient::initPolicy(): policyKey invalid\n");
        return false;
    }

#ifdef TEST1
    fprintf(g_logFile, "fileClient::initPolicy, about to initpolicy Cert\n%s\n",
            (char*)m_tcHome.m_policyKey);
    fflush(g_logFile);
    if(g_policyPrincipalCert==NULL)
        g_policyPrincipalCert= new PrincipalCert();
#endif
    if(!g_policyPrincipalCert->init((char*)m_tcHome.m_policyKey)) {
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


bool fileClient::initFileKeys()
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
        if(!getCryptoRandom(m_sizeKey*NBITSINBYTE, m_fileKeys)) {
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
        memcpy(&keyBuf[n], m_fileKeys, m_sizeKey);
        n+= m_sizeKey;

        if(!m_tcHome.m_myMeasurementValid) {
            fprintf(g_logFile, "initFileKeys: measurement invalid\n");
            return false;
        }
        // seal and save
        size= BIGKEYSIZE;
        if(!m_tcHome.Seal(m_tcHome.m_myMeasurementSize, m_tcHome.m_myMeasurement,
                        n, keyBuf, &size, sealedkeyBuf)) {
            fprintf(g_logFile, "initFileKeys: cant seal keys\n");
            return false;
        }
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
        if(!m_tcHome.Unseal(m_tcHome.m_myMeasurementSize, m_tcHome.m_myMeasurement,
                        size, sealedkeyBuf, &m, keyBuf)) {
            fprintf(g_logFile, "initFileKeys: cant unseal keys\n");
            return false;
        }
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
        memcpy(m_fileKeys, &keyBuf[n], m_sizeKey);
        n+= m_sizeKey;
        if(n>m) {
            fprintf(g_logFile, "initFileKeys: unsealed keys wrong size\n");
            return false;
        }
        m_fKeysValid= true;
    }

#ifdef  TEST
    fprintf(g_logFile, "initFileKeys\n");
    PrintBytes((char*)"fileKeys\n", m_fileKeys, m_sizeKey);
    fflush(g_logFile);
#endif
    return true;
}


bool fileClient::initClient(char* configDirectory)
{
    struct sockaddr_in  server_addr;
    int                 slen= sizeof(struct sockaddr_in);
    int                 iError;
    bool                fRet= true;
    char*               directory= NULL;

#ifdef  TEST
    fprintf(g_logFile, "initClient\n");
#endif

    try {

        char** parameters= NULL;
        int parameterCount= 0;
        if(configDirectory==NULL) {
            directory= DEFAULTDIRECTORY;
        } else {
            directory= configDirectory;
            parameters= &directory;
            parameterCount= 1;
        }

        if(!initAllCrypto()) {
            throw((char*)"fileClient::Init: can't initcrypto\n");
        }
        m_oKeys.m_fClient= true;

        // init Host and Environment
        if(!m_host.HostInit(PLATFORMTYPELINUX, parameterCount, parameters)) {
            throw((char*)"fileClient::Init: can't init host\n");
        }
#ifdef TEST
        fprintf(g_logFile, "fileClient::Init: after HostInit, pid: %d\n",
            getpid());
#endif

        // init environment
        if(!m_tcHome.EnvInit(PLATFORMTYPELINUXAPP, (char*)"fileClient",
                                DOMAIN, directory, 
                                &m_host, 0, NULL)) {
            throw((char*)"fileClient::Init: can't init environment\n");
        }
#ifdef TEST
        fprintf(g_logFile, "fileClient::Init: after EnvInit\n");
        m_tcHome.printData();
#endif

        // Initialize file encryption keys
        if(!initFileKeys())
            throw((char*)"fileClient::Init: can't init file keys\n");
#ifdef TEST
        fprintf(g_logFile, "fileClient::Init: after initFileKeys\n");
        m_tcHome.printData();
#endif

        // Initialize program private key and certificate for session
        if(!m_tcHome.m_privateKeyValid || 
               !m_oKeys.getMyProgramKey((RSAKey*)m_tcHome.m_privateKey))
            throw((char*)"fileClient::Init: Cant get my private key\n");
        if(!m_tcHome.m_myCertificateValid || 
               !m_oKeys.getMyProgramCert((char*)m_tcHome.m_myCertificate))
            throw((char*)"fileClient::Init: Cant get my Cert\n");
    
        // Initialize resource and principal tables
        if(!g_theVault.initMetaData(m_tcHome.m_fileNames.m_szdirectory, (char*)"fileClient"))
            throw((char*)"fileClient::Init: Cant init metadata\n");
        if(!g_theVault.initFileNames())
            throw((char*)"fileClient::Init: Cant init file names\n");

        // Init global policy 
        if(!initPolicy())
            throw((char*)"fileClient::Init: Cant init policy objects\n");

        // open sockets
        m_fd= socket(AF_INET, SOCK_STREAM, 0);
        if(m_fd<0) 
            throw((char*) "Can't get socket\n");
        memset((void*) &server_addr, 0, sizeof(struct sockaddr_in));

#ifdef  TEST
        fprintf(g_logFile, "initClient: socket opened\n");
#endif

        server_addr.sin_family= AF_INET;
        server_addr.sin_addr.s_addr= htonl(INADDR_ANY);
        // Fix: set up fileClient and fileServer to pass arguments down to
        // their measured versions so we can control this by arguments
        //if (!inet_aton("10.0.0.3", &server_addr.sin_addr)) {
        //  throw "Can't create the address for the fileServer";
        //}
        //server_addr.sin_addr.s_addr= htonl(INADDR_ANY);
        server_addr.sin_port= htons(SERVICE_PORT);
    
        iError= connect(m_fd, (const struct sockaddr*) &server_addr, (socklen_t) slen);
        if(iError!=0)
            throw((char*) "fileClient::Init: Can't connect", strerror(errno));

#ifdef TEST
        fprintf(g_logFile, "initClient: connect completed\n");
        fflush(g_logFile);
#endif
    }
    catch(char* szError) {
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
char* szMsg1= (char*) "<ClientNego phase='1'>\n<Random size='32'> %s </Random>\n"\
  "<CipherSuites>\n <CipherSuite> %s </CipherSuite>\n</CipherSuites>\n"\
  " <ProtocolVersion> 1 </ProtocolVersion>\n</ClientNego>\n";

char* szMsg2a= (char*)
  "<ClientNego phase='2' sessionId='%d'>\n<EncryptedPreMasterSecret>\n";
char* szMsg2b= (char*) "\n</EncryptedPreMasterSecret>\n";
char* szMsg2c= (char*) "\n<ClientCertificate>\n";
char* szMsg2d= (char*) "\n</ClientCertificate>\n</ClientNego>\n";

char* szMsg3a= (char*) "<ClientNego phase='3'>\n<SignedChallenge>\n";
char* szMsg3b= (char*) "</SignedChallenge>\n";
char* szMsg3c= (char*) "\n</ClientNego>\n"; 

char* szMsg4aa= (char*) "<ClientNego phase='4'>\n<EvidenceCollection count='0'/>\n";
char* szMsg4a= (char*) "<ClientNego phase='4'>\n";
char* szMsg4d= (char*) "\n</ClientNego>\n"; 


// -----------------------------------------------------------------------


bool clientNegoMessage1(char* buf, int maxSize, char* szAlg, char* szRand)
//  client phase 1  client-->server:
//      clientMsg1(rand, ciphersuites)
{
    sprintf(buf,szMsg1, szRand, szAlg);
    return true;
}


bool clientNegoMessage2(char* buf, int maxSize, char* szEncPreMasterSecret, 
                                   char* szClientCert, int iSessionId)
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


bool clientNegoMessage3(char* buf, int maxSize, char* szSignedHash)
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


bool clientNegoMessage4(char* buf, int maxSize, char* szPrincipalCerts,
                           int principalCount, char* szSignedChallenges)
//  client phase 4  client-->server:
//      clientMsg4(Principal-certs, D_P1(challenge), D_P2(challenge+1),... )
{
    int     iLeft= maxSize;
    int     k;
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
    TiXmlNode*      pNode2;
    TiXmlElement*   pRootElement= NULL;
    char*           szCipherSuite= NULL;
    char*           szRandom= NULL;
    char*           szServerCert= NULL;
    char*           szProposedSuite= NULL;
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
            throw((char*)"getDatafromServerMessage1: parse failure\n");
        pRootElement= doc.RootElement();
        if(pRootElement==NULL) 
            throw((char*)"getDatafromServerMessage1: Cant find root\n");
        pRootElement->QueryIntAttribute("sessionId", &oKeys.m_iSessionId);
        pNode= Search((TiXmlNode*) pRootElement, (char*)"Random");
        if(pNode==NULL)
            throw((char*)"getDatafromServerMessage1: Cant find random1\n");
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw((char*) "getDatafromServerMessage1: Bad random value");
        szRandom= (char*) pNode1->Value();
        if(szRandom==NULL)
            throw((char*) "getDatafromServerMessage1: Bad random value");
        iOutLen= SMALLNONCESIZE;
        if(!fromBase64(strlen(szRandom), szRandom, &iOutLen, (byte*)oKeys.m_rguServerRand)) 
            throw((char*)"getDatafromServerMessage1: Cant base64 decode random number\n");
        oKeys.m_fServerRandValid= true;

        // get ciphersuite
        iIndex= -1;
        pNode= Search((TiXmlNode*) pRootElement, (char*)"CipherSuite");
        if(pNode==NULL)
            throw((char*) "getDatafromServerMessage1: No ciphersuite\n");
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw((char*) "getDatafromServerMessage1: Bad ciphersuite\n");
        szProposedSuite= (char*)((TiXmlElement*)pNode1)->Value();
        if(szProposedSuite==NULL)
            throw((char*)"getDatafromServerMessage1: Unsupported cipher suite %s\n", szProposedSuite);
        iIndex =cipherSuiteIndexFromName(szProposedSuite);
        if(iIndex<0)
            throw((char*)"getDatafromServerMessage1: Unsupported cipher suite %s\n", szProposedSuite);
        szCipherSuite= cipherSuiteNameFromIndex(iIndex);
        if(szCipherSuite==NULL)
            throw((char*)"getDatafromServerMessage1: No ciphersuite");
        oKeys.m_szSuite= strdup(szCipherSuite);

        // ServerCertificate
        pNode= Search((TiXmlNode*) pRootElement, (char*)"ServerCertificate");
        if(pNode==NULL)
            throw((char*)"getDatafromServerMessage1: No ServerCertificate\n");
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw((char*)"getDatafromServerMessage1: No ServerCertificate\n");
        szServerCert= canonicalize(pNode1);
        if(szServerCert==NULL)
            throw((char*) "getDatafromServerMessage1: Can't canonicalize Server Certificate\n");
        oKeys.m_szXmlServerCert= szServerCert;
        oKeys.m_pserverCert= new PrincipalCert();
        if(!oKeys.m_pserverCert->init(szServerCert))
            throw((char*)"getDatafromServerMessage1: Cant initialize server certificate\n");
        if(!oKeys.m_pserverCert->parsePrincipalCertElements())
            throw((char*)"getDatafromServerMessage1: Cant parse client certificate\n");
        oKeys.m_pserverPublicKey= (RSAKey*)oKeys.m_pserverCert->getSubjectKeyInfo();
        if(oKeys.m_pserverPublicKey==NULL)
            throw((char*)"getDatafromServerMessage1: Cant init client public RSA key\n");
        oKeys.m_fServerCertValid= true;
    }
    catch(char* szError) {
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
    byte            rgRand[128];
    int             iOutLen= 128;
    bool            fRet= true;

#ifdef  TEST
    fprintf(g_logFile, "ServerMessage 2\n%s\n", request);
    fflush(g_logFile);
#endif
    try {
        if(!doc.Parse(request))
            throw((char*)"getDatafromServerMessage2: parse failure\n");
        pRootElement= doc.RootElement();
        if(pRootElement==NULL)
            throw((char*)"getDatafromServerMessage2: No root element\n");
        pNode= Search((TiXmlNode*) pRootElement, (char*)"RequestAuthentication");
        if(pNode==NULL)
            throw((char*)"getDatafromServerMessage2: No RequestAuthentication\n");
        char* p= (char*)((TiXmlElement*) pNode)->Attribute("Algorithm");
        if(p!=NULL)
            oKeys.m_szChallengeSignAlg= strdup(p);

#ifdef  TEST
        fprintf(g_logFile, "getDatafromServerMessage2: hash processing\n");
        fflush(g_logFile);
#endif
        pNode= Search((TiXmlNode*) pRootElement, (char*)"Challenge");
        if(pNode==NULL)
            throw((char*)"getDatafromServerMessage2: No challenge element\n");
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw((char*)"getDatafromServerMessage2: Bad challenge element\n");
        char* szRandom= (char*) pNode1->Value();
        if(szRandom==NULL)
            throw((char*)"getDatafromServerMessage2: No random element\n");
        iOutLen= SMALLNONCESIZE;
        if(!fromBase64(strlen(szRandom), szRandom, &iOutLen, (byte*)oKeys.m_rguChallenge))
            throw((char*)"getDatafromServerMessage2: Cant base64 decode random number\n");
        oKeys.m_fChallengeValid= true;

        pNode= Search((TiXmlNode*) pRootElement, (char*)"Hash");
        if(pNode==NULL)
            throw((char*)"getDatafromServerMessage2: No hash element\n");
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw((char*)"getDatafromServerMessage2: Bad hash element\n");
        oKeys.m_szbase64ServerMessageHash= strdup((char*) pNode1->Value());
        oKeys.m_fbase64ServerMessageHashValid= true;
        if(oKeys.m_szbase64ServerMessageHash==NULL)
            throw((char*)"getDatafromServerMessage2: No hash element\n");
        iOutLen= SHA256DIGESTBYTESIZE;
        if(!fromBase64(strlen(oKeys.m_szbase64ServerMessageHash), 
                              oKeys.m_szbase64ServerMessageHash, &iOutLen, 
                              (byte*)oKeys.m_rgDecodedServerMessageHash))
            throw((char*)"getDatafromServerMessage2: Cant base64 decode hash\n");
        oKeys.m_fDecodedServerMessageHashValid= true;
    }
    catch(char* szError) {
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
    TiXmlNode*      pNode2;
    TiXmlElement*   pRootElement= NULL;
    bool            fRet= true;
    int             iOutLen= 128;

#ifdef  TEST
    fprintf(g_logFile, "ServerMessage 3\n%s\n", request);
    fflush(g_logFile);
#endif
    try {
        if(!doc.Parse(request))
            throw((char*)"getDatafromServerMessage3: parse failure\n");
        pRootElement= doc.RootElement();
        if(pRootElement==NULL)
            throw((char*)"getDatafromServerMessage3: No root element\n");

        pNode= Search((TiXmlNode*) pRootElement, (char*)"Status");
        if(pNode==NULL)
            throw((char*)"getDatafromServerMessage3: No status element\n");
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw((char*)"getDatafromServerMessage3: Bad status element\n");
        char*   szStatus= (char*) pNode1->Value();
        if(szStatus==NULL)
            throw((char*)"getDatafromServerMessage3: Bad status element\n");
        if(strcmp(szStatus, (char*)"Succeed")!=0)
           fRet= false;
    }
    catch(char* szError) {
        fRet= false;
        fprintf(g_logFile, "%s", szError);
    }

    return fRet;
}


// ------------------------------------------------------------------------


bool fileClient::protocolNego(int fd, safeChannel& fc)
{
    char    request[MAXREQUESTSIZEWITHPAD];
    char    rgszBase64[256];
    int     i, n;
    int     type= CHANNEL_NEGO;
    byte    multi= 0;
    byte    final= 0;
    int     iOut64= 256;
    int     iOut= 256;
    char*   szSignedNonce= NULL;
    char*   szEncPreMasterSecret= NULL;
    char*   szSignedChallenges= NULL;
    char*   szAlg= (char*) "TLS_RSA1024_WITH_AES128_CBC_SHA256";
    bool    fRet= true;


    m_clientState= KEYNEGOSTATE;
    request[0]= '\0';
#ifdef TEST
    fprintf(g_logFile, "fileClient: protocol negotiation\n");
    fflush(g_logFile);
#endif

    try {

        // init message hash
        if(!m_oKeys.initMessageHash())
            throw((char*) "fileClient::protocolNego: Can't init message hash");

        // Phase 1, send
        iOut64= 256;
        if(!getBase64Rand(SMALLNONCESIZE, m_oKeys.m_rguClientRand, &iOut64, rgszBase64))
            throw((char*) "fileClient::protocolNego: Can't generated first nonce");
        m_oKeys.m_fClientRandValid= true;

        if(!clientNegoMessage1(request, MAXREQUESTSIZE, szAlg, rgszBase64))
            throw((char*) "fileClient::protocolNego: Can't format negotiation message 1");
        if(!m_oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw((char*) "fileClient::protocolNego: Can't update message hash");
        if((n=sendPacket(fd, (byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw((char*) "fileClient::protocolNego: Can't send packet 1");
    
        // Phase 1, receive
        if((n=getPacket(fd, (byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw((char*) "fileClient::protocolNego: Can't get packet 1");
        if(!m_oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw((char*) "fileClient::protocolNego: Can't update message hash");
        if(!getDatafromServerMessage1(n, request, m_oKeys))
            throw((char*) "fileClient::protocolNego: Can't decode server message 1");

        // Phase 2, send
        if(!m_oKeys.generatePreMaster())
            throw((char*) "fileClient::protocolNego: Cant generate premaster");
        if(!m_oKeys.computeClientKeys())
            throw((char*)"fileClient::protocolNego: Cant compute client keys");

        // Pre-master secret
        if(!m_oKeys.m_fPreMasterSecretValid)
            throw((char*) "fileClient: No Pre-master string");
        if(!m_oKeys.m_fServerCertValid)
            throw((char*) "fileClient: Server key invalid");

        szEncPreMasterSecret= rsaXmlEncodeChallenge(true, *m_oKeys.m_pserverPublicKey,
                                    m_oKeys.m_rguPreMasterSecret, BIGSYMKEYSIZE);
#ifdef TEST
        fprintf(g_logFile, "fileClient: pre-master encoded\n");
        fflush(g_logFile);
#endif
        if(szEncPreMasterSecret==NULL)
            throw((char*)"fileClient: Cant encrypt premaster secret");
        m_oKeys.m_fEncPreMasterSecretValid= true;

        if(!clientNegoMessage2(request, MAXREQUESTSIZE, szEncPreMasterSecret,
                               m_oKeys.m_szXmlClientCert, m_oKeys.m_iSessionId))
            throw((char*) "fileClient: Can't format negotiation message 2");
        if(!m_oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw((char*) "fileClient::protocolNego: Can't update message hash");
        if((n=sendPacket(fd, (byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw((char*) "fileClient: Can't send packet 2");

        if(!m_oKeys.clientcomputeMessageHash()) 
            throw((char*)"fileClient::protocolNego: client cant compute message hash");
        if(!m_oKeys.clientsignMessageHash()) 
            throw((char*)"fileClient::protocolNego: client cant sign message hash");
        if(!clientNegoMessage3(request, MAXREQUESTSIZE, m_oKeys.m_szbase64SignedMessageHash))
            throw((char*) "fileClient: Can't format negotiation message 3");
        if(!m_oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw((char*) "fileClient::protocolNego: Can't update message hash");
        if((n=sendPacket(fd, (byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw((char*) "fileClient: Can't send packet 2");

        // encrypted from here on
        if(!initSafeChannel(fc))
            throw((char*) "fileClient: Can't init safe channel");
#ifdef TEST
        fprintf(g_logFile, "fileClient: initsafeChannel succeeded\n");
#endif

        // Assume CBC
        if((n=getPacket(fd, fc.lastgetBlock, AES128BYTEBLOCKSIZE, &type, &multi, &final))<0)
            throw((char*)"fileClient: Cant get IV\n");
        fc.fgetIVReceived= true;
        if((n=sendPacket(fd, fc.lastsendBlock, AES128BYTEBLOCKSIZE, CHANNEL_NEGO_IV, 0, 1))<0)
            throw((char*)"fileClient: Cant send IV\n");
        fc.fsendIVSent= true;
#ifdef  TEST
        fprintf(g_logFile, "fileClient::protocolNego: Encrypted mode on\n");
        fflush(g_logFile);
#endif

        // Phase 2, receive
        if((n=fc.safegetPacket((byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw((char*) "fileClient: Can't get server packet 2");
        if(!m_oKeys.servercomputeMessageHash())
            throw((char*) "fileClient::protocolNego: Can't compute server hash");
        if(!getDatafromServerMessage2(n, request, m_oKeys))
            throw((char*) "fileClient::protocolNego: Can't decode server message 2");

        // do hashes match?
#ifdef TEST
        fprintf(g_logFile, "fileClient::protocolNego: server hases\n");
    PrintBytes((char*)"Computed: ", m_oKeys.m_rgServerMessageHash, 
                    SHA256DIGESTBYTESIZE);
    PrintBytes((char*)"Received: ", m_oKeys.m_rgDecodedServerMessageHash, 
                    SHA256DIGESTBYTESIZE);
    fflush(g_logFile);
#endif
        if(!m_oKeys.m_fServerMessageHashValid || 
           !m_oKeys.m_fDecodedServerMessageHashValid ||
           memcmp(m_oKeys.m_rgServerMessageHash, m_oKeys.m_rgDecodedServerMessageHash, 
                  SHA256DIGESTBYTESIZE)!=0)
            throw((char*) "fileClient::protocolNego: server hash does not match");

        // Phase 4, send
        if(!m_oKeys.getPrincipalPrivateKeysFromFile())  
            throw((char*) "fileClient: Cant principal private keys from file");
#ifdef TEST
        fprintf(g_logFile, "fileClient: got principal keys\n");
#endif
        if(!m_oKeys.getPrincipalCertsFromFile())
            throw((char*) "fileClient: Cant get principal private keys from file");
        if(!m_oKeys.initializePrincipalPrivateKeys())
            throw((char*) "fileClient: Cant initialize principal private keys");
#ifdef TEST
        fprintf(g_logFile, "fileClient: got principal private keys\n");
#endif
        if(!m_oKeys.initializePrincipalCerts())
            throw((char*) "fileClient: Cant initialize principal certs\n");

        if(strcmp(m_oKeys.m_szChallengeSignAlg, (char*)"TLS_RSA2048_WITH_AES128_CBC_SHA256")!=0 &&
           strcmp(m_oKeys.m_szChallengeSignAlg, (char*)"TLS_RSA1024_WITH_AES128_CBC_SHA256")!=0)
            throw((char*) "fileClient: Unsupported challenge algorithm\n");
        
        szSignedChallenges= 
                rsaXmlEncodeChallenges(false, m_oKeys.m_iNumPrincipalPrivateKeys,
                                                 m_oKeys.m_rgPrincipalPrivateKeys,
                                                 m_oKeys.m_rguChallenge, SMALLNONCESIZE);
#ifdef TEST
        fprintf(g_logFile, "fileClient: challenges encoded\n");
#endif
        if(szSignedChallenges==NULL)
            throw((char*) "fileClient: Can't sign principal challenges");
        if(!clientNegoMessage4(request, MAXREQUESTSIZE, m_oKeys.m_szPrincipalCerts, 
                               m_oKeys.m_iNumPrincipalPrivateKeys, szSignedChallenges))
            throw((char*) "fileClient: Can't format negotiation message 3");
        if((n=fc.safesendPacket((byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw((char*) "fileClient: Can't send packet 3");

        // Phase 3, receive
        if((n=fc.safegetPacket((byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw((char*) "fileClient: Can't get packet 3");

        if(!getDatafromServerMessage3(n, request, m_oKeys))
            throw((char*) "fileClient: Can't decode client message 3");

        m_oKeys.validateChannelData(true);
#ifdef TEST
        fprintf(g_logFile, "fileClient: channel data validated\n");
#endif

        // register principals
        if(m_oKeys.m_pserverCert!=NULL) {
            if(registerPrincipalfromCert(m_oKeys.m_pserverCert)==NULL)
                throw((char *)"fileClient: Can't register server principal\n");
        }
#ifdef TEST
        fprintf(g_logFile, "fileClient: server principal registered\n");
#endif

        if(registerPrincipalfromCert(m_oKeys.m_pclientCert)==NULL)
            throw((char *)"fileClient: Can't register client principal\n");
#ifdef TEST
        fprintf(g_logFile, "fileClient: server principal registered\n");
#endif

        for(i=0;i<m_oKeys.m_iNumPrincipals; i++) {
            if(m_oKeys.m_rgPrincipalCerts[i]!=NULL) {
                if(registerPrincipalfromCert(m_oKeys.m_rgPrincipalCerts[i])==NULL)
                    throw((char *)"fileClient: Can't register client principal\n");
            }
        }
        m_clientState= REQUESTSTATE;
#ifdef TEST
        fprintf(g_logFile, "fileClient: protocol nego succesfully completed\n");
        fflush(g_logFile);
#endif
    }
    catch(char* szError) {
        fprintf(g_logFile, "fileClient: Protocol Nego error: %s\n", szError);
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


bool fileClient::closeClient()
{
    packetHdr oPH;

    m_clientState= SERVICETERMINATESTATE;

#ifdef TEST
    fprintf(g_logFile,"in closeClient()\n");
    fflush(g_logFile);
#endif

    if(m_fd>0) {
        oPH.len= 0;
#if 0
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


bool fileClient::initSafeChannel(safeChannel& fc)
{
    return fc.initChannel(m_fd, AES128, CBCMODE, HMACSHA256, 
                          AES128BYTEKEYSIZE, AES128BYTEKEYSIZE,
                          m_oKeys.m_rguEncryptionKey1, m_oKeys.m_rguIntegrityKey1, 
                          m_oKeys.m_rguEncryptionKey2, m_oKeys.m_rguIntegrityKey2);
}


// ------------------------------------------------------------------------


char*  g_szTerm=  (char*) "terminate channel\n";


#define FILECLIENTTEST
#ifdef  FILECLIENTTEST

int main(int an, char** av)
{
    fileClient      oFileClient;
    safeChannel     fc;
    int             iRet= 0;
    int             i;
    bool            fInit= false;
    bool            fInitProg= false;
    char*           szEvidence= NULL;
    char*           szSubject=(char*) "//www.manferdelli.com/User/JohnManferdelli/0001";
    char*           szResource=(char*) "//www.manferdelli.com/Gauss/fileServer/files/file.test";
    int             encType= NOENCRYPT;
    char*           directory= NULL;

    initLog(NULL);

#ifdef  TEST
    fprintf(g_logFile, "fileClient test\n");
    fflush(g_logFile);
#endif

    if(an>1) {
        for(i=0;i<an;i++) {
            if(strcmp(av[i],"-initProg")==0) {
                fInitProg= true;
             }
            if(strcmp(av[i],"-initKeys")==0) {
                fInit= true;
             }
            if(strcmp(av[i],"-port")==0 && an>(i+1)) {
                oFileClient.m_szPort= strdup(av[++i]);
             }
            if(strcmp(av[i],"-address")==0) {
                oFileClient.m_szAddress= strdup(av[++i]);
             }
            if (strcmp(av[i],"-directory")==0) {
                directory= strdup(av[++i]);
             }
        }
    }

#ifdef DONTENCRYPTFILES
    oFileClient.m_fEncryptFiles= false;
#else
    oFileClient.m_fEncryptFiles= true;
#endif

    if(fInitProg) {
#ifdef  TEST
        fprintf(g_logFile, "fileClient main starting measured %s\n", av[0]);
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

    initLog((char*)"fileClient.log");
#ifdef  TEST
    fprintf(g_logFile, "fileClient main in measured loop\n");
    fflush(g_logFile);
#endif

    try {

        g_policyPrincipalCert= new PrincipalCert();
        if(g_policyPrincipalCert==NULL)
            throw((char*)"fileClient main: failed to new Principal\n");

#ifdef  TEST
        fprintf(g_logFile, "fileClient main: inited g_policyPrincipalCert\n");
        fflush(g_logFile);
#endif
        // init logfile, crypto, etc
        if(!oFileClient.initClient(directory))
            throw((char *)"fileClient main: initClient() failed\n");

        // copy my public key into client public key
        if(!oFileClient.m_tcHome.m_myCertificateValid || 
               !oFileClient.m_oKeys.getClientCert((char*)oFileClient.m_tcHome.m_myCertificate))
            throw((char *)"fileClient main: Cant load client public key structures\n");

#ifdef  TEST
        fprintf(g_logFile, "fileClient main: protocol nego\n");
        fflush(g_logFile);
#endif
        // protocol Nego
        if(!oFileClient.protocolNego(oFileClient.m_fd, fc))
            throw((char *)"fileClient main: Cant negotiate channel\n");

#ifdef TEST
        oFileClient.m_oKeys.printMe();
        fflush(g_logFile);
#endif
    }
    catch(char* szError) {
        iRet= 1;
        fprintf(g_logFile, "Error: %s\n", szError);
        fflush(g_logFile);
        goto cleanup;
    }

    szEvidence= readandstoreString((char*) "fileClient/authRule1Signed.xml");
#ifdef  TEST
    fprintf(g_logFile, "fileClient main: Evidence for create: %s\n", szEvidence);
    fflush(g_logFile);
#endif

    if(clientcreateResourceonserver(fc, szResource, szSubject, szEvidence, encType, oFileClient.m_fileKeys)) {
        fprintf(g_logFile, "fileClient main: create resource successful\n");
        fflush(g_logFile);
    }
    else {
        fprintf(g_logFile, "fileClient main: create resource unsuccessful\n");
        fflush(g_logFile);
    }

    if(clientsendResourcetoserver(fc, szResource, NULL, (char*)"fileClient/files/file.test", 
                                  encType, oFileClient.m_fileKeys)) {
        fprintf(g_logFile, "fileClient main: Send file successful\n");
        fflush(g_logFile);
        }
    else {
        fprintf(g_logFile, "fileClient main: Send file unsuccessful\n");
        fflush(g_logFile);
    }

    if(clientgetResourcefromserver(fc, 
                                   (char*)"//www.manferdelli.com/Gauss/fileServer/files/file.test", 
                                   NULL, (char*)"fileClient/files/clientfile.test.out", 
                                   encType, oFileClient.m_fileKeys)) {
        fprintf(g_logFile, "fileClient main: Get file successful\n");
        fflush(g_logFile);
        }
    else {
        fprintf(g_logFile, "fileClient main: Get file unsuccessful\n");
        fflush(g_logFile);
    }

cleanup:
    // CHANNEL_TERMINATE 
    if(fc.fd>0)
        fc.safesendPacket((byte*) g_szTerm, strlen(g_szTerm)+1, CHANNEL_TERMINATE, 0, 1);
    
#ifdef  TEST
    fprintf(g_logFile, "fileClient main: At close client\n");
#endif
    // clean up global keys
    oFileClient.closeClient();
    closeLog();

    return iRet;
}
#endif


// ------------------------------------------------------------------------



