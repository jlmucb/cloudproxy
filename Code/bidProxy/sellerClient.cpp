//  File: sellerClient.cpp
//      John Manferdelli
//
//  Description: Seller Client.
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
#include "bidClient.h"
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
#include "claims.h"
#include "bidTester.h"

#include "objectManager.h"
#include "tao.h"

#include "trustedKeyNego.h"
#include "encryptedblockIO.h"
#include "secPrincipal.h"
#include "hashprep.h"
#include "sellerClient.h"
#include "encapsulate.h"

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

const char* g_szClientPrincipalCertsFile= "sellerClient/principalPublicKeys.xml";
const char* g_szClientPrincipalPrivateKeysFile= "sellerClient/principalPrivateKeys.xml";


accessPrincipal* registerPrincipalfromCert(PrincipalCert* pSig);


// ------------------------------------------------------------------------


bool    listBids(const char* szDir, int* pNum, char* bidName[])
{
    DIR*            dir= opendir(szDir);
    struct dirent*  ent;
    char*           fname;
    int             n= 0;

    if(dir==NULL) {
        fprintf(g_logFile, "No such directory\n");
        return false;
    }

    while((ent=readdir(dir))!=NULL && n<*pNum) {
        if(ent->d_type&DT_DIR)
            continue;
        fname= ent->d_name;
        if(strcmp(fname, ".")==0 || strcmp(fname,"..")==0)
            continue;
        if(strncmp(fname, "BidMeta", 7)!=0)
            continue;
        bidName[n++]= strdup(fname);
    }
    
    *pNum= n;
#ifdef TEST
    int i;
    fprintf(g_logFile, "listBids returning %d bids\n", n);
    for(i=0; i<n;i++)
        fprintf(g_logFile, "\t%s\n", bidName[i]);
#endif
    return true; 
}


bool filePresent(const char* resFile)
{
    struct stat statBlock;
    if(stat(resFile, &statBlock)<0) {
        return false;
    }
    return true;
}

// ------------------------------------------------------------------------


sellerClient::sellerClient ()
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

    m_szAuctionID= NULL;
    m_fWinningBidValid= false;
    m_WinningBidAmount= -1;
    m_szSignedWinner= NULL;
}


sellerClient::~sellerClient ()
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
    m_fKeysValid= false;
    if(m_szSealedKeyFile!=NULL)
        free(m_szSealedKeyFile);
    m_szSealedKeyFile= NULL;

    if(m_szAuctionID!=NULL) {
        free(m_szAuctionID);
        m_szAuctionID= NULL;
    }
    if(m_szSignedWinner!=NULL) {
        free(m_szSignedWinner);
        m_szSignedWinner= NULL;
    }
}


bool sellerClient::initPolicy()
{
#ifdef TEST
    fprintf(g_logFile, "sellerClient::initPolicy\n");
    fflush(g_logFile);
#endif
    if(!m_tcHome.m_envValid) {
        fprintf(g_logFile, "sellerClient::initPolicy(): environment invalid\n");
        return false;
    }

    if(!m_tcHome.m_policyKeyValid)  {
        fprintf(g_logFile, "sellerClient::initPolicy(): policyKey invalid\n");
        return false;
    }

#ifdef TEST1
    fprintf(g_logFile, "sellerClient::initPolicy, about to initpolicy Cert\n%s\n",
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

    g_globalpolicyValid= true;
    return true;
}


bool sellerClient::initClient(const char* configDirectory, const char* serverAddress, u_short serverPort,
                              bool fInitChannel)
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
            throw "sellerClient::Init: can't initcrypto\n";
        }
        m_oKeys.m_fClient= true;

        // init Host and Environment
        m_taoHostInitializationTimer.Start();
        if(!m_host.HostInit(PLATFORMTYPELINUX, parameterCount, parameters)) {
            throw "sellerClient::Init: can't init host\n";
        }
        m_taoHostInitializationTimer.Stop();
#ifdef TEST
        fprintf(g_logFile, "sellerClient::Init: after HostInit, pid: %d\n",
            getpid());
#endif

        // init environment
        m_taoEnvInitializationTimer.Start();
        if(!m_tcHome.EnvInit(PLATFORMTYPELINUXAPP, "sellerClient",
                                DOMAIN, directory, 
                                &m_host, 0, NULL)) {
            throw "sellerClient::Init: can't init environment\n";
        }
        m_taoEnvInitializationTimer.Stop();
#ifdef TEST
        fprintf(g_logFile, "sellerClient::Init: after EnvInit\n");
        m_tcHome.printData();
#endif

        // Initialize program private key and certificate for session
        if(!m_tcHome.m_privateKeyValid || 
               !m_oKeys.getMyProgramKey((RSAKey*)m_tcHome.m_privateKey))
            throw "sellerClient::Init: Cant get my private key\n";
        if(!m_tcHome.m_myCertificateValid || 
               !m_oKeys.getMyProgramCert(m_tcHome.m_myCertificate))
            throw "sellerClient::Init: Cant get my Cert\n";
    
        // Init global policy 
        if(!initPolicy())
            throw "sellerClient::Init: Cant init policy objects\n";

        if(fInitChannel) {
            // open sockets
            m_fd= socket(AF_INET, SOCK_STREAM, 0);
            if(m_fd<0) 
                throw  "Can't get socket\n";
            memset((void*) &server_addr, 0, sizeof(struct sockaddr_in));
    
#ifdef  TEST
            fprintf(g_logFile, "initClient: socket opened\n");
#endif

            server_addr.sin_family= AF_INET;

            // Fix: set up sellerClient and bidServer to pass arguments down to
            // their measured versions so we can control this by arguments
            if (!inet_aton(serverAddress, &server_addr.sin_addr)) {
                throw "Can't create the address for the bidServer";
            }
            server_addr.sin_port= htons(serverPort);
    
            iError= connect(m_fd, (const struct sockaddr*) &server_addr, (socklen_t) slen);
            if(iError!=0)
                throw  "sellerClient::Init: Can't connect";

#ifdef TEST
            fprintf(g_logFile, "initClient: connect completed\n");
            fflush(g_logFile);
#endif
        }
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
 *      2. If you use GCM, don't need seperate bid key
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


bool sellerClient::protocolNego(int fd, safeChannel& fc, const char* keyFile, const char* certFile)
{
    char    request[MAXREQUESTSIZEWITHPAD];
    char    rgszBase64[256];
    int     n;
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
    fprintf(g_logFile, "sellerClient: protocol negotiation\n");
    fflush(g_logFile);
#endif

    try {

        // init message hash
        if(!m_oKeys.initMessageHash())
            throw  "sellerClient::protocolNego: Can't init message hash";

        // Phase 1, send
        iOut64= 256;
        if(!getBase64Rand(SMALLNONCESIZE, m_oKeys.m_rguClientRand, &iOut64, rgszBase64))
            throw  "sellerClient::protocolNego: Can't generated first nonce";
        m_oKeys.m_fClientRandValid= true;

        if(!clientNegoMessage1(request, MAXREQUESTSIZE, szAlg, rgszBase64))
            throw  "sellerClient::protocolNego: Can't format negotiation message 1";
        if(!m_oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw  "sellerClient::protocolNego: Can't update message hash";
        if((n=sendPacket(fd, (byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw  "sellerClient::protocolNego: Can't send packet 1";
    
        // Phase 1, receive
        if((n=getPacket(fd, (byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw  "sellerClient::protocolNego: Can't get packet 1";
        if(!m_oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw  "sellerClient::protocolNego: Can't update message hash";
        if(!getDatafromServerMessage1(n, request, m_oKeys))
            throw  "sellerClient::protocolNego: Can't decode server message 1";

        // Phase 2, send
        if(!m_oKeys.generatePreMaster())
            throw  "sellerClient::protocolNego: Cant generate premaster";
        if(!m_oKeys.computeClientKeys())
            throw "sellerClient::protocolNego: Cant compute client keys";

        // Pre-master secret
        if(!m_oKeys.m_fPreMasterSecretValid)
            throw  "sellerClient: No Pre-master string";
        if(!m_oKeys.m_fServerCertValid)
            throw  "sellerClient: Server key invalid";

        szEncPreMasterSecret= rsaXmlEncodeChallenge(true, *m_oKeys.m_pserverPublicKey,
                                    m_oKeys.m_rguPreMasterSecret, BIGSYMKEYSIZE);
#ifdef TEST
        fprintf(g_logFile, "sellerClient: pre-master encoded %s\n", 
                szEncPreMasterSecret);
        fflush(g_logFile);
#endif
        if(szEncPreMasterSecret==NULL)
            throw "sellerClient: Cant encrypt premaster secret";
        m_oKeys.m_fEncPreMasterSecretValid= true;

        if(!clientNegoMessage2(request, MAXREQUESTSIZE, szEncPreMasterSecret,
                               m_oKeys.m_szXmlClientCert, m_oKeys.m_iSessionId))
            throw  "sellerClient: Can't format negotiation message 2";
        if(!m_oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw  "sellerClient::protocolNego: Can't update message hash";
        if((n=sendPacket(fd, (byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw  "sellerClient: Can't send packet 2";

        if(!m_oKeys.clientcomputeMessageHash()) 
            throw "sellerClient::protocolNego: client cant compute message hash";
        if(!m_oKeys.clientsignMessageHash()) 
            throw "sellerClient::protocolNego: client cant sign message hash";
        if(!clientNegoMessage3(request, MAXREQUESTSIZE, m_oKeys.m_szbase64SignedMessageHash))
            throw  "sellerClient: Can't format negotiation message 3";
        if(!m_oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw  "sellerClient::protocolNego: Can't update message hash";
        if((n=sendPacket(fd, (byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw  "sellerClient: Can't send packet 2";

        // encrypted from here on
        if(!initSafeChannel(fc))
            throw  "sellerClient: Can't init safe channel";
#ifdef TEST
        fprintf(g_logFile, "sellerClient: initsafeChannel succeeded\n");
#endif

        // Assume CBC
        if((n=getPacket(fd, fc.lastgetBlock, AES128BYTEBLOCKSIZE, &type, &multi, &final))<0)
            throw "sellerClient: Cant get IV\n";
        fc.fgetIVReceived= true;
        if((n=sendPacket(fd, fc.lastsendBlock, AES128BYTEBLOCKSIZE, CHANNEL_NEGO_IV, 0, 1))<0)
            throw "sellerClient: Cant send IV\n";
        fc.fsendIVSent= true;
#ifdef  TEST
        fprintf(g_logFile, "sellerClient::protocolNego: Encrypted mode on\n");
        PrintBytes((char*)"Received IV: ", fc.lastgetBlock, AES128BYTEBLOCKSIZE);
        PrintBytes((char*)"Sent     IV: ", fc.lastsendBlock, AES128BYTEBLOCKSIZE);
        fflush(g_logFile);
#endif

        // Phase 2, receive
        if((n=fc.safegetPacket((byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw  "sellerClient: Can't get server packet 2";
        if(!m_oKeys.servercomputeMessageHash())
            throw  "sellerClient::protocolNego: Can't compute server hash";
        if(!getDatafromServerMessage2(n, request, m_oKeys))
            throw  "sellerClient::protocolNego: Can't decode server message 2";

        // do hashes match?
#ifdef TEST
        fprintf(g_logFile, "sellerClient::protocolNego: server hases\n");
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
            throw  "sellerClient::protocolNego: server hash does not match";

        // Phase 4, send
        if(!m_oKeys.getPrincipalPrivateKeysFromFile(keyFile))  
            throw  "sellerClient: Cant principal private keys from file";
#ifdef TEST
        fprintf(g_logFile, "sellerClient: got principal keys\n");
#endif
        if(!m_oKeys.getPrincipalCertsFromFile(certFile))
            throw  "sellerClient: Cant get principal private keys from file";
        if(!m_oKeys.initializePrincipalPrivateKeys())
            throw  "sellerClient: Cant initialize principal private keys";
#ifdef TEST
        fprintf(g_logFile, "sellerClient: got principal private keys\n");
#endif
        if(!m_oKeys.initializePrincipalCerts())
            throw  "sellerClient: Cant initialize principal certs\n";

        if(strcmp(m_oKeys.m_szChallengeSignAlg, "TLS_RSA2048_WITH_AES128_CBC_SHA256")!=0 &&
           strcmp(m_oKeys.m_szChallengeSignAlg, "TLS_RSA1024_WITH_AES128_CBC_SHA256")!=0)
            throw  "sellerClient: Unsupported challenge algorithm\n";
        
        szSignedChallenges= 
                rsaXmlEncodeChallenges(false, m_oKeys.m_iNumPrincipalPrivateKeys,
                                                 m_oKeys.m_rgPrincipalPrivateKeys,
                                                 m_oKeys.m_rguChallenge, SMALLNONCESIZE);
#ifdef TEST
        fprintf(g_logFile, "sellerClient: challenges encoded\n");
#endif
        if(szSignedChallenges==NULL)
            throw  "sellerClient: Can't sign principal challenges";
        if(!clientNegoMessage4(request, MAXREQUESTSIZE, m_oKeys.m_szPrincipalCerts, 
                               m_oKeys.m_iNumPrincipalPrivateKeys, szSignedChallenges))
            throw  "sellerClient: Can't format negotiation message 3";
        if((n=fc.safesendPacket((byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw  "sellerClient: Can't send packet 3";

        // Phase 3, receive
        if((n=fc.safegetPacket((byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw  "sellerClient: Can't get packet 3";

        if(!getDatafromServerMessage3(n, request, m_oKeys))
            throw  "sellerClient: Can't decode client message 3";

        m_oKeys.validateChannelData(true);
#ifdef TEST
        fprintf(g_logFile, "sellerClient: channel data validated\n");
#endif
        m_clientState= REQUESTSTATE;
#ifdef TEST
        fprintf(g_logFile, "sellerClient: protocol nego succesfully completed\n");
        fflush(g_logFile);
#endif
    }
    catch(const char* szError) {
        fprintf(g_logFile, "sellerClient: Protocol Nego error: %s\n", szError);
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


bool sellerClient::closeClient()
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


bool sellerClient::initSafeChannel(safeChannel& fc)
{
    return fc.initChannel(m_fd, AES128, CBCMODE, HMACSHA256, 
                          AES128BYTEKEYSIZE, AES128BYTEKEYSIZE,
                          m_oKeys.m_rguEncryptionKey1, m_oKeys.m_rguIntegrityKey1, 
                          m_oKeys.m_rguEncryptionKey2, m_oKeys.m_rguIntegrityKey2);
}


// ------------------------------------------------------------------------


const char*  g_szTerm= "terminate channel\n";


bool sellerClient::establishConnection(safeChannel& fc, 
                                    const char* keyFile, 
                                    const char* certFile, 
                                    const char* directory,
                                    const char* serverAddress,
                                    u_short serverPort) {
    try {
        if (g_policyPrincipalCert==NULL) {
            g_policyPrincipalCert= new PrincipalCert();
            if(g_policyPrincipalCert==NULL)
                throw "sellerClient main: failed to new Principal\n";
        }

#ifdef  TEST
        fprintf(g_logFile, "sellerClient main: inited g_policyPrincipalCert\n");
        fflush(g_logFile);
#endif
        // init logfile, crypto, etc
        if(!initClient(directory, serverAddress, serverPort, true))
            throw "sellerClient main: initClient() failed\n";

        // copy my public key into client public key
        if(!m_tcHome.m_myCertificateValid || 
               !m_oKeys.getClientCert(m_tcHome.m_myCertificate))
            throw "sellerClient main: Cant load client public key structures\n";

#ifdef  TEST
        fprintf(g_logFile, "sellerClient main: protocol nego\n");
        fflush(g_logFile);
#endif
        // protocol Nego
        m_protocolNegoTimer.Start();
        if(!protocolNego(m_fd, fc, keyFile, certFile))
            throw "sellerClient main: Cant negotiate channel\n";
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


bool sellerClient::loadKeys(const char* keyFile, const char* certFile, 
                            const char* directory) 
{
    u_short serverPort= 0;
    const char* serverAddress= NULL;

    try {
        if (g_policyPrincipalCert==NULL) {
            g_policyPrincipalCert= new PrincipalCert();
            if(g_policyPrincipalCert==NULL)
                throw "sellerClient main: failed to new Principal\n";
        }

#ifdef  TEST
        fprintf(g_logFile, "sellerClient main: inited g_policyPrincipalCert\n");
        fflush(g_logFile);
#endif
        // init logfile, crypto, etc
        if(!initClient(directory, serverAddress, serverPort, false))
            throw "sellerClient main: initClient() failed\n";

        // copy my public key into client public key
        if(!m_tcHome.m_myCertificateValid || 
               !m_oKeys.getClientCert(m_tcHome.m_myCertificate))
            throw "sellerClient main: Cant load client public key structures\n";
    }
    catch(const char* szError) {
        fprintf(g_logFile, "Error: %s\n", szError);
        fflush(g_logFile);
        return false;
    }

  return true;
}


void sellerClient::closeConnection(safeChannel& fc) {
        if(fc.fd>0) {
                fc.safesendPacket((byte*) g_szTerm, strlen(g_szTerm)+1, CHANNEL_TERMINATE, 0, 1);
        }
}


// ------------------------------------------------------------------------

//
//  Application specific logic
// 

bool sellerClient::readBidResolution(safeChannel& fc, const string& subject, 
                                const string& identityCert, 
                                const string& proposedKey, 
                                const string& localOutput) 
{
#if 0
    int             encType= NOENCRYPT;

    if(clientgetCredentialfromserver(fc, subject.c_str(), "PKToken",
                                      identityCert.c_str(), NULL,
                                      proposedKey.c_str(), localOutput.c_str(),
                encType, m_bidKeys, m_encTimer)) {
        fprintf(g_logFile, "sellerClient bidTest: read file successful\n");
        fflush(g_logFile);
    } 
    else {
        fprintf(g_logFile, "sellerClient fileTest: read file unsuccessful\n");
        fflush(g_logFile);
        return false;
    }
#endif

    return true;
}


bool sellerClient::compareFiles(const string& firstFile, const string& secondFile) {
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


int timeCompare(struct tm& time1, struct tm& time2)
{
    if(time1.tm_year>time2.tm_year)
        return 1;
    if(time1.tm_year<time2.tm_year)
        return -1;
    if(time1.tm_mon>time2.tm_mon)
        return 1;
    if(time1.tm_mon<time2.tm_mon)
        return -1;
    if(time1.tm_mday>time2.tm_mday)
        return 1;
    if(time1.tm_mday<time2.tm_mday)
        return -1;
    if(time1.tm_hour>time2.tm_hour)
        return 1;
    if(time1.tm_hour<time2.tm_hour)
        return -1;
    if(time1.tm_min>time2.tm_min)
        return 1;
    if(time1.tm_min<time2.tm_min)
        return -1;
    if(time1.tm_sec>time2.tm_sec)
        return 1;
    if(time1.tm_sec<time2.tm_sec)
        return -1;

    return 0;
}


/*
 *  <Bid>
 *      <AuctionID> </AuctionID>
 *      <BidAmount> </BidAmount>
 *      <SubjectName> </SubjectName>
 *      <DateTime> </DateTime>
 *      <BidderCert> </BidderCert>
 *  <Bid>
 */


class bidInfo {
public:
    TiXmlDocument   doc;
    char*           auctionID;
    int             bidAmount;
    char*           userName;
    char*           szTime;
    struct tm       timeinfo;

    bidInfo();
    ~bidInfo();

    bool    parse(const char* szBid);
    bool    getBidInfo(RSAKey* sealingKey, const char* szBid);
    char*   getUserCert();
#ifdef TEST
    void    printMe();
#endif
};


bidInfo::bidInfo() 
{
    auctionID= NULL;
    bidAmount= -1;
    userName= NULL;
    szTime= NULL;
}


bidInfo::~bidInfo()
{
    if(auctionID!=NULL) {
        free(auctionID);
        auctionID= NULL;
    }
    if(userName!=NULL) {
        free(userName);
        userName= NULL;
    }
    if(szTime!=NULL) {
        free(szTime);
        szTime= NULL;
    }
}


#ifdef TEST
void bidInfo::printMe() 
{
    if(auctionID==NULL) 
        fprintf(g_logFile, "auctionID is NULL\n");
    else
        fprintf(g_logFile, "auctionID is %s\n", auctionID);
    fprintf(g_logFile, "bidAmount is %d\n", bidAmount);
    if(userName==NULL) 
        fprintf(g_logFile, "userName is NULL\n");
    else
        fprintf(g_logFile, "userName is %s\n", userName);
    if(szTime==NULL) 
        fprintf(g_logFile, "szTime is NULL\n");
    else
        fprintf(g_logFile, "szTime is %s\n", szTime);
}
#endif


bool  bidInfo::parse(const char* szBid) 
{
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;
    TiXmlElement*   pRootElement= NULL;
    const char*     szAuctionID= NULL;
    const char*     szBidAmount= NULL;
    const char*     szSubjectName= NULL;
    const char*     szBidTime= NULL;

#ifdef  TEST
    fprintf(g_logFile, "bidInfo::parse\n%s\n", szBid);
    fflush(g_logFile);
#endif

    try {
        if(!doc.Parse(szBid))
            throw "bidInfo::parse: parse failure\n";
        pRootElement= doc.RootElement();
        if(pRootElement==NULL)
            throw "bidInfo::parse: No root element\n";
        pNode= Search((TiXmlNode*) pRootElement, "AuctionID");
        if(pNode==NULL)
            throw "bidInfo::parse: No AuctionID element\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw "bidInfo::parse: Bad AuctionID element\n";
        if(pNode1->Value()!=NULL) {
            szAuctionID= pNode1->Value();
        }

        pNode= Search((TiXmlNode*) pRootElement, "BidAmount");
        if(pNode==NULL)
            throw "bidInfo::parse: No BidAmount element\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw "bidInfo::parse: Bad BidAmount element\n";
        if(pNode1->Value()!=NULL) {
            szBidAmount= pNode1->Value();
        }
        pNode= Search((TiXmlNode*) pRootElement, "SubjectName");
        if(pNode!=NULL) {
            pNode1= pNode->FirstChild();
            if(pNode1!=NULL && pNode1->Value()!=NULL) {
                szSubjectName= pNode1->Value();
            }
        }

        pNode= Search((TiXmlNode*) pRootElement, "DateTime");
        if(pNode==NULL)
            throw "bidInfo::parse: No DateTime element\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw "bidInfo::parse: Bad DateTime element\n";
        if(pNode1->Value()!=NULL) {
            szBidTime= pNode1->Value();
        }
    }
    catch(const char* szError) {
        fprintf(g_logFile, "bidInfo::parse error: %s\n");
        return false;
    }
        
    if(szAuctionID==NULL) {
        fprintf(g_logFile, "bidInfo::parse: no auctionID\n");
        return false;
    }
    else
        auctionID= strdup(szAuctionID);

    if(szBidAmount!=NULL);
        bidAmount= atoi(szBidAmount);
    
    if(szSubjectName==NULL) {
        szSubjectName= "Anonymous";
    }
    userName= strdup(szSubjectName);
    if(szBidTime==NULL) {
        fprintf(g_logFile, "bidInfo::parse: no szBidTime\n");
        return false;
    }
    else
        szTime= strdup(szBidTime);

fprintf(g_logFile, "bidInfo::parse: about to scan\n");
fflush(g_logFile);
    sscanf(szTime, "%04d-%02d-%02dZ%02d:%02d.%02d",
        &timeinfo.tm_year, &timeinfo.tm_mon,
        &timeinfo.tm_mday, &timeinfo.tm_hour,
        &timeinfo.tm_min, &timeinfo.tm_sec);

#ifdef  TEST
    fprintf(g_logFile, "bidInfo::parse succeeds\n");
    printMe();
    fflush(g_logFile);
#endif
    return true;
}


char* bidInfo::getUserCert()
{
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;
    TiXmlElement*   pRootElement= NULL;
    char*           szCert= NULL;

#ifdef  TEST
    fprintf(g_logFile, "bidInfo::getUserCert\n");
    fflush(g_logFile);
#endif
    try {
        pRootElement= doc.RootElement();
        if(pRootElement==NULL)
            throw "bidInfo::getUserCert: No root element\n";

        pNode= Search((TiXmlNode*) pRootElement, "BidderCert");
        if(pNode==NULL)
            throw "bidInfo::getUserCert: No BidderCert element\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw "bidInfo::getUserCert: Bad BidderCert element\n";
        if(pNode1->Value()!=NULL)
            szCert= canonicalize(pNode1);

    }
    catch(const char* szError) {
        fprintf(g_logFile, "%s", szError);
    }

    return szCert;
}


bool  bidInfo::getBidInfo(RSAKey* sealingKey, const char* szBid)
{
    int                 size= 8192;
    byte                buf[8192];
    encapsulatedMessage oM;
    const char*         szMetaDataName= szBid;
    char                szName[256];
    char*               szBlob= NULL;
    char*               szMeta= NULL;
    char*               szMetaData= NULL;
    bool                fRet= true;

    // construct Blob Name
    sprintf(szName, "bidServer/bids/SealedBid%s", szMetaDataName+7);
    szBlob= strdup(szName);
    sprintf(szName, "bidServer/bids/%s", szMetaDataName);
    szMeta= strdup(szName);

    // get metaData
    size= 8192;
    if(!getBlobfromFile(szMeta, buf, &size)) {
        fprintf(g_logFile, "bidInfo::getBidInfo: cant get metadata file %d\n",
                szMetaDataName);
        return false;
    }
    szMetaData= strdup((char*)buf);

    // get Blob
    size= 8192;
    if(!getBlobfromFile(szBlob, buf, &size)) {
        fprintf(g_logFile, "bidInfo::getBidInfo: cant get sealed keys\n");
        fRet= false;
        goto done;
    }

    // parse metadata
    oM.m_szXMLmetadata= szMetaData;
    if(!oM.parseMetaData()) {
        fprintf(g_logFile, "bidInfo::getBidInfo: cant parse metadata\n");
        fRet= false;
        goto done;
    }

    // unseal key
    if(!oM.unSealKey(sealingKey)) {
        fprintf(g_logFile, "bidInfo::getBidInfo: cant unseal key\n");
        fRet= false;
        goto done;
    }

    // decrypt bid
    if(!oM.setencryptedMessage(size, buf)) {
        fprintf(g_logFile, "bidInfo::getBidInfo: cant set encrypted\n");
        fRet= false;
        goto done;
    }

    if(!oM.decryptMessage()) {
        fprintf(g_logFile, "bidInfo::getBidInfo: cant decrypt message\n");
        fRet= false;
        goto done;
    }

    // sanity check bid
    char  szBidBuf[8192];
    size= oM.plainMessageSize();
    if(size<2) {
        fprintf(g_logFile, "bidInfo::getBidInfo: Bid xml too small\n");
        fRet= false;
        goto done;
    }
    if(size>8180) {
        fprintf(g_logFile, "bidInfo::getBidInfo: Bid xml too large\n");
        fRet= false;
        goto done;
    }
    memcpy((byte*)szBidBuf, oM.m_rgPlain, size);
    if(szBidBuf[size-1]!='\0') {
        szBidBuf[size]= '\0';
        size++;
    }
    if(szBidBuf[size-2]!='\n') {
        szBidBuf[size-1]= '\n';
        szBidBuf[size]= '\0';
        size++;
    }

    // parse bid
    if(!parse(szBidBuf)) {
        fprintf(g_logFile, "bidInfo::getBidInfo: can't parse bid\n");
        fRet= false;
        goto done;
    }
#ifdef TEST
    fprintf(g_logFile, "bidInfo::getBidInfo: succeeded\n");
    fflush(g_logFile);
#endif

done:
    oM.m_szXMLmetadata= NULL;
    if(szMetaData!=NULL) {
        free(szMetaData);
        szMetaData= NULL;
    }
    return fRet;
}

/*
 *  <SignedInfo>
 *      <AuctionID> auction </AuctionID>
 *      <TimeofDetermination> </TimeofDetermination>
 *      <Price> </Price>
 *      <WinnerCert> </WinnerCert>
 *  </SignedInfo>
 */
static char* g_signedBidTemplate= (char*)
"<SignedInfo>\n  <AuctionID> %s </AuctionID>\n  <TimeofDetermination> %s </TimeofDetermination>\n"\
"    <Price> %d </Price>\n  <WinnerCert>\n %s\n </WinnerCert>\n </SignedInfo>\n";

/*
 *  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id='uniqueid'>
 *    <ds:SignedInfo>
 *      <ds:CanonicalizationMethod Algorithm="http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#" />
 *      <ds:SignatureMethod Algorithm="http://www.manferdelli.com/2011/Xml/algorithms/rsa1024-sha256-pkcspad#" />
 *      <SignedInfo>
 *      ...
 *      </SignedInfo>
 *      <ds:SignatureValue> ...  </ds:SignatureValue>
 *      <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#" KeyName='sellerClientKey'>
 *      </ds:KeyValue>
 *   </ds:KeyInfo>
 *  </ds:Signature>
 */
static char* g_signatureTemplate= (char*)
"<ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id='%sWinner'>\n"\
"  %s\n  <ds:SignatureValue>\n %s </ds:SignatureValue>\n  %s\n</ds:Signature>\n";


char* sellerClient::signWinner(RSAKey* signingKey, const char* auctionID, 
                               int winningBidAmount, const char* szWinnerCert)
{
    char            szTimeNow[256];
    time_t          now;
    struct tm *     timeinfo;
    int             size= 8192;
    char            szSignedBuf[8192];
    char*           szSignedInfo= NULL;
    Sha256          oHash;
    byte            rgHash[64];
    bnum            bnMsg(128);
    bnum            bnOut(128);
    byte            rgPadded[512];
    char*           szSignature= NULL;
    char            szbase64[512];
    char*           szMyKeyInfo= NULL;
    bool            fRet= true;
    TiXmlDocument   doc1;
    TiXmlDocument   doc2;

#ifdef  TEST
    fprintf(g_logFile, "sellerClient::signWinner\n");
    fflush(g_logFile);
#endif
    time(&now);
    timeinfo= gmtime(&now);
    if(timeinfo==NULL) {
        fprintf(g_logFile, "sellerClient::signWinner: can't get current time\n");
        fflush(g_logFile);
        szTimeNow[0]= 0;
    }
    else {
        // 2011-01-01Z00:00.00
        sprintf(szTimeNow,"%04d-%02d-%02dZ%02d:%02d.%02d", 
                1900+timeinfo->tm_year, timeinfo->tm_mon+1,
                timeinfo->tm_mday, timeinfo->tm_hour, 
                timeinfo->tm_min, timeinfo->tm_sec);
    }

    // encode signed body
    sprintf(szSignedBuf, g_signedBidTemplate, auctionID, szTimeNow,
                               winningBidAmount, szWinnerCert);
    if(!doc1.Parse(szSignedBuf)) {
        fprintf(g_logFile, "sellerClient::signWinner: cant parse szSignedBuf\n%s\n", szSignedBuf);
        return false;
    }
    szSignedInfo= canonicalize((TiXmlNode*)doc1.RootElement());
    if(szSignedInfo==NULL) {
        fprintf(g_logFile, "sellerClient::signWinner: cant generate SignedInfo\n");
        return false;
    }

#ifdef  TEST
    fprintf(g_logFile, "hashing\n");
    fflush(g_logFile);
#endif
    // hash, pad, sign
    oHash.Init();
    oHash.Update((byte*) szSignedInfo, strlen(szSignedInfo));
    oHash.Final();
    oHash.GetDigest(rgHash);

#ifdef  TEST
    fprintf(g_logFile, "padding\n");
    fflush(g_logFile);
#endif
    if(!emsapkcspad(SHA256HASH, rgHash, signingKey->m_iByteSizeM, rgPadded)) {
        fprintf(g_logFile, "sellerClient::signWinner: bad pad\n");
        fRet= false;
        goto cleanup;
    }

#ifdef  TEST
    fprintf(g_logFile, "signing\n");
    fflush(g_logFile);
#endif
    mpZeroNum(bnMsg);
    mpZeroNum(bnOut);

    revmemcpy((byte*)bnMsg.m_pValue, rgPadded, signingKey->m_iByteSizeM);

    if(!mpRSAENC(bnMsg, *(signingKey->m_pbnD), *(signingKey->m_pbnM), bnOut)) {
        fprintf(g_logFile, "sellerClient::signWinner: decrypt failed\n");
        fRet= false;
        goto cleanup;
    }

#ifdef  TEST
    fprintf(g_logFile, "base64 encode\n");
    fflush(g_logFile);
#endif

    size= 512;
    if(!toBase64(signingKey->m_iByteSizeM, (byte*)bnOut.m_pValue, &size, szbase64)) {
        fprintf(g_logFile, "sellerClient::signWinner: cant transform sigto base64\n");
        fRet= false;
        goto cleanup;
    }

#ifdef  TEST
    fprintf(g_logFile, "encode signature\n");
    fflush(g_logFile);
#endif
    // encode Signature
    szMyKeyInfo= signingKey->SerializePublictoString();
    sprintf(szSignedBuf, g_signatureTemplate, auctionID, szSignedInfo, szbase64, szMyKeyInfo);
    if(!doc2.Parse(szSignedBuf)) {
        fprintf(g_logFile, "sellerClient::signWinner: parse szSignedBuf\n");
        return false;
    }
    szSignature= canonicalize((TiXmlNode*)doc2.RootElement());
#ifdef  TEST
    fprintf(g_logFile, "got final sig\n");
    fflush(g_logFile);
#endif

cleanup:
    if(szSignedInfo!=NULL) {
        free(szSignedInfo);
        szSignedInfo= NULL;
    }
    if(szMyKeyInfo!=NULL) {
        free(szMyKeyInfo);
        szMyKeyInfo= NULL;
    }
    if(szSignedInfo!=NULL) {
        free(szSignedInfo);
        szSignedInfo= NULL;
    }

    if(fRet)
        return szSignature;
    return NULL;
}


bool sellerClient::resolveAuction(int numbids, char* bidFiles[])
{
    int                 i;
    RSAKey*             sealingKey= NULL;
    int                 winningBidAmount= 0;
    char*               szCurrentBid= NULL;
    char*               szWinnerCert= NULL;
    char*               szWinningBid;
    bidInfo*            pWinningBid= NULL;
    bidInfo*            pCurrentBid= NULL;

//#define OFFLINETEST
#ifdef OFFLINETEST
    char*               szKey= NULL;
    szKey= readandstoreString("bidServer/privateKey.xml");
    if(szKey==NULL) {
        fprintf(g_logFile, 
                "sellerClient::resolveAuction: cant read unsealing key\n");
        return false;
    }
    sealingKey= keyfromkeyInfo(szKey);
#ifdef TEST
    fprintf(g_logFile, "sellerClient::resolveAuction: back from keyfromkey\n%s\n",
            szKey);
    fflush(g_logFile);
#endif
#else
    if(!m_tcHome.m_privateKeyValid) {
        fprintf(g_logFile, 
                "sellerClient::resolveAuction: seller private key invalid\n");
        return false;
    }
    sealingKey= (RSAKey*)m_tcHome.m_privateKey;
#endif

    if(sealingKey==NULL) {
        fprintf(g_logFile, 
                "sellerClient::resolveAuction: sealing key invalid\n");
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "SealingKey\n");
    sealingKey->printMe();
#endif

    // init
    szWinningBid= bidFiles[0];
    pWinningBid= new bidInfo();
    if(!pWinningBid->getBidInfo(sealingKey, szWinningBid)) {
        fprintf(g_logFile, 
            "sellerClient::resolveAuction:  cant read initial bid\n");
        return false;
    }
    winningBidAmount= pWinningBid->bidAmount;

    for(i=1;i<numbids; i++) {
        szCurrentBid= bidFiles[i];
        pCurrentBid= new bidInfo();
        if(!pCurrentBid->getBidInfo(sealingKey, szCurrentBid)) {
            fprintf(g_logFile, 
                "sellerClient::resolveAuction:  cant read bid info %d\n", i);
            return false;
        }
#ifdef TEST
        fprintf(g_logFile, "SealingKey\n");
        sealingKey->printMe();
#endif
        if(strcmp(m_szAuctionID, pCurrentBid->auctionID)!=0) {
            fprintf(g_logFile, "sellerClient::resolveAuction: wrong auction, %s\n", 
                    m_szAuctionID);
            continue;
        }
        if(strcmp(m_szAuctionID, pWinningBid->auctionID)!=0) {
            delete pWinningBid;
            winningBidAmount= pCurrentBid->bidAmount;
            pWinningBid= pCurrentBid;
            pCurrentBid= NULL;
            continue;
        }
        if(winningBidAmount<pCurrentBid->bidAmount) {
            winningBidAmount= pCurrentBid->bidAmount;
            szWinningBid=  szCurrentBid;
            delete pWinningBid;
            pWinningBid= pCurrentBid;
            pCurrentBid= NULL;
        }
        else if(winningBidAmount==pCurrentBid->bidAmount) {
            if(timeCompare(pCurrentBid->timeinfo, pWinningBid->timeinfo)<0) {
                winningBidAmount= pCurrentBid->bidAmount;
                szWinningBid=  szCurrentBid;
                delete pWinningBid;
                pWinningBid= pCurrentBid;
                pCurrentBid= NULL;
            }
            else {
                delete pCurrentBid;
                pCurrentBid= NULL;
            }
        }
        else {
            delete pCurrentBid;
            pCurrentBid= NULL;
        }
    }

    // sign winning bid
    if(strcmp(m_szAuctionID, pWinningBid->auctionID)!=0) {
        fprintf(g_logFile, "sellerClient::resolveAuction: wrong auction, %s\n", 
                pWinningBid->auctionID);
        return false;
    }
    szWinnerCert= pWinningBid->getUserCert();
    m_szSignedWinner= signWinner(sealingKey, m_szAuctionID, winningBidAmount, szWinnerCert);
    if(m_szSignedWinner==NULL) {
        fprintf(g_logFile, "sellerClient::resolveAuction: cant sign winning bid\n");
        if(szWinnerCert!=NULL) {
            free(szWinnerCert);
            szWinnerCert= NULL;
        }
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "Winning Bid\n%s\n", m_szSignedWinner);
#endif

    // record result
    m_fWinningBidValid= true;
    m_WinningBidAmount= winningBidAmount;

    return true;
}


// ------------------------------------------------------------------------


int main(int an, char** av)
{
    sellerClient    oSellerClient;
    safeChannel     fc;
    int             iRet= 0;
    int             i;
    bool            fInitProg= false;
    const char*     directory= NULL;
    string          testPath("sellerClient/tests/");
    string          testFileName("tests.xml");
    bool            result;
    string          userKeyFile("bidClient/tests/basicBidTest/UserPublicKey.xml");
    string          userCertFile("bidClient/tests/basicBidTest/UserCert.xml");


    initLog(NULL);

#ifdef  TEST
    fprintf(g_logFile, "sellerClient test\n");
    fflush(g_logFile);
#endif

    UNUSEDVAR(result);
    if(an>1) {
        for(i=0;i<an;i++) {
            if(strcmp(av[i],"-initProg")==0) {
                fInitProg= true;
            }
            if(strcmp(av[i],"-port")==0 && an>(i+1)) {
                oSellerClient.m_szPort= strdup(av[++i]);
            }
            if(strcmp(av[i],"-address")==0) {
                oSellerClient.m_szAddress= strdup(av[++i]);
            }
            if (strcmp(av[i],"-directory")==0) {
                directory= strdup(av[++i]);
            }
        }
    }
    UNUSEDVAR(directory);

    if(fInitProg) {
#ifdef  TEST
        fprintf(g_logFile, "sellerClient main starting measured %s\n", av[0]);
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

    initLog("sellerClient.log");
#ifdef  TEST
    fprintf(g_logFile, "sellerClient main in measured loop\n");
    fflush(g_logFile);
#endif
    try {
        if(!filePresent("sellerClient/privatekey")) {
#ifdef  TEST
            fprintf(g_logFile, "sellerClient no private file, initializing\n");
            fflush(g_logFile);
#endif
            safeChannel channel;
            result = oSellerClient.establishConnection(channel,
                        userKeyFile.c_str(),
                        userCertFile.c_str(),
                        directory,
                        "127.0.0.1",
                        SERVICE_PORT);
            if(result)
                fprintf(g_logFile, "sellerClient initialization complete\n");
            else
                fprintf(g_logFile, "sellerClient initialization failed\n");
            closeLog();
            return 0;
        }
        if(!filePresent("sellerClient/resolve")) {
            fprintf(g_logFile, "sellerClient not time to resolve auction\n");
            closeLog();
            return 0;
        }

        // get auction id
        oSellerClient.m_szAuctionID= readandstoreString("./sellerClient/resolve");
        if(oSellerClient.m_szAuctionID==NULL) {
            fprintf(g_logFile, 
                "sellerClient::resolveAuction:  cant read auctionID\n");
            return false;
        }
        char* p= oSellerClient.m_szAuctionID;
        while(*p!='\0') {
            if(*p==' '|| *p=='\n') {
                *p= 0;
                break;
            }
            p++;
        }

        fprintf(g_logFile, "sellerClient, resolving  auction %s\n", oSellerClient.m_szAuctionID);

        // load keys
        if(!oSellerClient.loadKeys(userKeyFile.c_str(), userCertFile.c_str(),
                                    directory))  {
            fprintf(g_logFile, "sellerClient cant load keys\n");
            closeLog();
            return 0;
        }
#ifdef  TEST
        fprintf(g_logFile, "LoadKeys done\n");
        fflush(g_logFile);
#endif

        // get bids
        int     nBids= 500;
        char*   rgBids[500];

        if(!listBids("sellerClient/bids", &nBids, rgBids)) {
            fprintf(g_logFile, "sellerClient: can't retrieve bids\n");
            closeLog();
            return 0;
        }
#ifdef  TEST
        fprintf(g_logFile, "Got %d bids\n", nBids);
        fflush(g_logFile);
#endif
        if(oSellerClient.resolveAuction(nBids, rgBids))
            fprintf(g_logFile, "sellerClient: auction successfully concluded\n");
        else
            fprintf(g_logFile, "sellerClient: auction resolution unsuccessful\n");

        for(i=0;i<nBids;i++)
            free(rgBids[i]);

        closeLog();
        return 0;
    } 
    catch (const char* err) {
        fprintf(g_logFile, "execution failed with error %s\n", err);
        iRet= 1;
    }

    return iRet;
}


void sellerClient::printTimers(FILE* log) {
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

void sellerClient::resetTimers() {
    m_sealTimer.Clear();
    m_unsealTimer.Clear();
    m_taoEnvInitializationTimer.Clear();
    m_taoHostInitializationTimer.Clear();
    m_protocolNegoTimer.Clear();
    m_encTimer.Clear();
    m_decTimer.Clear();
}

void sellerClient::getKeyFiles(const string& directory,
                             const string& testFile,
                             string& identityCertFile,
                             string& userCertFile,
                             string& userKeyFile,
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
        } else if (name.compare("UserKey") == 0) {
            userKeyFile = directory + text;
        } else if (name.compare("Key") == 0) {
            keyFile = directory + text;
        } else {
            throw "Unknown child node of Test\n";
        }
    }

    return;
}

string sellerClient::getFileContents(const string& filename) {
    // read the file and output the text
    ifstream file(filename.c_str());
    string fileContents((istreambuf_iterator<char>(file)),
                        (istreambuf_iterator<char>()));
    return fileContents;
}

// ------------------------------------------------------------------------



