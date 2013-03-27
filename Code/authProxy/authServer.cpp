//
//  File: authServer.cpp
//      John Manferdelli
//
//  Description: Sever for authServer
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
#include "authServer.h"
#include "jlmcrypto.h"
#include "channel.h"
#include "safeChannel.h"
#include "channelstate.h"
#include "jlmUtility.h"
#include "tinyxml.h"
#include "session.h"
#include "sha256.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "rsaHelper.h"
#include "request.h"
#include "tcIO.h"

#include "tao.h"

#include "objectManager.h"
#include "secPrincipal.h"
#include "claims.h"
#include "trustedKeyNego.h"
#include "encryptedblockIO.h"
#include "domain.h"

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
#include <pthread.h>
#include <errno.h>
#ifdef LINUX
#include <wait.h>
#endif


bool             g_fTerminateServer= false;
int              iQueueSize= 5;

bool             g_globalpolicyValid= false;
// metaData         g_theVault;
PrincipalCert*   g_policyPrincipalCert= NULL;
RSAKey*          g_policyKey= NULL;
accessPrincipal* g_policyAccessPrincipal= NULL;

#include "./policyCert.inc"

accessPrincipal* registerPrincipalfromCert(PrincipalCert* pSig);


// ------------------------------------------------------------------------

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
 *  ----------Encrypted from here on
 *  client phase 3  client-->server:
 *      clientMsg3(Principal-certs, D_P1(challenge), D_P2(challenge+1),...)
 *  server phase 3  server-->client serverMsg3(Successful nego)
 *
 *  Secret Keys:[64]:= 
 *      PRF(premaster, "authServer keyNego protocol", Server-Rand||ClientRand)
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
 *      If the length of K > B: hash K to obtain an L byte string, then
 *       append 
 *      (B-L) 0's to create a B-byte string K0 (i.e., K0= H(K)|| 00...00). 
 *      If the length of K<B: append zeros to the end of K to create a
 *        B-byte string K0 (e.g., if K is 20 bytes in length and B= 64,
 *        then K will be appended with 44 zero bytes 0x00).
 *
 *  For now just PKCS-pad.  Should use PSS later.
 */


// Server Nego Messages
const char* szMsg1a= "<ServerNego phase='1' sessionId='%d'>\n <Random size='32'>"\
  "%s</Random>\n<CipherSuite> %s </CipherSuite>\n<ServerCertificate>\n";
const char* szMsg1b= "</ServerCertificate>\n</ServerNego>\n";

#if 0
const char* szMsg2= 
  "<ServerNego phase='2'>\n <RequestAuthentication Algorithm='%s'/>\n"\
  "<Challenge size='32'>%s</Challenge>\n</ServerNego>\n";
#endif

const char* szMsg2= 
  "<ServerNego phase='2'>\n <RequestAuthentication Algorithm='%s'/>\n"\
  "<Challenge size='32'>%s</Challenge>\n" \
  "<Hash>%s</Hash>\n</ServerNego>\n";

const char* szMsg3Pass=
  "<ServerNego phase='3'>\n <Status>Succeed</Status>\n</ServerNego>\n";
const char* szMsg3Fail=
  "<ServerNego phase='3'\n ><Status> Fail </Status>\n</ServerNego>\n";


bool serverNegoMessage1(char* buf, int maxSize, int iSessionId, const char* szAlg, 
                        const char* szRand, const char* szServerCert)
//  server phase 1  server-->client:
//      serverMsg1(rand, ciphersuite, server-cert)
{
    int     iLeft= maxSize;
    char*   p= buf;
    int     i= 0;

    sprintf(buf, szMsg1a, iSessionId, szRand, szAlg);
    i= strlen(buf);
    p+= i;
    iLeft-= i;
    if(!safeTransfer(&p, &iLeft, szServerCert))
        return false;
    if(!safeTransfer(&p, &iLeft, szMsg1b))
        return false;

    return true;
}


bool serverNegoMessage2(char* buf, int maxSize, const char* szAlg, 
                         const char* szChallenge, const char* szHash)
//  server phase 2  server-->client:
//      serverMsg2(Principal cert requests, challenge)--Encrypted after this
{
    sprintf(buf, szMsg2, szAlg, szChallenge, szHash);
    return true;
}


bool serverNegoMessage3(char* buf, int maxSize, bool fSucceed)
//  server phase 3  server-->client serverMsg3(Successful nego)
{
    int     iLeft= maxSize;
    char*   p= buf;

    if(fSucceed) {
        if(!safeTransfer(&p, &iLeft, szMsg3Pass))
            return false;
    }
    else {
        if(!safeTransfer(&p, &iLeft, szMsg3Fail))
            return false;
    }
    return true;
}


bool getDatafromClientMessage1(int n, char* request, sessionKeys& oKeys)
{
    TiXmlDocument   doc;
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;
    int             iOutLen= 64;

#ifdef  TEST
    fprintf(g_logFile, "Client Message 1\n%s\n", request);
    fflush(g_logFile);
#endif
    if(!doc.Parse(request)) {
        fprintf(g_logFile, "getDatafromClientMessage1: Message 1 parse failure in key Nego\n");
        return false;
    }

    TiXmlElement* pRootElement= doc.RootElement();
    if(pRootElement==NULL)
        return false;
    pNode= Search((TiXmlNode*) pRootElement, "Random");
    if(pNode==NULL)
        return false;
    pNode1= pNode->FirstChild();
    if(pNode1==NULL)
        return false;
    const char*   szRandom=  pNode1->Value();
    if(szRandom==NULL)
        return false;

    if(!fromBase64(strlen(szRandom), szRandom, &iOutLen, 
                                     (byte*)oKeys.m_rguClientRand)) {
        fprintf(g_logFile, "getDatafromClientMessage1: Cant base64 decode random number\n");
        return false;
    }
    oKeys.m_fClientRandValid= true;

    pNode= Search((TiXmlNode*) pRootElement, "CipherSuites");
    if(pNode==NULL)
        return false;

    pNode1= pNode->FirstChild();
    int         iIndex= -1;
    TiXmlNode*  pNode2= NULL;
    const char*       szProposedSuite= NULL;

    while(pNode1) {
         if(pNode1->Type()==TiXmlNode::TINYXML_ELEMENT) {
            if(strcmp(((TiXmlElement*)pNode1)->Value(),"CipherSuite")==0) {
                pNode2= ((TiXmlElement*)pNode1)->FirstChild();
                if(pNode2) {
                    szProposedSuite= ((TiXmlElement*)pNode2)->Value();
                    if(szProposedSuite!=NULL &&  
                       ((iIndex=cipherSuiteIndexFromName(szProposedSuite))>=0)) {
                        break;
                    }
                }
            }
        }
        pNode1= pNode1->NextSibling();
    }

    if(iIndex<0) {
        fprintf(g_logFile, "getDatafromClientMessage1: Unsupported cipher suite\n");
        return false;
    }
    char*   szCipherSuite= cipherSuiteNameFromIndex(iIndex);
    oKeys.m_szSuite= strdup(szCipherSuite);

    return true;
}


bool getDatafromClientMessage2(int n, char* request, sessionKeys& oKeys)
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;
    int             iOutLen= BIGSIGNEDSIZE;
    const char*     szEncryptedPreMasterSecret= NULL;
    char*     szClientCert= NULL;
    bool            fRet= true;

#ifdef  TEST
    fprintf(g_logFile, "Client Message 2\n%s\n", request);
    fflush(g_logFile);
#endif
    try {
        if(!doc.Parse(request))
            throw "getDatafromClientMessage2: parse failure\n";

        pRootElement= doc.RootElement();
        if(pRootElement==NULL)
            throw "getDatafromClientMessage2: No root element\n";
        pNode= Search((TiXmlNode*) pRootElement, "EncryptedPreMasterSecret");
        if(pNode==NULL)
            throw "getDatafromClientMessage2: No EncPreMaster\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw "getDatafromClientMessage2: No encryptedPreMaster\n";
        szEncryptedPreMasterSecret= pNode1->Value();
        if(szEncryptedPreMasterSecret==NULL)
            throw  "getDatafromClientMessage2: Cant find encrypted pPreMaster secret";
        if(!fromBase64(strlen(szEncryptedPreMasterSecret), szEncryptedPreMasterSecret, 
                       &iOutLen, (byte*)oKeys.m_rguEncPreMasterSecret))
            throw "getDatafromClientMessage2: Cant base64 decode pre-master secret\n";
        oKeys.m_fEncPreMasterSecretValid= true;
    
        pNode= Search((TiXmlNode*) pRootElement, "ClientCertificate");
        if(pNode==NULL)
            throw "getDatafromClientMessage2: Cant get Client Certificate\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw "getDatafromClientMessage2: Cant get Client Certificate\n";
        szClientCert= canonicalize(pNode1);
        if(szClientCert==NULL)
            throw "getDatafromClientMessage2: Cant canonicalize Client Certificate\n";
        oKeys.m_szXmlClientCert= szClientCert;
        oKeys.m_pclientCert= new PrincipalCert();
        if(!oKeys.m_pclientCert->init(szClientCert)) 
            throw "getDatafromClientMessage2: Cant initialize client certificate\n";
        if(!oKeys.m_pclientCert->parsePrincipalCertElements()) 
            throw "getDatafromClientMessage2: Cant parse client certificate\n";
        oKeys.m_pclientPublicKey= (RSAKey*)oKeys.m_pclientCert->getSubjectKeyInfo();
        if(oKeys.m_pclientPublicKey==NULL)
            throw "getDatafromClientMessage2: Cant init client public RSA key\n";
        oKeys.m_fClientCertValid= true;
    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "%s\n", szError);
    }

    if(szClientCert==NULL) {
        free(szClientCert);
        szClientCert= NULL;
    }

    return fRet;
}


bool getDatafromClientMessage3(int n, char* request, sessionKeys& oKeys)
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;
    const char*           szSignedChallenge= NULL;
    bool            fRet= true;

#ifdef  TEST
    fprintf(g_logFile, "getDatafromClientMessage 3\n%s\n", request);
    fflush(g_logFile);
#endif

    try {
        if(!doc.Parse(request))
            throw "getDatafromClientMessage3: parse failure\n";

        pRootElement= doc.RootElement();
        if(pRootElement==NULL)
            throw "getDatafromClientMessage3: No root element\n";

        pNode= Search((TiXmlNode*) pRootElement, "SignedChallenge");
        if(pNode==NULL)
            throw "getDatafromClientMessage3: No Signed Challenge\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw "getDatafromClientMessage3: No Signed Challenge value\n";
        szSignedChallenge=  pNode1->Value();
        if(szSignedChallenge==NULL)
            throw  "getDatafromClientMessage3: Cant extract szSignedChallenge";

        oKeys.m_szbase64SignedMessageHash= strdup(szSignedChallenge);
        oKeys.m_fbase64SignedMessageHashValid= true;

        if(!fromBase64(strlen(szSignedChallenge), szSignedChallenge, 
                       &oKeys.m_sizeSignedMessage, oKeys.m_rgSignedMessage))
            throw "getDatafromClientMessage3: Cant base64 decode signed hash \n";
        oKeys.m_fSignedMessageValid= true;
    
    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "%s\n", szError);
    }

    return fRet;
}


bool getDatafromClientMessage4(int n, char* request, sessionKeys& oKeys)
{
    // Principal certs, signed sequential challenges by principals
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;

#ifdef  TEST
    fprintf(g_logFile, "Client Message 4\n%s\n", request);
    fflush(g_logFile);
#endif
    if(!doc.Parse(request)) {
        fprintf(g_logFile, "getDatafromClientMessage4: parse failure\n");
        return false;
    }

    pRootElement= doc.RootElement();
    if(pRootElement==NULL) {
        fprintf(g_logFile, "getDatafromClientMessage4: no root cert\n");
        return false;
    }
    pNode= Search((TiXmlNode*) pRootElement, "EvidenceCollection");
    if(pNode==NULL) {
        fprintf(g_logFile, "getDatafromClientMessage4: no Principal EvidenceCollection tag\n");
        return false;
    }
    ((TiXmlElement*) pNode)->QueryIntAttribute("count", &oKeys.m_iNumPrincipals);
    pNode1= pNode->FirstChild();
    if(pNode1!=NULL) {
        oKeys.m_szPrincipalCerts= canonicalize(pNode);
    }

    pNode= Search((TiXmlNode*) pRootElement, "SignedChallenges");
    if(pNode!=NULL) {
        oKeys.m_szSignedChallenges= canonicalize(pNode);
    }

    return true;
}


// ------------------------------------------------------------------------


theServiceChannel::theServiceChannel()
{
    m_pParent= NULL;
    m_fdChannel= -1;

    m_serverState= NOSTATE;
    m_fChannelAuthenticated= false;
}


theServiceChannel::~theServiceChannel()
{
}


bool theServiceChannel::initSafeChannel()
{
    return m_osafeChannel.initChannel(m_fdChannel, AES128, CBCMODE, HMACSHA256, 
                          AES128BYTEKEYSIZE, AES128BYTEKEYSIZE,
                          m_oKeys.m_rguEncryptionKey2, m_oKeys.m_rguIntegrityKey2, 
                          m_oKeys.m_rguEncryptionKey1, m_oKeys.m_rguIntegrityKey1);
}


bool theServiceChannel::protocolNego()
{
    char    request[MAXREQUESTSIZEWITHPAD];
    char    rgszBase64[256];
    char    rgszHashBase64[256];
    int     n;
    int     type= CHANNEL_NEGO;
    byte    multi= 0;
    byte    final= 0;
    int     iOut64= 256;
    int     iOut= 256;
    bool    fRet= true;

#ifdef  TEST
    fprintf(g_logFile, "theServiceChannel::protocolNego\n");
    fflush(g_logFile);
#endif
    m_serverState= KEYNEGOSTATE;
    request[0]= '\0';

    try {

        // init message hash
        if(!m_oKeys.initMessageHash())
            throw  "authServer::protocolNego: Can't init message hash";

        // Phase 1, receive
        if((n=getPacket(m_fdChannel, (byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw  "theServiceChannel::protocolNego: Can't get packet 1\n";
        if(!m_oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw  "authServer::protocolNego: Can't update messagehash";
        if(!getDatafromClientMessage1(n, request, m_oKeys))
            throw  "theServiceChannel::protocolNego: Can't decode client message 1\n";
        iOut64= 256;
        if(!getBase64Rand(SMALLNONCESIZE, m_oKeys.m_rguServerRand, &iOut64, rgszBase64))
            throw  "theServiceChannel::protocolNego: Can't generate first nonce\n";
        m_oKeys.m_fServerRandValid= true;
#ifdef TEST
        fprintf(g_logFile, "theServiceChannel: got client rand\n");
        fflush(g_logFile);
#endif

        // Phase 1, send
        if(m_oKeys.m_szXmlServerCert==NULL)
            throw "theServiceChannel::protocolNego: No server Certificate\n";
        if(!serverNegoMessage1(request, MAXREQUESTSIZE, m_oKeys.m_iSessionId,
                               m_oKeys.m_szChallengeSignAlg, rgszBase64, m_oKeys.m_szXmlServerCert))
            throw  "theServiceChannel::protocolNego: Can't format negotiation message 1\n";
        if(!m_oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw  "authServer::protocolNego: Can't update messagehash";
        if((n=sendPacket(m_fdChannel, (byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw  "theServiceChannel::protocolNego: Can't send packet 1\n";

        // Phase 2, receive
        if((n=getPacket(m_fdChannel, (byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw  "theServiceChannel::protocolNego: Can't get packet 2\n";
        if(!m_oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw  "authServer::protocolNego: Can't update messagehash";
        if(!getDatafromClientMessage2(n, request, m_oKeys))
            throw  "theServiceChannel::protocolNego: Can't decode client message 2\n";
        if(!m_oKeys.clientcomputeMessageHash())
            throw "theServiceChannel::protocolNego: client cant compute message hash";
        if(!m_oKeys.computeServerKeys()) 
            throw  "theServiceChannel::protocolNego: Cant compute channel keys\n";
#ifdef TEST
        fprintf(g_logFile, "theServiceChannel: computed server keys\n");
        fflush(g_logFile);
#endif

        // Phase 3, receive
        if((n=getPacket(m_fdChannel, (byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw  "theServiceChannel::protocolNego: Can't get packet 3\n";
        if(!getDatafromClientMessage3(n, request, m_oKeys))
            throw  "theServiceChannel::protocolNego: Can't decode client message 3\n";
        if(!m_oKeys.checkclientSignedHash())
            throw "theServiceChannel::protocolNego: client signed message hash does not match";
        if(!m_oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw  "authServer::protocolNego: Can't update messagehash";
        if(!m_oKeys.servercomputeMessageHash())
            throw "theServiceChannel::protocolNego: can't compute server hash";

        // init safeChannel
        if(!initSafeChannel())
            throw  "theServiceChannel::protocolNego: Cant init channel\n";

        // Assume CBC
        if((n=sendPacket(m_fdChannel, m_osafeChannel.lastsendBlock, AES128BYTEBLOCKSIZE, CHANNEL_NEGO_IV, 0, 1))<0)
            throw "theServiceChannel::protocolNego: Cant send IV\n";
        m_osafeChannel.fsendIVSent= true;
        if((n=getPacket(m_fdChannel, m_osafeChannel.lastgetBlock, AES128BYTEBLOCKSIZE, &type, &multi, &final))<0)
            throw "theServiceChannel::protocolNego: Cant get IV\n";
        m_osafeChannel.fgetIVReceived= true;

#ifdef  TEST
        fprintf(g_logFile, "theServiceChannel::protocolNego: Encrypted mode on\n");
        PrintBytes((char*)"Received IV: ", m_osafeChannel.lastgetBlock, AES128BYTEBLOCKSIZE);
        PrintBytes((char*)"Sent     IV: ", m_osafeChannel.lastsendBlock, AES128BYTEBLOCKSIZE);
        fflush(g_logFile);
#endif

        // Phase 2, send
        iOut= 256;
        if(!getBase64Rand(SMALLNONCESIZE, m_oKeys.m_rguChallenge, &iOut, rgszBase64)) 
            throw  "theServiceChannel::protocolNego: Can't generate principal challenge\n";
        m_oKeys.m_fChallengeValid= true;

        // compute szHash string
        iOut= 256;
        if(!toBase64(SHA256DIGESTBYTESIZE, m_oKeys.m_rgServerMessageHash, 
                      &iOut, rgszHashBase64))
            throw  "theServiceChannel::protocolNego: Can't base64 encode server hash\n";
        if(!serverNegoMessage2(request, MAXREQUESTSIZE, m_oKeys.m_szChallengeSignAlg, 
                               rgszBase64, rgszHashBase64))
            throw  "theServiceChannel::protocolNego: Can't format negotiation message 2\n";

        if((n=m_osafeChannel.safesendPacket((byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw  "theServiceChannel::protocolNego: Can't safesendPacket 2\n";
#ifdef TEST
        fprintf(g_logFile, "theServiceChannel::protocolNego: client signed message hash matches\n");
        fflush(g_logFile);
#endif

        // Phase 4, receive
        if((n=m_osafeChannel.safegetPacket((byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw  "theServiceChannel::protocolNego: Can't get packet 4\n";
        if(!m_oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw  "theServiceChannel::protocolNego: Can't update messagehash";
        if(!getDatafromClientMessage4(n, request, m_oKeys)) 
            throw  "theServiceChannel::protocolNego: Can't decode client message 4\n";
        if(!m_oKeys.initializePrincipalCerts())
            throw "theServiceChannel::protocolNego: Cant initialize principal public keys\n";
        if(!m_oKeys.checkPrincipalChallenges())
            throw "theServiceChannel::protocolNego: Principal challenges fail\n";
#ifdef TEST
        fprintf(g_logFile, "theServiceChannel: checked principal challenges\n");
        fflush(g_logFile);
#endif

        // Phase 4, send
        if(!serverNegoMessage3(request, MAXREQUESTSIZE, true))
            throw  "theServiceChannel::protocolNego: Can't format negotiation message 3\n";
        if((n=m_osafeChannel.safesendPacket((byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw  "theServiceChannel::protocolNego: Can't send packet 3\n";
#ifdef TEST
        fprintf(g_logFile, "theServiceChannel: success packet sent\n");
        fflush(g_logFile);
#endif
    }
    catch(const char* szError) {
        fprintf(g_logFile, "%s",szError);
        fRet= false;
        return false;
    }

    m_oKeys.validateChannelData(false);
#ifdef TEST
        fprintf(g_logFile, "theServiceChannel: protocol data validated\n");
        fflush(g_logFile);
#endif

    // register principals
    if(m_oKeys.m_pserverCert!=NULL) {
        if(registerPrincipalfromCert(m_oKeys.m_pserverCert)==NULL)
            throw "theServiceChannel::protocolNego: Can't register server principal\n";
    }

    if(m_oKeys.m_pclientCert!=NULL) {
        if(registerPrincipalfromCert(m_oKeys.m_pclientCert)==NULL)
            throw "theServiceChannel::protocolNego: Can't register client principal\n";
    }
#ifdef TEST
        fprintf(g_logFile, "theServiceChannel: protocol negotiation complete\n");
        m_oKeys.printMe();
        fflush(g_logFile);
#endif

    m_serverState= REQUESTSTATE;

    return fRet;
}


int theServiceChannel::processRequests()
{
    byte    request[MAXREQUESTSIZEWITHPAD];
    int     type= 0;
    byte    multi= 0;
    byte    final= 0;
    int     encType= NOENCRYPT;
    byte*   key= NULL;

#ifdef TEST
    fprintf(g_logFile, "\n\ntheServiceChannel: processRequest\n");
#endif
    m_serverState= REQUESTSTATE;

    if(m_osafeChannel.safegetPacket(request, MAXREQUESTSIZE, &type, &multi, &final)<(int)sizeof(packetHdr)) {
        fprintf(g_logFile, "theServiceChannel::processRequests: Can't get ProcessRequest packet\n");
        return -1;
    }

#ifdef TEST
    fprintf(g_logFile, "theServiceChannel::processRequests: packetType %d, serverstate %d\n", type, m_serverState);
#endif
    if(type==CHANNEL_TERMINATE) {
        fprintf(g_logFile, "Received CHANNEL_TERMINATE; returning 0 from theServiceChannel::processRequests\n");
        fflush(g_logFile);
        return 0;
    }
    if(type!=CHANNEL_REQUEST) {
        fprintf(g_logFile, "theServiceChannel::processRequests: Not a channel request\n");
        return -1;
    }

    if(m_pParent->m_fEncryptFiles) {
        if(!m_pParent->m_fKeysValid) {
            fprintf(g_logFile, "theServiceChannel::processRequests: Encryption enabled but key invalid\n");
            return -1;
        }
        encType= DEFAULTENCRYPT;
        key= m_pParent->m_authKeys;
    }

    int     iRequestType= 0;
    {
        Request oReq;

        // oReq.m_poAG= &m_oAG;
        if(!oReq.getDatafromDoc(reinterpret_cast<char*>(request))) {
            fprintf(g_logFile, "theServiceChannel::processRequests: cant parse: %s\n", request);
            return -1;
        }

#ifdef TEST
        fprintf(g_logFile, "parsed oReq from request: %s\n", request);
#endif


        iRequestType= oReq.m_iRequestType;
        if(oReq.m_szCredentialType==NULL) {
            fprintf(g_logFile, "theServiceChannel::processRequests: Empty credential type\n");
            return -1;
        }

        switch(iRequestType) {
          case GETTOKEN:
            if(!serversendCredentialtoclient(m_signingKey, m_osafeChannel, oReq,  m_oKeys, encType, key, 
                                        m_pParent->m_accessCheckTimer, m_pParent->m_decTimer)) {
                fprintf(g_logFile, "serversendCredentialtoclient failed 1\n");
                return -1;
            }
            return 1;
          default:
            fprintf(g_logFile, "theServiceChannel::processRequests: invalid request type\n");
            return -1;
        }
    }
}


bool theServiceChannel::initServiceChannel()
{
    int     n= 0;

#ifdef  TEST
    fprintf(g_logFile, "theServiceChannel::initserviceChannel\n");
    fflush(g_logFile);
#endif

    m_serverState= INITSTATE;

    // Initialize program private key and certificate for session
    if(!m_pParent->m_tcHome.m_privateKeyValid ||
           !m_oKeys.getMyProgramKey((RSAKey*)m_pParent->m_tcHome.m_privateKey)) {
        fprintf(g_logFile, "theServiceChannel::serviceChannel: Cant get my private key\n");
        return false;
    }
#ifdef  TEST
    fprintf(g_logFile, "theServiceChannel::serviceChannel: program key set\n");
    fflush(g_logFile);
#endif
    if(!m_pParent->m_tcHome.m_myCertificateValid ||
           !m_oKeys.getMyProgramCert(m_pParent->m_tcHome.m_myCertificate)) {
        fprintf(g_logFile, "theServiceChannel::serviceChannel: Cant get my Cert\n");
        return false;
    }

    // copy my public key into server public key
    if(!m_pParent->m_tcHome.m_myCertificateValid ||
           !m_oKeys.getServerCert(m_pParent->m_tcHome.m_myCertificate)) {
        fprintf(g_logFile, "theServiceChannel::serviceChannel: Cant load client public key structures\n");
        return false;
    }

    m_pParent->m_protocolNegoTimer.Start();
    if(!protocolNego())
        return false;
    m_pParent->m_protocolNegoTimer.Stop();

#ifdef  TEST
    fprintf(g_logFile, "theServiceChannel::serviceChannel, about to init guard\n");
    fflush(g_logFile);
#endif
    // Access Guard valid?
#if 0
    if(!m_oAG.m_fValid) {
        if(!m_oAG.initChannelAccess(m_oKeys.m_iNumPrincipals, m_oKeys.m_rgPrincipalCerts)) {
            fprintf(g_logFile, "Request::validateRequest: initAccessGuard returned false\n");
            return false;
        }
    }
#endif

    m_serverState= REQUESTSTATE;
    while((n=processRequests())!=0) {
        if(n<0)
            fprintf(g_logFile, "theServiceChannel::serviceChannel: processRequest error\n");
        fflush(g_logFile);
        m_pParent->printTimers(g_logFile);
        m_pParent->resetTimers();
    }
    m_serverState= SERVICETERMINATESTATE;

#ifdef TEST
    fprintf(g_logFile, "theServiceChannel: serviceChannel terminating\n");
#endif
    if(m_fdChannel>0) {
        close(m_fdChannel);
        m_fdChannel= -1;
    }
    return true;
}


void* channelThread(void* ptr)
{
    try {
        theServiceChannel*  poSc= (theServiceChannel*) ptr;

#ifdef TEST
        fprintf(g_logFile, "channelThread activated\n");
        fprintf(g_logFile, "\tptr: %08x\n", ptr);
        fprintf(g_logFile, "\tchannel: %d, parent: %08x\n",
                poSc->m_fdChannel, poSc->m_pParent);

        fflush(g_logFile);
#endif
        if(!poSc->initServiceChannel()) {
            fprintf(g_logFile, "channelThread: initServiceChannel failed\n");
        }

        // delete enty in thread table in parent
        if(poSc->m_myPositionInParent>=0) 
            poSc->m_pParent->m_fthreadValid[poSc->m_myPositionInParent]= false;
        poSc->m_myPositionInParent= -1;
#ifdef TEST
        fprintf(g_logFile, "channelThread exiting\n");
        fflush(g_logFile);
#endif
        delete  poSc;
    } catch (const char* err) {
        fprintf(g_logFile, "Server thread exited with error: %s\n", err);
        fflush(g_logFile);
    }

    pthread_exit(NULL);
    return NULL;
}
    

// ----------------------------------------------------------------------------


authServer::authServer()
{
    m_szPort= NULL;
    m_szAddress= NULL;
    m_iNumClients= 0;

    m_fEncryptFiles= false;
    m_szSealedKeyFile= NULL;
    m_fKeysValid= false;
    m_uAlg= 0;
    m_uMode= 0;
    m_uPad= 0;
    m_uHmac= 0;
    m_sizeKey= SMALLKEYSIZE;
    m_szSigningKeyFile= NULL;
    m_szSigningKeyCert= NULL;
    m_szSigningKeyMetaDataFile= NULL;
}


authServer::~authServer()
{
    if(m_szPort!=NULL) {
        free(m_szPort);
        m_szPort= NULL;
    }
    if(m_szAddress!=NULL) {
        free(m_szAddress);
        m_szAddress= NULL;
    }
    if(m_fKeysValid)
        memset(m_authKeys, 0, m_sizeKey);
    m_fKeysValid= false;
    if(m_szSealedKeyFile!=NULL)
        free(m_szSealedKeyFile);
    m_szSealedKeyFile= NULL;
}


bool authServer::initPolicy()
{
#ifdef TEST
    fprintf(g_logFile, "authServer::initPolicy\n");
    fflush(g_logFile);
#endif
    if(!m_tcHome.m_envValid) {
        fprintf(g_logFile, "authServer::initPolicy(): environment invalid\n");
        return false;
    }

    if(!m_tcHome.m_policyKeyValid)  {
        fprintf(g_logFile, "authServer::initPolicy(): policyKey invalid\n");
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "authServer::initPolicy: about to initpolicy Cert\n",
            m_tcHome.m_policyKey);
    fflush(g_logFile);
#endif
    if(!g_policyPrincipalCert->init(reinterpret_cast<char*>(m_tcHome.m_policyKey))) {
        fprintf(g_logFile, "authServer::initPolicy: Can't init policy cert 1\n");
        fflush(g_logFile);
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "authServer::initPolicy, about to parse policy Cert\n");
    fprintf(g_logFile, "authServer::initPolicy, policy Cert\n%s\n",
            m_tcHome.m_policyKey);
    fflush(g_logFile);
#endif
    if(!g_policyPrincipalCert->parsePrincipalCertElements()) {
        fprintf(g_logFile, "initPolicy: Can't init policy key 2\n");
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "authServer::initPolicy, about to get policy key\n");
    fflush(g_logFile);
#endif
    g_policyKey= (RSAKey*)g_policyPrincipalCert->getSubjectKeyInfo();
    if(g_policyKey==NULL) {
        fprintf(g_logFile, "initPolicy: Can't init policy key 3\n");
        return false;
    }
#if 0
    g_policyAccessPrincipal= registerPrincipalfromCert(g_policyPrincipalCert);
    if(g_policyAccessPrincipal==NULL) {
        fprintf(g_logFile, "initPolicy: Can't init policy key 3\n");
        return false;
    }
#endif

    g_globalpolicyValid= true;
#ifdef TEST
    fprintf(g_logFile, "authServer::initPolicy, returning true\n");
    fflush(g_logFile);
#endif
    return true;
}


bool authServer::initSigningKeys()
{
    int     size= 4096;
    byte    buf[4096];
    encapsulatedMessage     oM;
    char*   szMetaData= NULL;
    RSAKey* sealingKey= NULL;

    if(!m_tcHome.m_privateKeyValid) {
        fprintf(g_logFile, "authServer::initSigningKeys: private key not valid\n");
        return false;
    }
    sealingKey= (RSAKey*)m_tcHome.m_privateKey;
    if(sealingKey==NULL) {
        fprintf(g_logFile, "authServer::initSigningKeys: private key empty\n");
        return false;
    }

    m_szSigningKeyCert= strdup("./authServer/signingCert");
    if(!getBlobfromFile(m_szSigningKeyCert, buf, &size)) {
        fprintf(g_logFile, "authServer::initSigningKeys: Can't read signing cert\n");
        return false;
    }
    m_signingCert= strdup((char *)buf);

    size= 4096;
    memset(buf,0,size);
    m_szSigningKeyMetaDataFile= strdup("./authServer/signingKeyMetaData");
    if(!getBlobfromFile(m_szSigningKeyMetaDataFile, buf, &size)) {
        fprintf(g_logFile, "authServer::initSigningKeys: Can't read sealed signing key\n");
        return false;
    }
    szMetaData= strdup((char*)buf);
#ifdef TEST
    fprintf(g_logFile, "authServer::initSigningKeys: encapsulated meta\n%s\n",
            szMetaData);
#endif

    size= 4096;
    memset(buf,0,size);
    m_szSigningKeyFile= strdup("./authServer/signingKey");
    if(!getBlobfromFile(m_szSigningKeyFile, buf, &size)) {
        fprintf(g_logFile, "authServer::initSigningKeys: Can't read sealed signing key\n");
        return false;
    }

    if(!oM.setencryptedMessage(size, buf)) {
        fprintf(g_logFile, "authServer::initSigningKeys: cant set ciphertext\n");
        return false;
    }

    oM.m_szXMLmetadata= strdup(szMetaData);

    // parse metadata
    if(!oM.parseMetaData()) {
        fprintf(g_logFile, "authServer::initSigningKeys: cant parse metadata\n");
        return false;
    }

    // unseal key
    if(!oM.unSealKey(sealingKey)) {
        fprintf(g_logFile, "authServer::initSigningKeys: cant unseal key\n");
        return false;
    }

    if(!oM.decryptMessage()) {
        fprintf(g_logFile, "authServer::initSigningKeys: cant decrypt message\n");
        return false;
    }
#ifdef TEST
    PrintBytes((char*)"authServer::initSigningKeys: encrypted private key\n", 
               oM.m_rgEncrypted, oM.m_sizeEncrypted);
    fflush(g_logFile);
    PrintBytes((char*)"authServer::initSigningKeys: dencrypted private key\n", 
               oM.m_rgPlain, oM.m_sizePlain);
    fprintf(g_logFile, "%s\n",
            (char*)oM.m_rgPlain);
    fflush(g_logFile);
#endif

    m_signingKey= (RSAKey*)keyfromkeyInfo((char*)oM.m_rgPlain);
    if(m_signingKey==NULL)
        return false;
    return true;
}


bool authServer::initFileKeys()
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
            fprintf(g_logFile, "initFileKeys: key size too small\n");
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


bool authServer::initServer(const char* configDirectory)
{
    bool            fRet= true;
    const char*     directory= NULL;

    try {

        const char** parameters = NULL;
        int parameterCount = 0;
        if(configDirectory==NULL) {
            directory= DEFAULTDIRECTORY;
            
        } else {
            directory= configDirectory;
            parameters= &directory;
            parameterCount= 1;
        }

        if(!initAllCrypto()) {
            throw "authServer::Init: can't initcrypto\n";
        }

        // init Host and Environment
        m_taoHostInitializationTimer.Start();
        if(!m_host.HostInit(PLATFORMTYPELINUX, parameterCount, parameters)) {
            throw "authServer::Init: can't init host\n";
        }
        m_taoHostInitializationTimer.Stop();
#ifdef TEST
        fprintf(g_logFile, "authServer::Init: after HostInit, pid: %d\n",
            getpid());
#endif

        // init environment
        m_taoEnvInitializationTimer.Start();
        if(!m_tcHome.EnvInit(PLATFORMTYPELINUXAPP, "authServer",
                             DOMAIN, directory,
                             &m_host, 0, NULL)) {
            throw "authServer::Init: can't init environment\n";
        }
        m_taoEnvInitializationTimer.Stop();
#ifdef TEST
        fprintf(g_logFile, "authServer::Init: after EnvInit\n");
        m_tcHome.printData();
#endif

        // Initialize file encryption keys
        if(!initFileKeys())
            throw "authServer::Init: can't init file keys\n";
#ifdef TEST
        fprintf(g_logFile, "authServer::Init: after initFileKeys\n");
        m_tcHome.printData();
#endif

        // Initialize credential and principal tables
#if 0
        if(!g_theVault.initMetaData(m_tcHome.m_fileNames.m_szdirectory, 
            "authServer"))
            throw "authServer::Init: Cant init metadata\n";
        if(!g_theVault.initFileNames())
            throw "authServer::Init: Cant init file names\n";
#endif

        if(!initSigningKeys())
            throw "authServer::Init: Cant init signing keys\n";

#ifdef TEST
        fprintf(g_logFile, "initServer about to initPolicy();\n");
        fflush(g_logFile);
#endif
        // Init global policy 
        if(!initPolicy())
            throw "authServer::Init: Cant init policy objects\n";
#ifdef TEST
        fprintf(g_logFile, "initServer has private key and public key\n");
        fflush(g_logFile);
#endif

    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "authServer error: %s\n", szError);
        fflush(g_logFile);
    }

#ifdef TEST
    if(fRet)
        fprintf(g_logFile, "authServer initialized\n");
    else
        fprintf(g_logFile, "authServer initialization failed\n");
#endif
    return fRet;
}


bool authServer::closeServer()
{
    return true;
}


bool authServer::server()
{
    int                 fd, newfd;
    struct sockaddr_in  server_addr, client_addr;
    int                 slen= sizeof(struct sockaddr_in);
    int                 clen= sizeof(struct sockaddr);
    int                 iError;

    fd= socket(AF_INET, SOCK_STREAM, 0);
    if(fd<0) {
        fprintf(g_logFile, "authServer::server: Can't open socket\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "authServer::server: socket opened\n");
    fflush(g_logFile);
#endif

    memset((void*) &server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family= AF_INET;
    server_addr.sin_addr.s_addr= htonl(INADDR_ANY);     // 127.0.0.1
    server_addr.sin_port= htons(SERVICE_PORT);

    iError= bind(fd,(const struct sockaddr *) &server_addr, slen);
    if(iError<0) {
        fprintf(g_logFile, "Can't bind socket: %s", strerror(errno));
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "authServer::server: bind succeeded\n");
    fflush(g_logFile);
#endif

    listen(fd, iQueueSize);

    // set the signal disposition of SIGCHLD to not create zombies
    struct sigaction sigAct;
    memset(&sigAct, 0, sizeof(sigAct));
    sigAct.sa_handler = SIG_DFL;
    sigAct.sa_flags = SA_NOCLDWAIT; // don't zombify child processes
    int sigRv = sigaction(SIGCHLD, &sigAct, NULL);
    if (sigRv < 0) {
        fprintf(g_logFile, "Failed to set signal disposition for SIGCHLD\n");
    } 
    else {
        fprintf(g_logFile, "Set SIGCHLD to avoid zombies\n");
    }


    theServiceChannel*  poSc= NULL;
    int                 i;
    for(;;) {
#ifdef TEST
        fprintf(g_logFile, "authServer: top of accept loop\n");
        fflush(g_logFile);
#endif
        newfd= accept(fd, (struct sockaddr*) &client_addr, (socklen_t*)&clen);
        if(newfd<0) {
            fprintf(g_logFile, "Can't accept socket", strerror(errno));
            return false;
        }
#ifdef TEST
        fprintf(g_logFile, "authServer: accept succeeded\n");
        fflush(g_logFile);
#endif

        poSc= new theServiceChannel();

        if(poSc!=NULL) {

            for(i=0; i<m_iNumClients; i++) {
                if(!m_fthreadValid[i])
                    break;
            }

            if(i==m_iNumClients) {
                if(m_iNumClients>=MAXNUMCLIENTS) {
                    fprintf(g_logFile, "authServer::server: Can't allocate theServiceChannel\n");
                    return false;
                }
                i= m_iNumClients++;
            }
                    
            poSc->m_pParent= this;
            poSc->m_fdChannel= newfd;
            poSc->m_myPositionInParent= i;
            poSc->m_signingKey=  m_signingKey;
#ifdef TEST
            fprintf(g_logFile, "authServer: slot %d, about to pthread_create\n", i);
            fprintf(g_logFile, "\tnewfd: %d\n", newfd);
            fflush(g_logFile);
#endif

            memset(&m_threadData[i], 0, sizeof(pthread_t));
            m_threadIDs[i]= pthread_create(&m_threadData[i], NULL, 
                                    channelThread, poSc);
#ifdef TEST
            fprintf(g_logFile, "authServer: pthread create returns: %d\n", m_threadIDs[i]);
            fflush(g_logFile);
#endif
            if(m_threadIDs[i]>=0)
                m_fthreadValid[i]= true;
            else
                m_fthreadValid[i]= false;
        }
        else {
            fprintf(g_logFile, "authServer::server: Can't allocate theServiceChannel\n");
        }

        poSc= NULL;
        newfd= -1;
        if(g_fTerminateServer)
            break;
    }

    close(fd);
    fflush(g_logFile);
    return true;
}


// --------------------------------------------------------------------------


int main(int an, char** av)
// authServer.exe [-initKeys address-of-managementserver]
{
    authServer  oServer;
    int         i;
    int         iRet= 0;
    bool        fInitProg= false;
    const char* directory= NULL;


    initLog(NULL);
#ifdef TEST
    fprintf(g_logFile, "authServer main: authServer started\n");
    fflush(g_logFile);
#endif
    // check arguments
    if(an>1) {
        for(i=0;i<an;i++) {
             if(strcmp(av[i],"-initProg")==0) {
                fInitProg= true;
             }
            if(strcmp(av[i],"-address")==0) {
                oServer.m_szAddress= strdup(av[++i]);
             }
            if(strcmp(av[i],"-directory")==0) {
                directory= strdup(av[++i]);
            }
        }
    }

#ifdef DONTENCRYPTFILES
    oServer.m_fEncryptFiles= false;
#else
    oServer.m_fEncryptFiles= true;
#endif

    // am I alread measured?
    if(fInitProg) {
#ifdef TEST
        fprintf(g_logFile, "authServer main: start measured program %s\n", av[0]);
#endif
        if(!startMeAsMeasuredProgram(an, av)) {
#ifdef TEST
            fprintf(g_logFile, "authServer main: measured program failed, exiting\n");
#endif
            return 1;
        }
#ifdef TEST
        fprintf(g_logFile, "authServer main: measured program started\n");
#endif
        return 0;
    }

    initLog("authServer.log");
#ifdef TEST
        fprintf(g_logFile, "authServer main: measured server about to init server\n");
        fflush(g_logFile);
#endif

    try {
        g_policyPrincipalCert= new PrincipalCert();
        if(g_policyPrincipalCert==NULL)
            throw "authServer main: failed to new Principal\n";

        if(!oServer.initServer(directory)) 
            throw "authServer main: cant initServer\n";

#ifdef TEST
        fprintf(g_logFile, "authServer main: measured server entering server loop\n");
        fflush(g_logFile);
#endif
        oServer.server();
        oServer.closeServer();
        closeLog();
    } 
    catch(const char* szError) {
        fprintf(g_logFile, "%s", szError);
        iRet= 1;
    }

    return iRet;

}


// ------------------------------------------------------------------------


void authServer::printTimers(FILE* log) {
    if (m_sealTimer.GetMeasurements().size() > 0) {
        fprintf(log, "serverSealTimes = ");
        m_sealTimer.print(log);
    }

    if (m_unsealTimer.GetMeasurements().size() > 0) {
        fprintf(log, "serverUnsealTimes =  ");
        m_unsealTimer.print(log);
    }

    if (m_taoEnvInitializationTimer.GetMeasurements().size() > 0) {
        fprintf(log, "serverTaoEnvInitTimes = ");
        m_taoEnvInitializationTimer.print(log);
    }

    if (m_taoHostInitializationTimer.GetMeasurements().size() > 0) {
        fprintf(log, "serverTaoHostInitTimes = ");
        m_taoHostInitializationTimer.print(log);
    }

    if (m_protocolNegoTimer.GetMeasurements().size() > 0) {
        fprintf(log, "serverProtocolNegoTimes = ");
        m_protocolNegoTimer.print(log);
    }

    if (m_accessCheckTimer.GetMeasurements().size() > 0) {
        fprintf(log, "serverAccessCheckTimes = ");
        m_accessCheckTimer.print(log);
    }

    if (m_encTimer.GetMeasurements().size() > 0) {
        fprintf(log, "serverEncTimes = ");
        m_encTimer.print(log);
    }

    if (m_decTimer.GetMeasurements().size() > 0) {
        fprintf(log, "serverDecTimes = ");
        m_decTimer.print(log);
    }
}

void authServer::resetTimers() {
    m_sealTimer.Clear();
    m_unsealTimer.Clear();
    m_taoEnvInitializationTimer.Clear();
    m_taoHostInitializationTimer.Clear();
    m_protocolNegoTimer.Clear();
    m_accessCheckTimer.Clear();
    m_encTimer.Clear();
    m_decTimer.Clear();
}

// ------------------------------------------------------------------------




