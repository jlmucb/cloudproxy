//
//  File: fileServer.cpp
//      John Manferdelli
//
//  Description: Sever for fileServer
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
#include "fileServer.h"
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
#include "resource.h"
#include "secPrincipal.h"
#include "accessControl.h"
#include "vault.h"
#include "trustedKeyNego.h"
#include "encryptedblockIO.h"
#include "domain.h"

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
#include <errno.h>
#ifdef LINUX
#include <wait.h>
#endif


bool        g_fTerminateServer= false;
int         iQueueSize= 5;

bool             g_globalpolicyValid= false;
metaData         g_theVault;
PrincipalCert*   g_policyPrincipalCert= NULL;
RSAKey*          g_policyKey= NULL;
accessPrincipal* g_policyAccessPrincipal= NULL;

#include "./policyCert.inc"

accessPrincipal* registerPrincipalfromCert(PrincipalCert* pSig);

#ifdef TEST
void printResources(objectManager<resource>* pRM);
void printPrincipals(objectManager<accessPrincipal>* pPM);
#endif


// ------------------------------------------------------------------------


fileServer::fileServer ()
{
    m_serverState= NOSTATE;
    m_fChannelAuthenticated= false;
    m_szPort= NULL;
    m_szAddress= NULL;

    m_fEncryptFiles= false;
    m_szSealedKeyFile= NULL;
    m_fKeysValid= false;
    m_uAlg= 0;
    m_uMode= 0;
    m_uPad= 0;
    m_uHmac= 0;
    m_sizeKey= SMALLKEYSIZE;
}


fileServer::~fileServer ()
{
    m_serverState= NOSTATE;
    m_fChannelAuthenticated= false;
    if(m_szPort!=NULL) {
        free(m_szPort);
        m_szPort= NULL;
    }
    if(m_szAddress!=NULL) {
        free(m_szAddress);
        m_szAddress= NULL;
    }
    if(m_fKeysValid)
        memset(m_fileKeys, 0, m_sizeKey);
    m_fKeysValid= false;
    if(m_szSealedKeyFile!=NULL)
        free(m_szSealedKeyFile);
    m_szSealedKeyFile= NULL;
}


bool fileServer::initPolicy()
{
#ifdef TEST
    fprintf(g_logFile, "fileServer::initPolicy\n");
    fflush(g_logFile);
#endif
    if(!m_tcHome.m_envValid) {
        fprintf(g_logFile, "fileServer::initPolicy(): environment invalid\n");
        return false;
    }

    if(!m_tcHome.m_policyKeyValid)  {
        fprintf(g_logFile, "fileServer::initPolicy(): policyKey invalid\n");
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "fileServer::initPolicy: about to initpolicy Cert\n",
            (char*)m_tcHome.m_policyKey);
    fflush(g_logFile);
#endif
    if(!g_policyPrincipalCert->init((char*)m_tcHome.m_policyKey)) {
        fprintf(g_logFile, "fileServer::initPolicy: Can't init policy cert 1\n");
        fflush(g_logFile);
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "fileServer::initPolicy, about to parse policy Cert\n");
    fprintf(g_logFile, "fileServer::initPolicy, policy Cert\n%s\n",
            (char*)m_tcHome.m_policyKey);
    fflush(g_logFile);
#endif
    if(!g_policyPrincipalCert->parsePrincipalCertElements()) {
        fprintf(g_logFile, "initPolicy: Can't init policy key 2\n");
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "fileServer::initPolicy, about to get policy key\n");
    fflush(g_logFile);
#endif
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
#ifdef TEST
    fprintf(g_logFile, "fileServer::initPolicy, returning true\n");
    fflush(g_logFile);
#endif
    return true;
}


bool fileServer::initFileKeys()
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


bool fileServer::initServer(char* configDirectory)
{
    bool            fRet= true;
    char*           directory= NULL;

    try {

        char** parameters = NULL;
        int parameterCount = 0;
        if(configDirectory==NULL) {
            directory= DEFAULTDIRECTORY;
            
        } else {
            directory= configDirectory;
            parameters= &directory;
            parameterCount= 1;
        }

        if(!initAllCrypto()) {
            throw((char*)"fileServer::Init: can't initcrypto\n");
        }

        // init Host and Environment
        if(!m_host.HostInit(PLATFORMTYPELINUX, parameterCount, parameters)) {
            throw((char*)"fileServer::Init: can't init host\n");
        }
#ifdef TEST
        fprintf(g_logFile, "fileServer::Init: after HostInit, pid: %d\n",
            getpid());
#endif

        // init environment
        if(!m_tcHome.EnvInit(PLATFORMTYPELINUXAPP, (char*)"fileServer",
                             DOMAIN, directory,
                             &m_host, 0, NULL)) {
            throw((char*)"fileServer::Init: can't init environment\n");
        }
#ifdef TEST
        fprintf(g_logFile, "fileServer::Init: after EnvInit\n");
        m_tcHome.printData();
#endif

        // Initialize file encryption keys
        if(!initFileKeys())
            throw((char*)"fileServer::Init: can't init file keys\n");
#ifdef TEST
        fprintf(g_logFile, "fileServer::Init: after initFileKeys\n");
        m_tcHome.printData();
#endif

        // Initialize resource and principal tables
        if(!g_theVault.initMetaData(m_tcHome.m_fileNames.m_szdirectory, 
            (char*)"fileServer"))
            throw((char*)"fileServer::Init: Cant init metadata\n");
        if(!g_theVault.initFileNames())
            throw((char*)"fileServer::Init: Cant init file names\n");

#ifdef TEST
        fprintf(g_logFile, "initServer about to initPolicy();\n");
        fflush(g_logFile);
#endif
        // Init global policy 
        if(!initPolicy())
            throw((char*)"fileServer::Init: Cant init policy objects\n");
#ifdef TEST
        fprintf(g_logFile, "initServer has private key and public key\n");
        fflush(g_logFile);
#endif

    }
    catch(char* szError) {
        fRet= false;
        fprintf(g_logFile, "fileServer error: %s\n", szError);
        fflush(g_logFile);
    }

#ifdef TEST
    if(fRet)
        fprintf(g_logFile, "fileServer initialized\n");
    else
        fprintf(g_logFile, "fileServer initialization failed\n");
#endif
    return fRet;
}


bool fileServer::closeServer()
{
    return true;
}


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
 *      PRF(premaster, "fileServer keyNego protocol", Server-Rand||ClientRand)
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
char* szMsg1a= (char*) "<ServerNego phase='1' sessionId='%d'>\n <Random size='32'>"\
  "%s</Random>\n<CipherSuite> %s </CipherSuite>\n<ServerCertificate>\n";
char* szMsg1b= (char*) "</ServerCertificate>\n</ServerNego>\n";

#if 0
char* szMsg2= (char*) 
  "<ServerNego phase='2'>\n <RequestAuthentication Algorithm='%s'/>\n"\
  "<Challenge size='32'>%s</Challenge>\n</ServerNego>\n";
#endif

char* szMsg2= (char*) 
  "<ServerNego phase='2'>\n <RequestAuthentication Algorithm='%s'/>\n"\
  "<Challenge size='32'>%s</Challenge>\n" \
  "<Hash>%s</Hash>\n</ServerNego>\n";

char* szMsg3Pass= (char*)
  "<ServerNego phase='3'>\n <Status>Succeed</Status>\n</ServerNego>\n";
char* szMsg3Fail= (char*)
  "<ServerNego phase='3'\n ><Status> Fail </Status>\n</ServerNego>\n";


bool serverNegoMessage1(char* buf, int maxSize, int iSessionId, char* szAlg, 
                        char* szRand, char* szServerCert)
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


#if 0
bool serverNegoMessage2(char* buf, int maxSize, char* szAlg, char* szChallenge)
//  server phase 2  server-->client:
//      serverMsg2(Principal cert requests, challenge)--Encrypted after this
{
    sprintf(buf, szMsg2, szAlg, szChallenge);
    return true;
}
#else
bool serverNegoMessage2(char* buf, int maxSize, char* szAlg, 
                         char* szChallenge, char* szHash)
//  server phase 2  server-->client:
//      serverMsg2(Principal cert requests, challenge)--Encrypted after this
{
    sprintf(buf, szMsg2, szAlg, szChallenge, szHash);
    return true;
}
#endif


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
    pNode= Search((TiXmlNode*) pRootElement, (char*)"Random");
    if(pNode==NULL)
        return false;
    pNode1= pNode->FirstChild();
    if(pNode1==NULL)
        return false;
    char*   szRandom= (char*) pNode1->Value();
    if(szRandom==NULL)
        return false;

    if(!fromBase64(strlen(szRandom), szRandom, &iOutLen, 
                                     (byte*)oKeys.m_rguClientRand)) {
        fprintf(g_logFile, "getDatafromClientMessage1: Cant base64 decode random number\n");
        return false;
    }
    oKeys.m_fClientRandValid= true;

    pNode= Search((TiXmlNode*) pRootElement, (char*)"CipherSuites");
    if(pNode==NULL)
        return false;

    pNode1= pNode->FirstChild();
    int         iIndex= -1;
    TiXmlNode*  pNode2= NULL;
    char*       szProposedSuite= NULL;

    while(pNode1) {
         if(pNode1->Type()==TiXmlNode::TINYXML_ELEMENT) {
            if(strcmp(((TiXmlElement*)pNode1)->Value(),"CipherSuite")==0) {
                pNode2= ((TiXmlElement*)pNode1)->FirstChild();
                if(pNode2) {
                    szProposedSuite= (char*)((TiXmlElement*)pNode2)->Value();
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
    char*           szEncryptedPreMasterSecret= NULL;
    char*           szSig= NULL;
    char*           szClientCert= NULL;
    bool            fRet= true;

#ifdef  TEST
    fprintf(g_logFile, "Client Message 2\n%s\n", request);
    fflush(g_logFile);
#endif
    try {
        if(!doc.Parse(request))
            throw((char*)"getDatafromClientMessage2: parse failure\n");

        pRootElement= doc.RootElement();
        if(pRootElement==NULL)
            throw((char*)"getDatafromClientMessage2: No root element\n");
        pNode= Search((TiXmlNode*) pRootElement, (char*)"EncryptedPreMasterSecret");
        if(pNode==NULL)
            throw((char*)"getDatafromClientMessage2: No EncPreMaster\n");
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw((char*)"getDatafromClientMessage2: No encryptedPreMaster\n");
        szEncryptedPreMasterSecret= (char*) pNode1->Value();
        if(szEncryptedPreMasterSecret==NULL)
            throw((char*) "getDatafromClientMessage2: Cant find encrypted pPreMaster secret");
        if(!fromBase64(strlen(szEncryptedPreMasterSecret), szEncryptedPreMasterSecret, 
                       &iOutLen, (byte*)oKeys.m_rguEncPreMasterSecret))
            throw((char*)"getDatafromClientMessage2: Cant base64 decode pre-master secret\n");
        oKeys.m_fEncPreMasterSecretValid= true;
    
        pNode= Search((TiXmlNode*) pRootElement, (char*)"ClientCertificate");
        if(pNode==NULL)
            throw((char*)"getDatafromClientMessage2: Cant get Client Certificate\n");
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw((char*)"getDatafromClientMessage2: Cant get Client Certificate\n");
        szClientCert= canonicalize(pNode1);
        if(szClientCert==NULL)
            throw((char*)"getDatafromClientMessage2: Cant canonicalize Client Certificate\n");
        oKeys.m_szXmlClientCert= szClientCert;
        oKeys.m_pclientCert= new PrincipalCert();
        if(!oKeys.m_pclientCert->init(szClientCert)) 
            throw((char*)"getDatafromClientMessage2: Cant initialize client certificate\n");
        if(!oKeys.m_pclientCert->parsePrincipalCertElements()) 
            throw((char*)"getDatafromClientMessage2: Cant parse client certificate\n");
        oKeys.m_pclientPublicKey= (RSAKey*)oKeys.m_pclientCert->getSubjectKeyInfo();
        if(oKeys.m_pclientPublicKey==NULL)
            throw((char*)"getDatafromClientMessage2: Cant init client public RSA key\n");
        oKeys.m_fClientCertValid= true;
    }
    catch(char* szError) {
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
    int             iOutLen= BIGSIGNEDSIZE;
    char*           szSignedChallenge= NULL;
    bool            fRet= true;

#ifdef  TEST
    fprintf(g_logFile, "getDatafromClientMessage 3\n%s\n", request);
    fflush(g_logFile);
#endif

    try {
        if(!doc.Parse(request))
            throw((char*)"getDatafromClientMessage3: parse failure\n");

        pRootElement= doc.RootElement();
        if(pRootElement==NULL)
            throw((char*)"getDatafromClientMessage3: No root element\n");

        pNode= Search((TiXmlNode*) pRootElement, (char*)"SignedChallenge");
        if(pNode==NULL)
            throw((char*)"getDatafromClientMessage3: No Signed Challenge\n");
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw((char*)"getDatafromClientMessage3: No Signed Challenge value\n");
        szSignedChallenge= (char*) pNode1->Value();
        if(szSignedChallenge==NULL)
            throw((char*) "getDatafromClientMessage3: Cant extract szSignedChallenge");

        oKeys.m_szbase64SignedMessageHash= strdup(szSignedChallenge);
        oKeys.m_fbase64SignedMessageHashValid= true;

        if(!fromBase64(strlen(szSignedChallenge), szSignedChallenge, 
                       &oKeys.m_sizeSignedMessage, oKeys.m_rgSignedMessage))
            throw((char*)"getDatafromClientMessage3: Cant base64 decode signed hash \n");
        oKeys.m_fSignedMessageValid= true;
    
    }
    catch(char* szError) {
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
    pNode= Search((TiXmlNode*) pRootElement, (char*)"EvidenceCollection");
    if(pNode==NULL) {
        fprintf(g_logFile, "getDatafromClientMessage4: no Principal EvidenceCollection tag\n");
        return false;
    }
    ((TiXmlElement*) pNode)->QueryIntAttribute("count", &oKeys.m_iNumPrincipals);
    pNode1= pNode->FirstChild();
    if(pNode1!=NULL) {
        oKeys.m_szPrincipalCerts= canonicalize(pNode);
    }

    pNode= Search((TiXmlNode*) pRootElement, (char*)"SignedChallenges");
    if(pNode!=NULL) {
        oKeys.m_szSignedChallenges= canonicalize(pNode);
    }

    return true;
}


// ------------------------------------------------------------------------


bool fileServer::initSafeChannel(int fd, safeChannel& fc, sessionKeys& oKeys)
{
    return fc.initChannel(fd, AES128, CBCMODE, HMACSHA256, 
                          AES128BYTEKEYSIZE, AES128BYTEKEYSIZE,
                          oKeys.m_rguEncryptionKey2, oKeys.m_rguIntegrityKey2, 
                          oKeys.m_rguEncryptionKey1, oKeys.m_rguIntegrityKey1);
}


bool fileServer::protocolNego(int fd, safeChannel& fc, sessionKeys& oKeys)
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
    fprintf(g_logFile, "fileServer::protocolNego\n");
#endif
    m_serverState= KEYNEGOSTATE;
    request[0]= '\0';

    try {

        // init message hash
        if(!oKeys.initMessageHash())
            throw((char*) "fileClient::protocolNego: Can't init message hash");

        // Phase 1, receive
        if((n=getPacket(fd, (byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw((char*) "fileServer::protocolNego: Can't get packet 1\n");
        if(!oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw((char*) "fileClient::protocolNego: Can't update messagehash");
        if(!getDatafromClientMessage1(n, request, oKeys))
            throw((char*) "fileServer::protocolNego: Can't decode client message 1\n");
        iOut64= 256;
        if(!getBase64Rand(SMALLNONCESIZE, oKeys.m_rguServerRand, &iOut64, rgszBase64))
            throw((char*) "fileServer::protocolNego: Can't generate first nonce\n");
        oKeys.m_fServerRandValid= true;
#ifdef TEST1
        fprintf(g_logFile, "fileServer: got client rand\n");
        fflush(g_logFile);
#endif

        // Phase 1, send
        if(oKeys.m_szXmlServerCert==NULL)
            throw((char*)"fileServer::protocolNego: No server Certificate\n");
        if(!serverNegoMessage1(request, MAXREQUESTSIZE, oKeys.m_iSessionId,
                               oKeys.m_szChallengeSignAlg, rgszBase64, oKeys.m_szXmlServerCert))
            throw((char*) "fileServer::protocolNego: Can't format negotiation message 1\n");
        if(!oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw((char*) "fileClient::protocolNego: Can't update messagehash");
        if((n=sendPacket(fd, (byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw((char*) "fileServer::protocolNego: Can't send packet 1\n");

        // Phase 2, receive
        if((n=getPacket(fd, (byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw((char*) "fileServer::protocolNego: Can't get packet 2\n");
        if(!oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw((char*) "fileClient::protocolNego: Can't update messagehash");
        if(!getDatafromClientMessage2(n, request, oKeys))
            throw((char*) "fileServer::protocolNego: Can't decode client message 2\n");
        if(!oKeys.clientcomputeMessageHash())
            throw((char*)"fileServer::protocolNego: client cant compute message hash");
        if(!oKeys.computeServerKeys()) 
            throw((char*) "fileServer::protocolNego: Cant compute channel keys\n");
#ifdef TEST
        fprintf(g_logFile, "fileServer: computed server keys\n");
        fflush(g_logFile);
#endif

        // Phase 3, receive
        if((n=getPacket(fd, (byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw((char*) "fileServer::protocolNego: Can't get packet 3\n");
        if(!getDatafromClientMessage3(n, request, oKeys))
            throw((char*) "fileServer::protocolNego: Can't decode client message 3\n");
        if(!oKeys.checkclientSignedHash())
            throw((char*)"fileServer::protocolNego: client signed message hash does not match");
        if(!oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw((char*) "fileClient::protocolNego: Can't update messagehash");
        if(!oKeys.servercomputeMessageHash())
            throw((char*)"fileServer::protocolNego: can't compute server hash");

        // init safeChannel
        if(!initSafeChannel(fd, fc, oKeys))
            throw((char*) "fileServer::protocolNego: Cant init channel\n");

        // Assume CBC
        if((n=sendPacket(fd, fc.lastsendBlock, AES128BYTEBLOCKSIZE, CHANNEL_NEGO_IV, 0, 1))<0)
            throw((char*)"fileServer::protocolNego: Cant send IV\n");
        fc.fsendIVSent= true;
        if((n=getPacket(fd, fc.lastgetBlock, AES128BYTEBLOCKSIZE, &type, &multi, &final))<0)
            throw((char*)"fileServer::protocolNego: Cant get IV\n");
        fc.fgetIVReceived= true;

#ifdef  TEST
        fprintf(g_logFile, "fileServer::protocolNego: Encrypted mode on\n");
        fflush(g_logFile);
#endif

        // Phase 2, send
        iOut= 256;
        if(!getBase64Rand(SMALLNONCESIZE, oKeys.m_rguChallenge, &iOut, rgszBase64)) 
            throw((char*) "fileServer::protocolNego: Can't generate principal challenge\n");
        oKeys.m_fChallengeValid= true;
#if 0
        if(!serverNegoMessage2(request, MAXREQUESTSIZE, oKeys.m_szChallengeSignAlg, rgszBase64))
            throw((char*) "fileServer::protocolNego: Can't format negotiation message 2\n");
#else
        // compute szHash string
        iOut= 256;
        if(!toBase64(SHA256DIGESTBYTESIZE, oKeys.m_rgServerMessageHash, 
                      &iOut, rgszHashBase64))
            throw((char*) "fileServer::protocolNego: Can't base64 encode server hash\n");
        if(!serverNegoMessage2(request, MAXREQUESTSIZE, oKeys.m_szChallengeSignAlg, 
                               rgszBase64, rgszHashBase64))
            throw((char*) "fileServer::protocolNego: Can't format negotiation message 2\n");
#endif
        if((n=fc.safesendPacket((byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw((char*) "fileServer::protocolNego: Can't safesendPacket 2\n");
#ifdef TEST
        fprintf(g_logFile, "fileServer::protocolNego: client signed message hash matches\n");
        fflush(g_logFile);
#endif

        // Phase 4, receive
        if((n=fc.safegetPacket((byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw((char*) "fileServer::protocolNego: Can't get packet 4\n");
        if(!oKeys.updateMessageHash(strlen(request), (byte*) request))
            throw((char*) "fileClient::protocolNego: Can't update messagehash");
        if(!getDatafromClientMessage4(n, request, oKeys)) 
            throw((char*) "fileServer::protocolNego: Can't decode client message 3\n");
        if(!oKeys.initializePrincipalCerts())
            throw((char*)"fileServer::protocolNego: Cant initialize principal public keys\n");
        if(!oKeys.checkPrincipalChallenges())
            throw((char*)"fileServer::protocolNego: Principal challenges fail\n");
#ifdef TEST1
        fprintf(g_logFile, "fileServer: checked principal challenges\n");
        fflush(g_logFile);
#endif

        // Phase 4, send
        if(!serverNegoMessage3(request, MAXREQUESTSIZE, true))
            throw((char*) "fileServer::protocolNego: Can't format negotiation message 3\n");
        if((n=fc.safesendPacket((byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw((char*) "fileServer::protocolNego: Can't send packet 3\n");
#ifdef TEST1
        fprintf(g_logFile, "fileServer: success packet sent\n");
        fflush(g_logFile);
#endif
    }
    catch(char* szError) {
        fprintf(g_logFile, "%s",szError);
        fRet= false;
        return false;
    }

    oKeys.validateChannelData(false);
#ifdef TEST
        fprintf(g_logFile, "fileServer: protocol data validated\n");
        fflush(g_logFile);
#endif

    // register principals
    if(oKeys.m_pserverCert!=NULL) {
        if(registerPrincipalfromCert(oKeys.m_pserverCert)==NULL)
            throw((char *)"fileServer::protocolNego: Can't register server principal\n");
    }

    if(oKeys.m_pclientCert!=NULL) {
        if(registerPrincipalfromCert(oKeys.m_pclientCert)==NULL)
            throw((char *)"fileServer::protocolNego: Can't register client principal\n");
    }
#ifdef TEST
        fprintf(g_logFile, "fileServer: protocol negotiation complete\n");
        oKeys.printMe();
        fflush(g_logFile);
#endif

    m_serverState= REQUESTSTATE;

    return fRet;
}


int fileServer::processRequests(safeChannel& fc, sessionKeys& oKeys, accessGuard& oAG)
{
    byte    request[MAXREQUESTSIZEWITHPAD];
    int     type= 0;
    byte    multi= 0;
    byte    final= 0;
    int     encType= NOENCRYPT;
    byte*   key= NULL;

#ifdef  TEST
    fprintf(g_logFile, "\n\nfileServer: processRequest\n");
#endif
    m_serverState= REQUESTSTATE;

    if(fc.safegetPacket(request, MAXREQUESTSIZE, &type, &multi, &final)<(int)sizeof(packetHdr)) {
        fprintf(g_logFile, (char*) "fileServer::processRequests: Can't get ProcessRequest packet\n");
        return -1;
    }

#ifdef  TEST
    fprintf(g_logFile, "fileServer::processRequests: packetType %d, serverstate %d\n", type, m_serverState);
#endif
    if(type==CHANNEL_TERMINATE) {
        return 0;
    }
    if(type!=CHANNEL_REQUEST) {
        fprintf(g_logFile, (char*)"fileServer::processRequests: Not a channel request\n");
        return -1;
    }

    if(m_fEncryptFiles) {
        if(!m_fKeysValid) {
            fprintf(g_logFile, (char*)"fileServer::processRequests: Encryption enabled but key invalid\n");
            return -1;
        }
        encType= DEFAULTENCRYPT;
        key= m_fileKeys;
    }

    int     iRequestType= 0;
    {
        Request oReq;

        oReq.m_poAG= &oAG;
        if(!oReq.getDatafromDoc((char*)request)) {
            fprintf(g_logFile, "fileServer::processRequests: cant parse: %s\n", request);
            fprintf(g_logFile, (char*)"Cant parse request\n");
            return -1;
        }
        iRequestType= oReq.m_iRequestType;
        if(oReq.m_szResourceName==NULL) {
            fprintf(g_logFile, (char*)"fileServer::processRequests: Empty resource name\n");
            return -1;
        }

        switch(iRequestType) {
          case GETRESOURCE:
            if(!serversendResourcetoclient(fc, oReq,  oKeys, encType, key)) {
                fprintf(g_logFile, (char*)"serversendResourcetoclient failed 1\n");
                return -1;
            }
            return 1;
          case SENDRESOURCE:
            if(!servergetResourcefromclient(fc, oReq,  oKeys, encType, key)) {
                fprintf(g_logFile, (char*)"servercreateResourceonserver failed\n");
                return -1;
            }
            return 1;
          case CREATERESOURCE:
            if(!servercreateResourceonserver(fc, oReq,  oKeys, encType, key)) {
                fprintf(g_logFile, (char*)"servercreateResourceonserver failed\n");
                return -1;
            }
            return 1;
          case ADDOWNER :
            if(!serverchangeownerofResource(fc, oReq,  oKeys, encType, key)) {
                fprintf(g_logFile, (char*)"serveraddownertoResourcefailed\n");
                return -1;
            }
            return 1;
          case REMOVEOWNER:
            if(!serverchangeownerofResource(fc, oReq,  oKeys, encType, key)) {
                fprintf(g_logFile, (char*)"serverremoveownerfromResource failed\n");
                return -1;
            }
            return 1;
          case DELETERESOURCE:
          case GETOWNER:
          default:
            fprintf(g_logFile, (char*)"fileServer::processRequests: invalid request type\n");
            return -1;
        }
    }
}


void SigCatcher(int n)
{
    int status= 0;

    if(n==SIGCHLD)
        wait3(&status, WNOHANG, NULL);
    if(n==SIGUSR1)
        g_fTerminateServer= true;
}


bool fileServer::serviceChannel(int fd)
{
    sessionKeys     oKeys;
    safeChannel     fc;
    accessGuard     oAG;
    int             n= 0;

#ifdef  TEST
    fprintf(g_logFile, "fileServer::serviceChannel\n");
    fflush(g_logFile);
#endif

    // Initialize program private key and certificate for session
    if(!m_tcHome.m_privateKeyValid ||
           !oKeys.getMyProgramKey((RSAKey*)m_tcHome.m_privateKey)) {
        fprintf(g_logFile, (char*)"fileServer::serviceChannel: Cant get my private key\n");
        return false;
    }
    if(!m_tcHome.m_myCertificateValid ||
           !oKeys.getMyProgramCert((char*)m_tcHome.m_myCertificate)) {
        fprintf(g_logFile, (char*)"fileServer::serviceChannel: Cant get my Cert\n");
        return false;
    }

    // copy my public key into server public key
    if(!m_tcHome.m_myCertificateValid ||
           !oKeys.getServerCert((char*)m_tcHome.m_myCertificate)) {
        fprintf(g_logFile, (char *)"fileServer::serviceChannel: Cant load client public key structures\n");
        return false;
    }

    if(!protocolNego(fd, fc, oKeys))
        return false;

#ifdef  TEST
    fprintf(g_logFile, "fileServer::serviceChannel, about to init guard\n");
    fflush(g_logFile);
#endif
    // Access Guard valid?
    if(!oAG.m_fValid) {
        if(!oAG.initChannelAccess(oKeys.m_iNumPrincipals, oKeys.m_rgPrincipalCerts)) {
            fprintf(g_logFile, "Request::validateRequest: initAccessGuard returned false\n");
            return false;
        }
    }

    m_serverState= REQUESTSTATE;
    while((n=processRequests(fc, oKeys, oAG))!=0) {
        if(n<0)
            fprintf(g_logFile, "fileServer::serviceChannel: processRequest error\n");
        fflush(g_logFile);
#ifdef METADATATEST
        void metadataTest(char* szDir, m_fEncryptFiles, m_fileKeys);
        metadataTest(m_tcHome.m_fileNames.m_szdirectory);
#endif
    }
    m_serverState= SERVICETERMINATESTATE;

#ifdef  TEST
    fprintf(g_logFile, "fileServer: serviceChannel terminating\n");
#endif
    return true;
}


bool fileServer::server()
{
    int                 fd, newfd;
    int                 childpid;
    struct sockaddr_in  server_addr, client_addr;
    int                 slen= sizeof(struct sockaddr_in);
    int                 clen= sizeof(struct sockaddr);
    int                 iError;

    fd= socket(AF_INET, SOCK_STREAM, 0);
    if(fd<0) {
        fprintf(g_logFile, (char*)"fileServer::server: Can't open socket\n");
        return false;
    }
#ifdef  TEST
    fprintf(g_logFile, "fileServer::server: socket opened\n");
    fflush(g_logFile);
#endif

    memset((void*) &server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family= AF_INET;
    server_addr.sin_addr.s_addr= htonl(INADDR_ANY);     // 127.0.0.1
    server_addr.sin_port= htons(SERVICE_PORT);

    iError= bind(fd,(const struct sockaddr *) &server_addr, slen);
    if(iError<0) {
        fprintf(g_logFile, (char*)"Can't bind socket: %s", strerror(errno));
        return false;
    }
#ifdef  TEST
    fprintf(g_logFile, "fileServer::server: bind succeeded\n");
    fflush(g_logFile);
#endif

    listen(fd, iQueueSize);

    // no zomies, please
    signal(SIGCHLD, (void (*)(int)) SigCatcher);
    signal(SIGUSR1, (void (*)(int)) SigCatcher);

    for(;;) {
        newfd= accept(fd, (struct sockaddr*) &client_addr, (socklen_t*)&clen);
        if(newfd<0) {
            fprintf(g_logFile, (char*)"Can't accept socket", strerror(errno));
            return false;
        }
#ifdef  TEST
        fprintf(g_logFile, "fileServer: accept succeeded\n");
        fflush(g_logFile);
#endif

        if((childpid=fork())<0) {
            close(fd);
            fprintf(g_logFile, (char*)"fileServer::server: Can't fork in server()");
            return false;
        }

        if(childpid==0) {
#ifdef  TEST
            fprintf(g_logFile, "fileServer::server: in child\n");
#endif
            m_serverState= INITSTATE;
            if(!serviceChannel(newfd)) {
                close(newfd);
                break;
            }
            // save metadata?
            close(newfd);
            fflush(g_logFile);
        }

    if(g_fTerminateServer)
        break;
    }

    close(fd);
    fflush(g_logFile);
    return true;
}


// --------------------------------------------------------------------------


int main(int an, char** av)
// fileServer.exe [-initKeys address-of-managementserver]
{
    fileServer  oServer;
    int         i;
    int         iRet= 0;
    bool        fInit= false;
    bool        fInitProg= false;
    char*   directory= NULL;


    initLog(NULL);
#ifdef TEST
    fprintf(g_logFile, "fileServer main: fileServer started\n");
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
        fprintf(g_logFile, "fileServer main: start measured program %s\n", av[0]);
#endif
        if(!startMeAsMeasuredProgram(an, av)) {
#ifdef TEST
            fprintf(g_logFile, "fileServer main: measured program failed, exiting\n");
#endif
            return 1;
        }
#ifdef TEST
        fprintf(g_logFile, "fileServer main: measured program started\n");
#endif
        return 0;
    }

    initLog((char*)"fileServer.log");
#ifdef TEST
        fprintf(g_logFile, "fileServer main: measured server about to init server\n");
        fflush(g_logFile);
#endif

    try {

        g_policyPrincipalCert= new PrincipalCert();
        if(g_policyPrincipalCert==NULL)
            throw((char*)"fileServer main: failed to new Principal\n");

        if(!oServer.initServer(directory)) 
            throw((char*)"fileServer main: cant initServer\n");

#ifdef TEST
        fprintf(g_logFile, "fileServer main: measured server entering server loop\n");
        fflush(g_logFile);
#endif
            oServer.server();
        }
    catch(char* szError) {
        fprintf(g_logFile, "%s", szError);
        iRet= 1;
    }

    oServer.closeServer();
    closeLog();
    return iRet;
}


// ------------------------------------------------------------------------


#ifdef TEST

#if METADATATEST
void metadataTest(char* szDir, bool fEncrypt, byte* keys)
{
    int     encType;
    if(fEncrypt) {
        encType= DEFAULTENCRYPT;
    }
    else {
        encType= NOENCRYPT;
    }

    if(g_theVault.saveMetaData(encType, keys)) {
        fprintf(g_logFile, (char*)"fileServer::serviceChannel: save succeeds\n");
        fflush(g_logFile);
    }
    else {
        fprintf(g_logFile, (char*)"fileServer::serviceChannel: save fails\n");
        fflush(g_logFile);
    }
    metaData localVault;

    if(!localVault.initMetaData(szDir, (char*)"fileServer")) {
        fprintf(g_logFile, "fileServer::localInit: Cant init local metadata\n");
        fflush(g_logFile);
    }
    if(!localVault.initFileNames()) {
        fprintf(g_logFile, "fileServer::localInit: Cant init file names\n");
        fflush(g_logFile);
        return;
    }
    if(!localVault.restoreMetaData(encType, keys)) {
        fprintf(g_logFile, "fileServer::localInit: Cant init file names\n");
        fflush(g_logFile);
        return;
    }

    fprintf(g_logFile, "fileServer::localInit: printing tables\n");
    fflush(g_logFile);
    printResources(localVault.m_pRM);
    printPrincipals(localVault.m_pPM);
    fflush(g_logFile);
}
#endif


void printResources(objectManager<resource>* pRM)
{
    int     i;

    fprintf(g_logFile, "%d resources\n", pRM->numObjectsinTable());
    for(i=0; i<pRM->numObjectsinTable(); i++) {
        pRM->getObject(i)->printMe();
        fprintf(g_logFile, "\n");
    }
    fprintf(g_logFile, "\n");
}


void printPrincipals(objectManager<accessPrincipal>* pPM)
{
    int     i;

    fprintf(g_logFile, "%d principals\n", pPM->numObjectsinTable());
    for(i=0; i<pPM->numObjectsinTable(); i++) {
        pPM->getObject(i)->printMe();
        fprintf(g_logFile, "\n");
    }
    fprintf(g_logFile, "\n");
}
#endif


// ------------------------------------------------------------------------




