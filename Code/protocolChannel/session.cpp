//  File: session.cpp
//  Description: cloudProxy channel for client and server
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


#include "jlmTypes.h"
#include "logging.h"
#include "jlmcrypto.h"
#include "keys.h"
#include "session.h"
#include "jlmUtility.h"
#include "modesandpadding.h"
#include "cryptoHelper.h"
#include "validateEvidence.h"
#include "mpFunctions.h"
#include "tinyxml.h"
#include "channelstate.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>


// ------------------------------------------------------------------------


session::session()
{
    m_fClient= false;
    m_iSessionId= 0;
    m_sessionState= NOSTATE;

    m_myCertValid= false;
    m_myCert= NULL;

    m_myProgramKeyValid= false;
    m_myProgramKey= NULL;

    m_policyKey= NULL;
    m_policyCertValid= false;
    m_sizepolicyCert= 0;
    m_szpolicyCert= NULL;

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
    m_sizeSignedMessage= GLOBALMAXPUBKEYSIZE;

    m_pclientCert= NULL;
    m_pserverCert= NULL;

    m_pclientPublicKey= NULL;
    m_pserverPublicKey= NULL;

    m_szXmlClientCert= NULL;
    m_szXmlServerCert= NULL;

    m_szSuite= NULL;
    m_szChallengeSignAlg= NULL;
    m_szChallenge= NULL;
    m_szSignedChallenges= NULL;
    m_szChallengeSignAlg= strdup("TLS_RSA1024_WITH_AES128_CBC_SHA256");
}


session::~session()
{
    clearKeys();
}


// -----------------------------------------------------------------------------


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


const char*  g_szTerm= "terminate channel\n";


// Server Nego Messages
const char* szMsg1a= "<ServerNego phase='1' sessionId='%d'>\n <Random size='32'>"\
  "%s</Random>\n<CipherSuite> %s </CipherSuite>\n<ServerCertificate>\n";
const char* szMsg1b= "</ServerCertificate>\n</ServerNego>\n";

const char* szMsg2= 
  "<ServerNego phase='2'>\n <RequestAuthentication Algorithm='%s'/>\n"\
  "<Challenge size='32'>%s</Challenge>\n" \
  "<Hash>%s</Hash>\n</ServerNego>\n";

const char* szMsg3Pass=
  "<ServerNego phase='3'>\n <Status>Succeed</Status>\n</ServerNego>\n";
const char* szMsg3Fail=
  "<ServerNego phase='3'\n ><Status> Fail </Status>\n</ServerNego>\n";


// Client Nego Messages
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

const char* szMsg4aa= 
"<ClientNego phase='4'>\n"\
"  <EvidenceCollection count='0'/>\n"\
"  <SignedChallenges count='0'/>";
const char* szMsg4a= "<ClientNego phase='4'>\n";
const char* szMsg4d= "\n</ClientNego>\n"; 


// ------------------------------------------------------------------------


bool session::serverNegoMessage1(char* buf, int maxSize, int iSessionId, 
                                 const char* szAlg, const char* szRand, 
                                 const char* szServerCert)
//  server phase 1  server-->client:
//      serverMsg1(rand, ciphersuite, server-cert)
{
    int     iLeft= maxSize;
    char*   p= buf;
    int     i= 0;

    if(((int)(strlen(szMsg1a)+strlen(szRand)+strlen(szAlg)+8))>maxSize) {
        fprintf(g_logFile, "serverNegoMessage1: message too large\n");
        return false;
    }
    sprintf(buf, szMsg1a, iSessionId, szRand, szAlg);
    i= strlen(buf);
    p+= i;
    iLeft-= i;
    if(!safeTransfer(&p, &iLeft, szServerCert))
        return false;
    if(!safeTransfer(&p, &iLeft, szMsg1b))
        return false;

#ifdef TEST1
    fprintf(g_logFile, "serverNegoMessage1: %s\n", buf);
#endif
    return true;
}


bool session::serverNegoMessage2(char* buf, int maxSize, const char* szAlg, 
                         const char* szChallenge, const char* szHash)
//  server phase 2  server-->client: serverMsg2(Principal cert requests, challenge)
//         --Encrypted after this
{
#ifdef TEST1
    fprintf(g_logFile, "serverNegoMessage2: %s\n", buf);
#endif
    if(((int)(strlen(szMsg2)+strlen(szChallenge)+strlen(szAlg)+strlen(szHash)+4))
            >maxSize) {
        fprintf(g_logFile, "serverNegoMessage2: message too large\n");
        return false;
    }
    sprintf(buf, szMsg2, szAlg, szChallenge, szHash);
    return true;
}


bool session::serverNegoMessage3(char* buf, int maxSize, bool fSucceed)
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
#ifdef TEST1
    fprintf(g_logFile, "serverNegoMessage3: %s\n", buf);
#endif
    return true;
}


bool session::clientNegoMessage1(char* buf, int maxSize, const char* szAlg, const char* szRand)
//  client phase 1  client-->server: clientMsg1(rand, ciphersuites)
{
    if(((int)(strlen(szMsg1)+strlen(szRand)+strlen(szAlg)+4))>maxSize) {
        fprintf(g_logFile, "clientNegoMessage1: message too large\n");
        return false;
    }
    sprintf(buf,szMsg1, szRand, szAlg);
#ifdef TEST1
    fprintf(g_logFile, "clientNegoMessage1: %s\n", buf);
#endif
    return true;
}


bool session::clientNegoMessage2(char* buf, int maxSize, const char* szEncPreMasterSecret, 
                                   const char* szClientCert, int iSessionId)
//  client phase 2  client-->server: clientMsg2(E_S(premaster), D_C(rand1||rand2), client-cert)
{
    int     iLeft= maxSize;
    char*   p= buf;
    int     i= 0;

    if(((int)(strlen(szMsg2a)+8))>maxSize) {
        fprintf(g_logFile, "clientNegoMessage1: message too large\n");
        return false;
    }
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

#ifdef TEST1
    fprintf(g_logFile, "clientNegoMessage2: %s\n", buf);
#endif
    return true;
}


bool session::clientNegoMessage3(char* buf, int maxSize, const char* szSignedHash)
//  client phase 3  client-->server: clientMsg2(signed hash)
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

#ifdef TEST1
    fprintf(g_logFile, "clientNegoMessage3: %s\n", buf);
#endif
    return true;
}


bool session::clientNegoMessage4(char* buf, int maxSize, const char* szPrincipalCerts,
                           int principalCount, const char* szSignedChallenges)
//  client phase 4  client-->server: clientMsg4(Principal-certs, D_P1(challenge), D_P2(challenge+1),... )
{
    int     iLeft= maxSize;
    char*   p= buf;

#ifdef TEST1
    fprintf(g_logFile, 
            "clientNegoMessage4(%d), principals: %d\nCerts: %s\nSignedChallenges: %s\n",
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
    
#ifdef TEST1
    fprintf(g_logFile, "clientNegoMessage4: %s\n", buf);
#endif
    return true;
}


bool session::getDatafromServerMessage1(int n, char* request)
{
    TiXmlDocument   doc;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;
    TiXmlElement*   pRootElement= NULL;
    char*           szCipherSuite= NULL;
    const char*     szRandom= NULL;
    char*           szServerCert= NULL;
    const char*     szProposedSuite= NULL;
    int             iOutLen;
    int             iIndex= -1;
    bool            fRet= true;

#ifdef TEST1
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
        pRootElement->QueryIntAttribute("sessionId", &m_iSessionId);
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
        if(!fromBase64(strlen(szRandom), szRandom, &iOutLen, (byte*)m_rguServerRand)) 
            throw "getDatafromServerMessage1: Cant base64 decode random number\n";
        m_fServerRandValid= true;

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
        m_szSuite= strdup(szCipherSuite);

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
        m_szXmlServerCert= szServerCert;
        m_pserverCert= new PrincipalCert();
        if(!m_pserverCert->init(szServerCert))
            throw "getDatafromServerMessage1: Cant initialize server certificate\n";
        if(!m_pserverCert->parsePrincipalCertElements())
            throw "getDatafromServerMessage1: Cant parse client certificate\n";
        m_pserverPublicKey= (RSAKey*)m_pserverCert->getSubjectKeyInfo();
        if(m_pserverPublicKey==NULL)
            throw "getDatafromServerMessage1: Cant init client public RSA key\n";
        m_fServerCertValid= true;
    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "%s", szError);
    }

    return fRet;
}


// <RequestPrincipalCertificates/>
// <Challenge> </Challenge>
bool session::getDatafromServerMessage2(int n, char* request)
{
    TiXmlDocument   doc;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;
    TiXmlElement*   pRootElement= NULL;
    int             iOutLen;
    bool            fRet= true;

#ifdef  TEST1
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
            m_szChallengeSignAlg= strdup(p);

#ifdef  TEST1
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
        if(!fromBase64(strlen(szRandom), szRandom, &iOutLen, (byte*)m_rguChallenge))
            throw "getDatafromServerMessage2: Cant base64 decode random number\n";
        m_fChallengeValid= true;

        pNode= Search((TiXmlNode*) pRootElement, "Hash");
        if(pNode==NULL)
            throw "getDatafromServerMessage2: No hash element\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw "getDatafromServerMessage2: Bad hash element\n";
        m_szbase64ServerMessageHash= strdup( pNode1->Value());
        m_fbase64ServerMessageHashValid= true;
        if(m_szbase64ServerMessageHash==NULL)
            throw "getDatafromServerMessage2: No hash element\n";
        iOutLen= SHA256DIGESTBYTESIZE;
        if(!fromBase64(strlen(m_szbase64ServerMessageHash), 
                              m_szbase64ServerMessageHash, &iOutLen, 
                              (byte*)m_rgDecodedServerMessageHash))
            throw "getDatafromServerMessage2: Cant base64 decode hash\n";
        m_fDecodedServerMessageHashValid= true;
    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "%s", szError);
    }

    return fRet;
}


bool session::getDatafromServerMessage3(int n, char* request)
{
    TiXmlDocument   doc;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;
    TiXmlElement*   pRootElement= NULL;
    bool            fRet= true;

#ifdef  TEST1
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


// Client encode and decode messages

bool session::getDatafromClientMessage1(int n, char* request)
{
    TiXmlDocument   doc;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;
    int             iOutLen= SMALLNONCESIZE;

#ifdef  TEST1
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
                                     (byte*)m_rguClientRand)) {
        fprintf(g_logFile, "getDatafromClientMessage1: Cant base64 decode random number\n");
        return false;
    }
    m_fClientRandValid= true;

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
    m_szSuite= strdup(szCipherSuite);

    return true;
}


bool session::getDatafromClientMessage2(int n, char* request)
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;
    int             iOutLen= GLOBALMAXPUBKEYSIZE;
    const char*     szEncryptedPreMasterSecret= NULL;
    char*           szClientCert= NULL;
    bool            fRet= true;

#ifdef  TEST1
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
                       &iOutLen, (byte*)m_rguEncPreMasterSecret))
            throw "getDatafromClientMessage2: Cant base64 decode pre-master secret\n";
        m_fEncPreMasterSecretValid= true;
    
        pNode= Search((TiXmlNode*) pRootElement, "ClientCertificate");
        if(pNode==NULL)
            throw "getDatafromClientMessage2: Cant get Client Certificate\n";
        pNode1= pNode->FirstChild();
        if(pNode1==NULL)
            throw "getDatafromClientMessage2: Cant get Client Certificate\n";
        szClientCert= canonicalize(pNode1);
        if(szClientCert==NULL)
            throw "getDatafromClientMessage2: Cant canonicalize Client Certificate\n";
        m_szXmlClientCert= szClientCert;
        m_pclientCert= new PrincipalCert();
        if(!m_pclientCert->init(szClientCert)) 
            throw "getDatafromClientMessage2: Cant initialize client certificate\n";
        if(!m_pclientCert->parsePrincipalCertElements()) 
            throw "getDatafromClientMessage2: Cant parse client certificate\n";
        m_pclientPublicKey= (RSAKey*)m_pclientCert->getSubjectKeyInfo();
        if(m_pclientPublicKey==NULL)
            throw "getDatafromClientMessage2: Cant init client public RSA key\n";
        m_fClientCertValid= true;
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


bool session::getDatafromClientMessage3(int n, char* request)
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;
    const char*     szSignedChallenge= NULL;
    bool            fRet= true;

#ifdef  TEST1
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

        m_szbase64SignedMessageHash= strdup(szSignedChallenge);
        m_fbase64SignedMessageHashValid= true;

        if(!fromBase64(strlen(szSignedChallenge), szSignedChallenge, 
                       &m_sizeSignedMessage, m_rgSignedMessage))
            throw "getDatafromClientMessage3: Cant base64 decode signed hash \n";
        m_fSignedMessageValid= true;
    
    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "%s\n", szError);
    }

    return fRet;
}


bool session::getDatafromClientMessage4(int n, char* request)
// Principal certs, signed sequential challenges by principals
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;

#ifdef TEST1
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
    ((TiXmlElement*) pNode)->QueryIntAttribute("count", &m_iNumPrincipals);
    pNode1= pNode->FirstChild();
    if(pNode1!=NULL) {
        m_szPrincipalCerts= canonicalize(pNode);
    }

    pNode= Search((TiXmlNode*) pRootElement, "SignedChallenges");
    if(pNode!=NULL) {
        m_szSignedChallenges= canonicalize(pNode);
    }

    return true;
}


// ------------------------------------------------------------------------


bool bumpChallenge(int iSize, byte* puChallenge)
{
    int     ibnSize= ((iSize+sizeof(u64)-1)/sizeof(u64))*sizeof(u64);
    bnum    bnN(ibnSize);

    revmemcpy((byte*) bnN.m_pValue, puChallenge, iSize);
    mpInc(bnN);
    revmemcpy(puChallenge, (byte*) bnN.m_pValue, iSize);
    
    return true;
}


char* rsaXmlEncodeChallenge(bool fEncrypt, RSAKey& rgKey, byte* puChallenge, 
                            int sizeChallenge)
{
    int     iOut= GLOBALMAXPUBKEYSIZE;
    byte    rgSealed[GLOBALMAXPUBKEYSIZE];
    int     iBase64= 2*GLOBALMAXPUBKEYSIZE;
    char    rgBase64[2*GLOBALMAXPUBKEYSIZE];

#ifdef TEST1
    if(fEncrypt)
        fprintf(g_logFile, "rsaXmlEncodeChallenge, encrypt\n");
    else
        fprintf(g_logFile, "rsaXmlEncodeChallenge, decrypt\n");
    fflush(g_logFile);
#endif
    UNUSEDVAR(iBase64);
    if(fEncrypt) {
        if(!RSASeal(rgKey, USEPUBLIC, sizeChallenge, puChallenge, 
                    &iOut, rgSealed)) {
            fprintf(g_logFile, "rsaXmlEncryptandEncodeChallenge: encrypt failure\n");
            return NULL;
        }
    }
    else {
        if(!RSASeal(rgKey, USEPRIVATE, sizeChallenge, puChallenge, 
                    &iOut, rgSealed)) {
            fprintf(g_logFile, "rsaXmlEncryptandEncodeChallenge: encrypt failure\n");
            return NULL;
        }
    }
    iOut= 1024;
    if(!base64frombytes(rgKey.m_iByteSizeM, rgSealed, &iBase64, rgBase64)) {
        fprintf(g_logFile,
                "rsaXmlEncryptandEncodeChallenge: can't base64 encode challenge\n");
        return NULL;
    }

#ifdef TEST1
    PrintBytes("Encrypted challenge\n", rgSealed, rgKey.m_iByteSizeM);
#endif
    return strdup(rgBase64);
}


#define MAXPRINCIPALS 25
#define BIGSIGNEDSIZE 256

const char* szMsgChallenge1= "<SignedChallenges count='%d'>";
const char* szMsgChallenge2= "\n<SignedChallenge>";
const char* szMsgChallenge3= "\n</SignedChallenge>";
const char* szMsgChallenge4= "\n</SignedChallenges>\n";


#define MAXMSGHDR 128


char* rsaXmlEncodeChallenges(bool fEncrypt, int iNumKeys, RSAKey** rgKeys,
                             byte* puChallenge, int sizeChallenge) 
{
    int     i;
    char*   rgszSignedChallenges[MAXPRINCIPALS];
    byte    rguCurrentChallenge[GLOBALMAXPUBKEYSIZE];
    int     n= 0;
    char    szMsgHdr[MAXMSGHDR];
    int     iSC1;
    int     iSC2= strlen(szMsgChallenge2);
    int     iSC3= strlen(szMsgChallenge3);
    int     iSC4= strlen(szMsgChallenge4);

    memset(rguCurrentChallenge, 0, GLOBALMAXPUBKEYSIZE);
    memcpy(rguCurrentChallenge, puChallenge, sizeChallenge);

    if((strlen(szMsgHdr)+strlen(szMsgChallenge1)+8)>MAXMSGHDR) {
        fprintf(g_logFile, "rsaXmlEncodeChallenges: message too large\n");
        return false;
    }
    sprintf(szMsgHdr, szMsgChallenge1, iNumKeys);
    iSC1= strlen(szMsgHdr);
    
    for(i=0; i< iNumKeys; i++) {
#ifdef TEST1
        if(fEncrypt)
            fprintf(g_logFile, "rsaXmlEncodeChallenges key usepublic\n");
        else
            fprintf(g_logFile, "rsaXmlEncodeChallenges key use private\n");
        rgKeys[i]->printMe();
#endif
        rgszSignedChallenges[i]= rsaXmlEncodeChallenge(fEncrypt,
                *rgKeys[i], rguCurrentChallenge, sizeChallenge);
        if(rgszSignedChallenges[i]==NULL) {
            fprintf(g_logFile, "rsaXmlEncodeChallenges: Bad signed challenge %d\n", i);
            return NULL;
        }
        n+= strlen(rgszSignedChallenges[i]);
        if(i<(iNumKeys-1)) {
            if(!bumpChallenge(sizeChallenge, rguCurrentChallenge)) {
                fprintf(g_logFile, "rsaXmlEncodeChallenges: Can't bump challenge %d\n", i);
                return NULL;
            }
        }
    }

    // concatinate and return
    n+= iSC1+iSC4+iNumKeys*(iSC2+iSC3);
    char*   szReturn= (char*) malloc(n+1);
    char*   p= szReturn;
    int     iLeft= n+1;

    if(szReturn!=NULL) {

        if(!safeTransfer(&p, &iLeft, szMsgHdr))
            return NULL;

        for(i=0; i< iNumKeys; i++) {
            if(!safeTransfer(&p, &iLeft, szMsgChallenge2))
                return NULL;
            if(!safeTransfer(&p, &iLeft, rgszSignedChallenges[i]))
                return NULL;
            if(!safeTransfer(&p, &iLeft, szMsgChallenge3))
                return NULL;
            // free(rgszSignedChallenges[i]);
        }
        if(!safeTransfer(&p, &iLeft, szMsgChallenge4))
            return NULL;
        *p= 0;
    }
    
#ifdef TEST1
    fprintf(g_logFile, "Signed challenges: %s\n", szReturn);
#endif
    return szReturn;
}


bool rsaXmlDecryptandGetNonce(bool fEncrypt, RSAKey& rgKey, int sizein, byte* rgIn, 
                              int sizeNonce, byte* rgOut)

{
    int iOut= sizeNonce;

    if(fEncrypt) {
        if(!RSAUnseal(rgKey, USEPUBLIC, sizein, rgIn, &iOut, rgOut)) {
            return false;
        }
    }
    else {
        if(!RSAUnseal(rgKey, USEPRIVATE, sizein, rgIn, &iOut, rgOut)) {
            return false;
        }
    }
    return true;
}


bool rsaXmlDecodeandVerifyChallenge(bool fEncrypt, RSAKey& rgKey, const char* szSig,
                int sizeChallenge, byte* puOriginal)

{
    int     sizeunSealed= GLOBALMAXPUBKEYSIZE;
    byte    rgUnsealed[GLOBALMAXPUBKEYSIZE];
    int     iOut= GLOBALMAXPUBKEYSIZE;
    byte    rgBase64Decoded[GLOBALMAXPUBKEYSIZE];

#ifdef TEST1
    fprintf(g_logFile, "rsaXmlDecodeandVerifyChallenge: key\n");
    rgKey.printMe();
    fflush(g_logFile);
#endif
    if(!bytesfrombase64((char*)szSig, &iOut, rgBase64Decoded)) {
        fprintf(g_logFile, "rsaXmlDecodeandVerifyChallenge: cant base64 decode\n");
        return false;
    }

    if(fEncrypt) {
        if(!RSAUnseal(rgKey, USEPUBLIC, iOut, rgBase64Decoded, 
                      &sizeunSealed, rgUnsealed)) {
            fprintf(g_logFile, "rsaXmlDecodeandVerifyChallenge: cant seal\n");
            return false;
        }
    }
    else {
        if(!RSAUnseal(rgKey, USEPRIVATE, iOut, rgBase64Decoded, 
                      &sizeunSealed, rgUnsealed)) {
            fprintf(g_logFile, "rsaXmlDecodeandVerifyChallenge: cant unseal\n");
            return false;
        }
    }

    bool fRet= (memcmp(rgUnsealed, puOriginal, sizeChallenge)==0);
    return fRet;
}


// ------------------------------------------------------------------------

void session::clearKeys()
{
    memset(m_rgClientMessageHash, 0, SHA256DIGESTBYTESIZE); 
    memset(m_rgServerMessageHash,0, SHA256DIGESTBYTESIZE);
    memset(m_rguChallenge,0, SMALLNONCESIZE);
    memset(m_rguClientRand,0, SMALLNONCESIZE);
    memset(m_rguServerRand,0, SMALLNONCESIZE);
    memset(m_rguPreMasterSecret,0, PREMASTERSIZE);
    memset(m_rguEncPreMasterSecret,0, GLOBALMAXPUBKEYSIZE);
    memset(m_rguEncryptionKey1,0, GLOBALMAXSYMKEYSIZE);
    memset(m_rguIntegrityKey1,0, GLOBALMAXSYMKEYSIZE);
    memset(m_rguEncryptionKey2, 0, GLOBALMAXSYMKEYSIZE);
    memset(m_rguIntegrityKey2, 0, GLOBALMAXSYMKEYSIZE);

    if(m_myCert!=NULL) {
        free(m_myCert);
        m_myCert= NULL;
    }
    if(m_szXmlClientCert!=NULL) {
        free(m_szXmlClientCert);
        m_szXmlClientCert= NULL;
    }
    if(m_szXmlServerCert!=NULL) {
        free(m_szXmlServerCert);
        m_szXmlServerCert= NULL;
    }
    if(m_szpolicyCert!=NULL) {
        free(m_szpolicyCert);
        m_szpolicyCert= NULL;
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

    m_myProgramKey= NULL;
    m_policyKey= NULL;
}


bool session::getClientCert(const char* szXml)
{
#ifdef TEST1
    fprintf(g_logFile, "getClientCert\n");
    fflush(g_logFile);
#endif
    m_szXmlClientCert= strdup(szXml);
    if(m_szXmlClientCert==NULL) {
        fprintf(g_logFile, "session::getClientCert: Client cert string is null\n");
        return false;
    }
    
    m_pclientCert= new PrincipalCert();
    if(m_pclientCert==NULL) {
        fprintf(g_logFile, "session::getClientCert: Cant create client signature\n");
        return false;
    }
    if(!m_pclientCert->init(m_szXmlClientCert)) {
        fprintf(g_logFile, "session::getClientCert: Cant init client Cert\n");
        return false;
    }
    if(!m_pclientCert->parsePrincipalCertElements()) {
        fprintf(g_logFile, "session::getClientCert: Cant parsePrincipalCertElements\n");
        return false;
    }
    m_pclientPublicKey= (RSAKey*)m_pclientCert->getSubjectKeyInfo();
    if(m_pclientPublicKey==NULL) {
        fprintf(g_logFile, "session::getClientCert: Cant get client Subject Key\n");
        return false;
    }
    if(m_policyKey==NULL) {
        fprintf(g_logFile, "session::getClientCert: invalid policy key\n");
        return false;
    }
#ifdef TEST1
    fprintf(g_logFile, "session::getClientCert: Validating cert chain\n");
    fflush(g_logFile);
#endif

    // Validate cert chain
    int     rgType[2]= {PRINCIPALCERT, EMBEDDEDPOLICYPRINCIPAL};
    void*   rgObject[2]= {m_pclientCert, m_policyKey};

    int     iChain= VerifyChain(m_policyKey, "", NULL, 2, rgType, rgObject);
    if(iChain<0) {
        fprintf(g_logFile, "session::getClientCert: Invalid client certificate chain\n");
        return false;
    }
    m_fClientCertValid= true;

#ifdef TEST1
    fprintf(g_logFile, "session::getClientCert: Client Key\n");
    m_pclientPublicKey->printMe();
    fprintf(g_logFile, "\n");
    fflush(g_logFile);
#endif
    return true;
}


bool session::getServerCert(const char* szXml)
{
#ifdef  TEST1
    fprintf(g_logFile, "session::getServerCert\n");
    fflush(g_logFile);
#endif
    m_szXmlServerCert= strdup(szXml);
    if(m_szXmlServerCert==NULL)
        return false;
    m_pserverCert= new PrincipalCert();
    if(m_pserverCert==NULL) {
        fprintf(g_logFile, "session::getServerCert: Cant create server signature\n");
        return false;
    }
    if(!m_pserverCert->init(m_szXmlServerCert)) {
        fprintf(g_logFile, "session::getServerCert: Cant init server cert\n");
        return false;
    }
    if(!m_pserverCert->parsePrincipalCertElements()) {
        fprintf(g_logFile, "session::getServerCert: Cant parsePrincipalCertElements server cert\n");
        return false;
    }
    m_pserverPublicKey= (RSAKey*)m_pserverCert->getSubjectKeyInfo();
    if(m_pserverPublicKey==NULL) {
        fprintf(g_logFile, "Cant session::getServerCert: get server Subject Key\n");
        return false;
    }
#ifdef  TEST1
    fprintf(g_logFile, "session::getServerCert, server cert\n");
    m_pserverCert->printMe();
    fprintf(g_logFile, "session::getServerCert, policy key\n");
    m_policyKey->printMe();
    fflush(g_logFile);
#endif

    // Validate cert chain
    int     rgType[2]={PRINCIPALCERT, EMBEDDEDPOLICYPRINCIPAL};
    void*   rgObject[2]={m_pserverCert, m_policyKey};
    extern  bool revoked(const char*, const char*);
    int     iChain= VerifyChain(m_policyKey, "", NULL, 2, rgType, rgObject);

    if(iChain<0) {
        fprintf(g_logFile, "session::getServerCert: Invalid server certificate chain\n");
        return false;
    }
    m_fServerCertValid= true;
    
#ifdef TEST1
    fprintf(g_logFile, "session::getServerCert: Server public Key\n");
    m_pserverPublicKey->printMe();
    fprintf(g_logFile, "\n");
#endif
    return true;
}


bool session::initializePrincipalCerts(const char* szPrincipalCerts)
{
    int                 i;
    evidenceCollection  oEvidenceCollection;

    if(szPrincipalCerts==NULL) {
        m_iNumPrincipals= 0;
        m_fPrincipalCertsValid= true;
        return true;
    }

    m_szPrincipalCerts= strdup(szPrincipalCerts);

#ifdef TEST1
    if(m_szPrincipalCerts==NULL)
        fprintf(g_logFile, "initializePrincipalCerts is NULL\n");
    else
        fprintf(g_logFile, "initializePrincipalCerts:\n%s\n", m_szPrincipalCerts);
    fflush(g_logFile);
#endif
    if(!oEvidenceCollection.parseEvidenceCollection(szPrincipalCerts)) {
        fprintf(g_logFile, "session::initializePrincipalCerts: Cant parse Principal Public Keys\n");
        return false;
    }

    if(!oEvidenceCollection.validateEvidenceCollection(m_policyKey)) {
        fprintf(g_logFile,  "session::initializePrincipalCerts: Cannot validate Principal Public Keys\n");
        return false;
    }

    m_iNumPrincipals= oEvidenceCollection.m_iNumEvidenceLists;
    for(i=0; i<m_iNumPrincipals; i++) {
        if(oEvidenceCollection.m_iNumEvidenceLists<1 ||
                oEvidenceCollection.m_rgiCollectionTypes[0]!=PRINCIPALCERT) {
            fprintf(g_logFile, "session::initializePrincipalCerts: No Signed principal\n");
            return false;
        }

        // cert
        m_rgPrincipalCerts[i]= (PrincipalCert*)
                                 oEvidenceCollection.m_rgCollectionList[i]->m_rgEvidence[0];
        m_rgPrincipalPublicKeys[i]= (RSAKey*) (m_rgPrincipalCerts[i]->getSubjectKeyInfo());
    }

#ifdef TEST1
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


bool session::initializePrincipalPrivateKeys(const char* szPrincipalPrivateKeys)
{
    int             iNumKeys= 0;
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;

    if(szPrincipalPrivateKeys==NULL) {
        m_iNumPrincipalPrivateKeys= 0;
        m_fPrincipalPrivateKeysValid= true;
        return true;
    }

#ifdef TEST1
    fprintf(g_logFile, "Principal private keys\n%s\n", szPrincipalPrivateKeys);
    fflush(g_logFile);
#endif

    if(!doc.Parse(szPrincipalPrivateKeys)) {
        fprintf(g_logFile,  
           "session::initializePrincipalPrivateKeys: Cannot parse Principal Private Keys\n");
        return false;
    }

    pRootElement= doc.RootElement();
    if(strcmp(pRootElement->Value(),"PrivateKeys")!=0) {
        fprintf(g_logFile, 
            "session::initializePrincipalPrivateKeys: Should be list of private keys\n");
        return false;
    }
    pRootElement->QueryIntAttribute ("count", &iNumKeys);

#ifdef TEST1
    fprintf(g_logFile, "%d principal private keys\n", iNumKeys);
#endif

    if(iNumKeys>MAXPRINCIPALS) {
        fprintf(g_logFile, 
          "session::initializePrincipalPrivateKeys: Too many principal private keys\n");
        return false;
    }

    int iKeyList= 0;
    pNode= pRootElement->FirstChild();
    while(pNode) {
        if(pNode->Type()==TiXmlNode::TINYXML_ELEMENT) {
            if(strcmp(((TiXmlElement*)pNode)->Value(),"ds:KeyInfo")==0) {
                m_rgPrincipalPrivateKeys[iKeyList]= RSAKeyfromKeyInfoNode(pNode);
                if(m_rgPrincipalPrivateKeys[iKeyList]==NULL) {
                    fprintf(g_logFile, "session::initializePrincipalPrivateKeys: Cant init private key\n");
                    return false;
                }
                iKeyList++;
            }
        }
        pNode= pNode->NextSibling();
    }

    if(iKeyList!=iNumKeys) {
        fprintf(g_logFile, "session::initializePrincipalPrivateKeys: Count mismatch in private keys\n");
        return false;
    }

    m_iNumPrincipalPrivateKeys= iKeyList;
    m_fPrincipalPrivateKeysValid= true;
    return true;
}


bool session::initMessageHash()
{   
#ifdef TEST
    fprintf(g_logFile, "session::initMessageHash\n");
    fflush(g_logFile);
#endif
    m_oMessageHash.Init();
    return true;
}


bool session::updateMessageHash(int size, byte* buf)
{
#ifdef TEST
    fprintf(g_logFile, "session::updateMessageHash %d bytes\n", size);
    fflush(g_logFile);
#endif
    m_oMessageHash.Update(buf, size);
    return true;
}


bool session::clientcomputeMessageHash()
{
#ifdef TEST
    fprintf(g_logFile, "session::clientcomputeMessageHash\n");
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


bool session::clientsignMessageHash()
{
#ifdef TEST1
    fprintf(g_logFile, "session::clientsignMessageHash\n");
    fflush(g_logFile);
#endif

    if(!m_myProgramKeyValid || m_myProgramKey==NULL) {
        fprintf(g_logFile, "session::clientsignMessageHash: program key invalid\n");
        return false;
    }

    // Client signs Message hash
    if(!m_fClientMessageHashValid) {
        fprintf(g_logFile, "session::clientsignMessageHash: client message invalid\n");
        return false;
    }
    m_szbase64SignedMessageHash= rsaXmlEncodeChallenge(false, *m_myProgramKey, 
                                    m_rgClientMessageHash, SHA256DIGESTBYTESIZE);
    if(m_szbase64SignedMessageHash==NULL) {
        fprintf(g_logFile, "session::clientsignMessageHash: no base64SignedMessageHash\n");
        fflush(g_logFile);
        return false;
    }
    m_fbase64SignedMessageHashValid= true;
    return true;
}


bool session::checkclientSignedHash()
{
#ifdef TEST
    fprintf(g_logFile, "session::checkclientSignedHash\n");
    fflush(g_logFile);
#endif

    if(!m_fClientCertValid) {
        fprintf(g_logFile, "session::checkclientSignedHash: client cert invalid\n");
        return false;
    }
    if(!m_fClientMessageHashValid) {
        fprintf(g_logFile, "session::checkclientSignedHash: client hash invalid\n");
        return false;
    }
    if(!m_fbase64SignedMessageHashValid) {
        fprintf(g_logFile, "session::checkclientSignedHash: signed hash string invalid\n");
        return false;
    }

    // decode and verify hash
    if(!rsaXmlDecodeandVerifyChallenge(true, *m_pclientPublicKey, m_szbase64SignedMessageHash,
                                       SHA256DIGESTBYTESIZE, m_rgClientMessageHash)) {
        fprintf(g_logFile, "session::checkclientSignedHash: bad encrypted hash\n");
        return false;
    }

#ifdef TEST1
    PrintBytes("Hash: ", m_rgClientMessageHash, SHA256DIGESTBYTESIZE);
#endif
    return true;
}


bool session::servercomputeMessageHash()
{
#ifdef TEST
    fprintf(g_logFile, "session::servercomputeMessageHash\n");
    fflush(g_logFile);
#endif
    m_oMessageHash.Final();
    m_oMessageHash.GetDigest(m_rgServerMessageHash);
    m_fServerMessageHashValid= true;
#ifdef TEST1
    PrintBytes("server hash: ", m_rgServerMessageHash, SHA256DIGESTBYTESIZE);
    fflush(g_logFile);
#endif
    return true;
}


bool session::computeServerKeys()
{
    bool    fRet= false;

    if(!m_myProgramKeyValid)
        return false;

    fRet= rsaXmlDecryptandGetNonce(false, *m_myProgramKey, m_myProgramKey->m_iByteSizeM, 
                        m_rguEncPreMasterSecret, BIGSYMKEYSIZE, m_rguPreMasterSecret);
    if(!fRet) {
        fprintf(g_logFile, 
                "session::computeServerKeys: rsaXmlDecryptandGetNonce failed\n");
#ifdef TEST1
        m_myProgramKey->printMe();
#endif
        return false;
    }
    m_fPreMasterSecretValid= true;
    return computeClientKeys();
}


bool session::computeClientKeys()
{
    byte    rgSeed[2*GLOBALMAXSYMKEYSIZE];
    byte    rgKeys[4*GLOBALMAXSYMKEYSIZE];

    if(!m_fPreMasterSecretValid) {
        fprintf(g_logFile, "session::computeClientKeys: Premaster not valid\n");
        return false;
    }
    if(!m_fClientRandValid) {
        fprintf(g_logFile, "session::computeClientKeys: Client random not valid\n");
        return false;
    }
    if(!m_fServerRandValid) {
        fprintf(g_logFile, "session::computeClientKeys: Server random not valid\n");
        return false;
    }

    memcpy(rgSeed, m_rguServerRand, SMALLNONCESIZE);
    memcpy(&rgSeed[SMALLNONCESIZE], m_rguClientRand, SMALLNONCESIZE);
    if(!prf_SHA256(BIGSYMKEYSIZE, m_rguPreMasterSecret, 2*SMALLNONCESIZE, rgSeed,
                       "fileServer keyNego protocol", 4*AES128BYTEKEYSIZE, rgKeys)) {
        fprintf(g_logFile, "session::computeClientKeys: Cannot apply prf\n");
        return false;
   }

#ifdef TEST1
    fprintf(g_logFile,"session::computeClientKeys()\n");
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


bool session::checkPrincipalChallenges()
{
    byte            rguOriginalChallenge[GLOBALMAXPUBKEYSIZE];
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;
    int             iNumChecked= 0;
    bool            fRet= true;
    const char*     szSignedChallenge= NULL;
    int             iNumSignedChallenges= 0;

    if(!doc.Parse(m_szSignedChallenges)) {
        fprintf(g_logFile, "session::checkPrincipalChallenges: Can't parse SignedChallenges\n%s\n",
                m_szSignedChallenges);
        return false;
    }

    pRootElement= doc.RootElement();
    if(strcmp(pRootElement->Value(),"SignedChallenges")!=0) {
        fprintf(g_logFile, "session::checkPrincipalChallenges: Should be SignedChallenges: %s\n", 
                m_szSignedChallenges);
        return false;
    }
    pRootElement->QueryIntAttribute ("count", &iNumSignedChallenges);

#ifdef TEST
    fprintf(g_logFile, "checkPrincipalChallenges %d signed challenges\n", iNumSignedChallenges);
    fflush(g_logFile);
#endif

    if(iNumSignedChallenges==0)
        return true;

    if(m_iNumPrincipals!=iNumSignedChallenges) {
        fprintf(g_logFile, "session::checkPrincipalChallenges: Number of challenges is not number of principals\n");
        return false;
    }

    if(!m_fChallengeValid) {
        fprintf(g_logFile, "session::checkPrincipalChallenges: Challenge not valid\n");
        return false;
    }

    memcpy(rguOriginalChallenge, m_rguChallenge, SMALLNONCESIZE);

    pNode= pRootElement->FirstChild();
    while(pNode!=NULL) {
        if(pNode->Type()==TiXmlNode::TINYXML_ELEMENT) {
            if(strcmp(((TiXmlElement*)pNode)->Value(),"SignedChallenge")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1==NULL) {
                    fprintf(g_logFile, "session::checkPrincipalChallenges: Empty signed challenge\n");
                    return false;
                }
                szSignedChallenge= pNode1->Value();
                if(!rsaXmlDecodeandVerifyChallenge(true, *m_rgPrincipalPublicKeys[iNumChecked], 
                        szSignedChallenge, SMALLNONCESIZE, rguOriginalChallenge)) {
                    fprintf(g_logFile, "session::checkPrincipalChallenges: bad encrypted challenge\n");
                    fRet= false;
                    break;
                }
                // bump
                if(!bumpChallenge(SMALLNONCESIZE, rguOriginalChallenge)) {
                    fprintf(g_logFile, "session::checkPrincipalChallenges: Can't bump challenge\n");
                    return false;
                }
            iNumChecked++;
            }
        }
        pNode= pNode->NextSibling();
    }

    if(fRet && m_iNumPrincipals!=iNumChecked) {
        fprintf(g_logFile, "session::checkPrincipalChallenges: Number of signed challenges is not number of principals\n");
        return false;
    }

    return fRet;
}


bool session::generatePreMaster()
{
    if(!getCryptoRandom(GLOBALMAXPUBKEYSIZE*NBITSINBYTE, m_rguPreMasterSecret))
        return false;
    m_fPreMasterSecretValid= true;
    return true;
}


// ------------------------------------------------------------------------


#ifdef TEST
void session::printMe()
{
    int     i;
    char    szMessage[1024];

    fprintf(g_logFile, "\nSession Data\n");

    if(m_fClient)
        fprintf(g_logFile, "Client role\n");
    else
        fprintf(g_logFile, "Server role\n");

    fprintf(g_logFile, "Session id: %d, session state: %d\n",
            m_iSessionId, m_sessionState);

    if(m_policyCertValid)
        fprintf(g_logFile, "Policy cert\n%s\n", m_szpolicyCert);
    else
        fprintf(g_logFile, "Policy cert invalid\n");

    if(m_policyKey!=NULL)
        fprintf(g_logFile, "Policy key valid\n");
    else
        fprintf(g_logFile, "Policy key invalid\n");

    if(m_myProgramKeyValid) {
        fprintf(g_logFile, "Program key valid\n");
        m_myProgramKey->printMe();
    }
    else
        fprintf(g_logFile, "Program key invalid\n");

    if(m_myCertValid) {
        fprintf(g_logFile, "My cert valid\n%s\n", m_myCert);
    }
    else
        fprintf(g_logFile, "My cert invalid\n");

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
    fprintf(g_logFile, "\nEnd of Session Data\n");

    return;
}
#endif


// -----------------------------------------------------------------------


bool session::clientprotocolNego(int fd, safeChannel& fc,
                                 const char* szPrincipalKeys, 
                                 const char* szPrincipalCerts)
{
    char    request[MAXREQUESTSIZEWITHPAD];
    int     n;
    int     type= CHANNEL_NEGO;
    byte    multi= 0;
    byte    final= 0;

    int     iOut64= 2*SMALLNONCESIZE;
    char    rgszBase64[2*SMALLNONCESIZE];

    char*   szSignedNonce= NULL;
    char*   szEncPreMasterSecret= NULL;
    char*   szSignedChallenges= NULL;
    char*   szAlg= (char*) "TLS_RSA1024_WITH_AES128_CBC_SHA256";
    bool    fRet= true;

    m_sessionState= KEYNEGOSTATE;
    request[0]= '\0';
#ifdef TEST
    fprintf(g_logFile, "clientprotocolNego: protocol negotiation\n");
    fflush(g_logFile);
#endif

    try {

        // init message hash
        if(!initMessageHash())
            throw  "session::clientprotocolNego: Can't init message hash";

        // Phase 1, send
        iOut64= 2*SMALLNONCESIZE;
        if(!getBase64Rand(SMALLNONCESIZE, m_rguClientRand, &iOut64, rgszBase64))
            throw  "session::clientprotocolNego: Can't generated first nonce";
        m_fClientRandValid= true;

        if(!clientNegoMessage1(request, MAXREQUESTSIZE, szAlg, rgszBase64))
            throw  "session::clientprotocolNego: Can't format negotiation message 1";
        if(!updateMessageHash(strlen(request), (byte*) request))
            throw  "session::clientprotocolNego: Can't update message hash";
        if((n=sendPacket(fd, (byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw  "session::clientprotocolNego: Can't send packet 1";
    
        // Phase 1, receive
        if((n=getPacket(fd, (byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw  "session::clientprotocolNego: Can't get packet 1";
        if(!updateMessageHash(strlen(request), (byte*) request))
            throw  "session::clientprotocolNego: Can't update message hash";
        if(!getDatafromServerMessage1(n, request))
            throw  "session::clientprotocolNego: Can't decode server message 1";

        // Phase 2, send
        if(!generatePreMaster())
            throw  "session::clientprotocolNego: Cant generate premaster";
        if(!computeClientKeys())
            throw "session::clientprotocolNego: Cant compute client keys";

        // Pre-master secret
        if(!m_fPreMasterSecretValid)
            throw  "session::clientprotocolNego: No Pre-master string";
        if(!m_fServerCertValid)
            throw  "session::clientprotocolNego: Server key invalid";

        szEncPreMasterSecret= rsaXmlEncodeChallenge(true, *m_pserverPublicKey,
                                    m_rguPreMasterSecret, BIGSYMKEYSIZE);
#ifdef TEST1
        fprintf(g_logFile, "session::clientprotocolNego: pre-master encoded %s\n", 
                szEncPreMasterSecret);
        fflush(g_logFile);
#endif
        if(szEncPreMasterSecret==NULL)
            throw "session::clientprotocolNego: Cant encrypt premaster secret";
        m_fEncPreMasterSecretValid= true;

        if(!clientNegoMessage2(request, MAXREQUESTSIZE, szEncPreMasterSecret,
                               m_szXmlClientCert, m_iSessionId))
            throw  "session::clientprotocolNego: Can't format negotiation message 2";
        if(!updateMessageHash(strlen(request), (byte*) request))
            throw  "session::clientprotocolNego: Can't update message hash";
        if((n=sendPacket(fd, (byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw  "session::clientprotocolNego: Can't send packet 2";

        if(!clientcomputeMessageHash()) 
            throw "session::clientprotocolNego: client cant compute message hash";
        if(!clientsignMessageHash()) 
            throw "session::clientprotocolNego: client cant sign message hash";
        if(!clientNegoMessage3(request, MAXREQUESTSIZE, m_szbase64SignedMessageHash))
            throw  "session::clientprotocolNego: Can't format negotiation message 3";
        if(!updateMessageHash(strlen(request), (byte*) request))
            throw  "session::clientprotocolNego: Can't update message hash";
        if((n=sendPacket(fd, (byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw  "session::clientprotocolNego: Can't send packet 2";

        // encrypted from here on
        if(!fc.initChannel(fd, AES128, CBCMODE, HMACSHA256, AES128BYTEKEYSIZE, 
                           AES128BYTEKEYSIZE,
                           m_rguEncryptionKey1, m_rguIntegrityKey1, 
                           m_rguEncryptionKey2, m_rguIntegrityKey2))
            throw  "session::clientprotocolNego: Can't init safe channel";

#ifdef TEST
        fprintf(g_logFile, "session::clientprotocolNego: initsafeChannel succeeded\n");
#endif

        // Assume CBC
        if((n=getPacket(fd, fc.lastgetBlock, AES128BYTEBLOCKSIZE, &type, &multi, &final))<0)
            throw "session::clientprotocolNego: Cant get IV\n";
        fc.fgetIVReceived= true;
        if((n=sendPacket(fd, fc.lastsendBlock, AES128BYTEBLOCKSIZE, CHANNEL_NEGO_IV, 0, 1))<0)
            throw "session::clientprotocolNego: Cant send IV\n";
        fc.fsendIVSent= true;

#ifdef  TEST1
        fprintf(g_logFile, "session::clientprotocolNego: Encrypted mode on\n");
        PrintBytes((char*)"Received IV: ", fc.lastgetBlock, AES128BYTEBLOCKSIZE);
        PrintBytes((char*)"Sent     IV: ", fc.lastsendBlock, AES128BYTEBLOCKSIZE);
        fflush(g_logFile);
#endif

        // Phase 2, receive
        if((n=fc.safegetPacket((byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw  "session::clientprotocolNego: Can't get server packet 2";
        if(!servercomputeMessageHash())
            throw  "session::clientprotocolNego: Can't compute server hash";
        if(!getDatafromServerMessage2(n, request))
            throw  "session::clientprotocolNego: Can't decode server message 2";

        // do hashes match?
#ifdef TEST
        fprintf(g_logFile, "session::clientprotocolNego: server hashes\n");
        PrintBytes("Computed: ", m_rgServerMessageHash, SHA256DIGESTBYTESIZE);
        PrintBytes("Received: ", m_rgDecodedServerMessageHash, SHA256DIGESTBYTESIZE);
        fflush(g_logFile);
#endif
        if(!m_fServerMessageHashValid || !m_fDecodedServerMessageHashValid ||
                memcmp(m_rgServerMessageHash, m_rgDecodedServerMessageHash, 
                SHA256DIGESTBYTESIZE)!=0)
            throw  "session::clientprotocolNego: server hash does not match";

        // Phase 4, send
        if(!initializePrincipalPrivateKeys(szPrincipalKeys))
            throw  "session::clientprotocolNego: Cant initialize principal private keys";
#ifdef TEST
        fprintf(g_logFile, "session::clientprotocolNego: got principal private keys\n");
        fflush(g_logFile);
#endif
        if(!initializePrincipalCerts(szPrincipalCerts))
            throw  "session::clientprotocolNego: Cant initialize principal certs\n";

        if(strcmp(m_szChallengeSignAlg, "TLS_RSA2048_WITH_AES128_CBC_SHA256")!=0 &&
           strcmp(m_szChallengeSignAlg, "TLS_RSA1024_WITH_AES128_CBC_SHA256")!=0)
            throw  "session::clientprotocolNego: Unsupported challenge algorithm\n";
        
        szSignedChallenges= rsaXmlEncodeChallenges(false, m_iNumPrincipalPrivateKeys,
                                                 m_rgPrincipalPrivateKeys,
                                                 m_rguChallenge, SMALLNONCESIZE);
#ifdef TEST
        fprintf(g_logFile, "session::clientprotocolNego: challenges encoded\n%s\n",
            szSignedChallenges);
        fflush(g_logFile);
#endif

        if(szSignedChallenges==NULL)
            throw  "session::clientprotocolNego: Can't sign principal challenges";
        if(!clientNegoMessage4(request, MAXREQUESTSIZE, m_szPrincipalCerts, 
                               m_iNumPrincipalPrivateKeys, szSignedChallenges))
            throw  "session::clientprotocolNego: Can't format negotiation message 3";
        if((n=fc.safesendPacket((byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw  "session::clientprotocolNego: Can't send packet 3";

        // Phase 3, receive
        if((n=fc.safegetPacket((byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw  "session::clientprotocolNego: Can't get packet 3";

        if(!getDatafromServerMessage3(n, request)) {
#ifdef TEST1
            fprintf(g_logFile, "session::clientprotocolNego request\n%s\n", request);
            fflush(g_logFile);
#endif
            throw  "session::clientprotocolNego: Can't decode client message 3";
        }

        m_sessionState= REQUESTSTATE;
#ifdef TEST
        fprintf(g_logFile, "session::clientprotocolNego: protocol nego succesfully completed\n");
        fflush(g_logFile);
#endif
    }
    catch(const char* szError) {
        fprintf(g_logFile, "session::clientprotocolNego: Protocol Nego error: %s\n", szError);
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
    m_sessionState= REQUESTSTATE;

    return fRet;
}


bool session::clientInit(const char* szPolicyCert, KeyInfo* policyKey,
                         const char* szmyCert, KeyInfo* myKey)
{
    m_fClient= true;
    m_sessionState= NOSTATE;

    m_myProgramKeyValid= true;
    m_myProgramKey= (RSAKey*)myKey;
    m_myCertValid= true;
    m_myCert= strdup(szmyCert);

    m_policyKey= (RSAKey*)policyKey;
    m_policyCertValid= true;
    m_sizepolicyCert= strlen(szPolicyCert);
    m_szpolicyCert= strdup(szPolicyCert);

    m_fClientCertValid= true;
    m_szXmlClientCert= strdup(szmyCert);
    m_pclientCert= new PrincipalCert();
    if(!m_pclientCert->init(m_szXmlClientCert)) {
        fprintf(g_logFile, "session::clientInit: Cant initialize Client Cert\n");
        return false;
    }
    if(!m_pclientCert->parsePrincipalCertElements()) {
        fprintf(g_logFile, "session::clientInit: Cant parse client cert\n");
        return false;
    }
    m_pclientPublicKey= (RSAKey*)m_pclientCert->getSubjectKeyInfo();
    if(m_pclientPublicKey==NULL) {
        fprintf(g_logFile, "session::clientInit: client public key is empty\n");
        return false;
    }
    return true;
}


// ------------------------------------------------------------------------


bool session::serverInit(const char* szPolicyCert, KeyInfo* policyKey,
                         const char* szmyCert, KeyInfo* myKey)
{
    m_fClient= false;
    m_sessionState= NOSTATE;

    m_myProgramKeyValid= true;
    m_myProgramKey= (RSAKey*)myKey;
    m_myCertValid= true;
    m_myCert= strdup(szmyCert);

    m_policyKey= (RSAKey*)policyKey;
    m_policyCertValid= true;
    m_sizepolicyCert= strlen(szPolicyCert);
    m_szpolicyCert= strdup(szPolicyCert);

    m_fServerCertValid= true;
    m_szXmlServerCert= strdup(szmyCert);
    m_pserverCert= new PrincipalCert();
    if(!m_pserverCert->init(m_szXmlServerCert)) {
        fprintf(g_logFile, "session::clientInit: Cant initialize Server Cert\n");
        return false;
    }
    if(!m_pserverCert->parsePrincipalCertElements()) {
        fprintf(g_logFile, "session::clientInit: Cant parse Server cert\n");
        return false;
    }
    m_pserverPublicKey= (RSAKey*)m_pserverCert->getSubjectKeyInfo();
    if(m_pserverPublicKey==NULL) {
        fprintf(g_logFile, "session::clientInit: Server public key is empty\n");
        return false;
    }
    return true;
}


bool session::serverprotocolNego(int fd, safeChannel& fc)
{
    char    request[MAXREQUESTSIZEWITHPAD];
    char    rgszBase64[2*SMALLNONCESIZE];
    char    rgszHashBase64[2*GLOBALMAXDIGESTSIZE];
    int     n;
    int     type= CHANNEL_NEGO;
    byte    multi= 0;
    byte    final= 0;
    int     iOut64;
    int     iOut;
    bool    fRet= true;

#ifdef  TEST
    fprintf(g_logFile, "session::serverprotocolNego\n");
    fflush(g_logFile);
#endif
    m_sessionState= KEYNEGOSTATE;
    request[0]= '\0';

    try {

        // init message hash
        if(!initMessageHash())
            throw  "session::serverprotocolNego: Can't init message hash";

        // Phase 1, receive
        if((n=getPacket(fd, (byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw  "session::serverprotocolNego: Can't get packet 1\n";
        if(!updateMessageHash(strlen(request), (byte*) request))
            throw  "session::serverprotocolNego: Can't update messagehash";
        if(!getDatafromClientMessage1(n, request))
            throw  "session::serverprotocolNego: Can't decode client message 1\n";
        iOut64= 2*SMALLNONCESIZE;
        if(!getBase64Rand(SMALLNONCESIZE, m_rguServerRand, &iOut64, rgszBase64))
            throw  "session::serverprotocolNego: Can't generate first nonce\n";
        m_fServerRandValid= true;
#ifdef TEST
        fprintf(g_logFile, "session::serverprotocolNego: got client rand\n");
        fflush(g_logFile);
#endif

        // Phase 1, send
        if(m_szXmlServerCert==NULL)
            throw "session::serverprotocolNego: No server Certificate\n";
        if(!serverNegoMessage1(request, MAXREQUESTSIZE, m_iSessionId,
                               m_szChallengeSignAlg, rgszBase64, m_szXmlServerCert))
            throw  "session::serverprotocolNego: Can't format negotiation message 1\n";
        if(!updateMessageHash(strlen(request), (byte*) request))
            throw  "session::serverprotocolNego: Can't update messagehash";
        if((n=sendPacket(fd, (byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw  "session::serverprotocolNego: Can't send packet 1\n";

        // Phase 2, receive
        if((n=getPacket(fd, (byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw  "session::serverprotocolNego: Can't get packet 2\n";
        if(!updateMessageHash(strlen(request), (byte*) request))
            throw  "session::serverprotocolNego: Can't update messagehash";
        if(!getDatafromClientMessage2(n, request))
            throw  "session::serverprotocolNego: Can't decode client message 2\n";
        if(!clientcomputeMessageHash())
            throw "session::serverprotocolNego: client cant compute message hash";
        if(!computeServerKeys()) 
            throw  "session::serverprotocolNego: Cant compute channel keys\n";

#ifdef TEST
        fprintf(g_logFile, "session::serverprotocolNego: computed server keys\n");
        fflush(g_logFile);
#endif

        // Phase 3, receive
        if((n=getPacket(fd, (byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw  "session::serverprotocolNego: Can't get packet 3\n";
        if(!getDatafromClientMessage3(n, request))
            throw  "session::serverprotocolNego: Can't decode client message 3\n";
        if(!checkclientSignedHash())
            throw "session::serverprotocolNego: client signed message hash does not match";
        if(!updateMessageHash(strlen(request), (byte*) request))
            throw  "session::serverprotocolNego: Can't update messagehash";
        if(!servercomputeMessageHash())
            throw "session::serverprotocolNego: can't compute server hash";

        // init safeChannel
        if(!fc.initChannel(fd, AES128, CBCMODE, HMACSHA256, AES128BYTEKEYSIZE, 
                           AES128BYTEKEYSIZE,
                           m_rguEncryptionKey2, m_rguIntegrityKey2, 
                           m_rguEncryptionKey1, m_rguIntegrityKey1))
            throw("session::serverprotocolNego: Cant init channel\n");

        // Assume CBC
        if((n=sendPacket(fd, fc.lastsendBlock, AES128BYTEBLOCKSIZE, CHANNEL_NEGO_IV, 0, 1))<0)
            throw "session::serverprotocolNego: Cant send IV\n";
        fc.fsendIVSent= true;
        if((n=getPacket(fd, fc.lastgetBlock, AES128BYTEBLOCKSIZE, &type, &multi, &final))<0)
            throw "session::serverprotocolNego: Cant get IV\n";
        fc.fgetIVReceived= true;

#ifdef  TEST1
        fprintf(g_logFile, "session::serverprotocolNego: Encrypted mode on\n");
        PrintBytes((char*)"Received IV: ", fc.lastgetBlock, AES128BYTEBLOCKSIZE);
        PrintBytes((char*)"Sent     IV: ", fc.lastsendBlock, AES128BYTEBLOCKSIZE);
        fflush(g_logFile);
#endif

        // Phase 2, send
        iOut= 2*SMALLNONCESIZE;
        if(!getBase64Rand(SMALLNONCESIZE, m_rguChallenge, &iOut, rgszBase64)) 
            throw  "session::serverprotocolNego: Can't generate principal challenge\n";
        m_fChallengeValid= true;

        // compute szHash string
        iOut= 2*GLOBALMAXDIGESTSIZE;
        if(!toBase64(SHA256DIGESTBYTESIZE, m_rgServerMessageHash, &iOut, rgszHashBase64))
            throw  "session::serverprotocolNego: Can't base64 encode server hash\n";
        if(!serverNegoMessage2(request, MAXREQUESTSIZE, m_szChallengeSignAlg, 
                               rgszBase64, rgszHashBase64))
            throw  "session::serverprotocolNego: Can't format negotiation message 2\n";

        if((n=fc.safesendPacket((byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw  "session::serverprotocolNego: Can't safesendPacket 2\n";
#ifdef TEST
        fprintf(g_logFile, "session::serverprotocolNego: client signed message hash match\n");
        fflush(g_logFile);
#endif

        // Phase 4, receive
        if((n=fc.safegetPacket((byte*)request, MAXREQUESTSIZE, &type, &multi, &final))<0)
            throw  "session::serverprotocolNego: Can't get packet 4\n";
#ifdef TEST1
        fprintf(g_logFile, "session::serverprotocolNego: %d from safegetPacket, phase 4\n", n);
        fprintf(g_logFile, "session::serverprotocolNego: %s\n", request);
        fflush(g_logFile);
#endif
        if(!updateMessageHash(strlen(request), (byte*) request))
            throw  "session::serverprotocolNego: Can't update message hash";
        if(!getDatafromClientMessage4(n, request))
            throw  "session::serverprotocolNego: Can't decode client message 3\n";
        if(!initializePrincipalCerts(m_szPrincipalCerts))
            throw "session::serverprotocolNego: Cant initialize principal public keys\n";
        if(!checkPrincipalChallenges())
            throw "session::serverprotocolNego: Principal challenges fail\n";
#ifdef TEST1
        fprintf(g_logFile, "session::serverprotocolNego: checked principal challenges\n");
        fflush(g_logFile);
#endif

        // Phase 4, send
        if(!serverNegoMessage3(request, MAXREQUESTSIZE, true))
            throw  "session::serverprotocolNego: Can't format negotiation message 3\n";
        if((n=fc.safesendPacket((byte*)request, strlen(request)+1, CHANNEL_NEGO, 0, 1))<0)
            throw  "session::serverprotocolNego: Can't send packet 3\n";
#ifdef TEST1
        fprintf(g_logFile, "session::serverprotocolNego: success packet sent\n");
        fflush(g_logFile);
#endif
    }
    catch(const char* szError) {
        fprintf(g_logFile, "%s",szError);
        fRet= false;
        return false;
    }

#ifdef TEST
        fprintf(g_logFile, "session::serverprotocolNego: protocol negotiation complete\n");
        fflush(g_logFile);
#endif

    m_sessionState= REQUESTSTATE;
    return fRet;
}


// ----------------------------------------------------------------------------


