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
#include "bidRequest.h"
#include "sha256.h"
#include "tinyxml.h"
#include "cryptoHelper.h"
#include "domain.h"
#include "tcIO.h"
#include "timer.h"
#include "validateEvidence.h"
#include "bidTester.h"
#include "taoSetupglobals.h"

#include "objectManager.h"
#include "tao.h"

#include "trustedKeyNego.h"
#include "encryptedblockIO.h"
#include "cert.h"
#include "validateEvidence.h"
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

#include "./policyCert.inc"

#define DEFAULTDIRECTORY    "/home/jlm/jlmcrypt"
#define SELLERCLIENTSUBDIRECTORY "sellerClient"
#define BIGBUFSIZE  16384


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
    m_sizeKey= GLOBALMAXSYMKEYSIZE;
    m_fpolicyCertValid= false;

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
    m_sizeKey= GLOBALMAXSYMKEYSIZE;
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
    if(!m_tcHome.isValid()) {
        fprintf(g_logFile, "sellerClient::initPolicy(): environment invalid\n");
        return false;
    }

    if(!m_tcHome.myCertValid())  {
        fprintf(g_logFile, "sellerClient::initPolicy(): policyKey invalid\n");
        return false;
    }

    // initialize policy cert
    if(!m_opolicyCert.init(m_tcHome.policyCertPtr())) {
        fprintf(g_logFile, "fileServer::Init:: Can't init policy cert 1\n");
        return false;
    }
    if(!m_opolicyCert.parsePrincipalCertElements()) {
        fprintf(g_logFile, "fileServer::Init:: Can't init policy key 2\n");
        return false;
    }
    m_fpolicyCertValid= true;

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

        // init Host and Environment
        m_taoHostInitializationTimer.Start();
        if(!m_host.HostInit(g_hostplatform, g_hostProvider, g_hostDirectory,
                            g_hostsubDirectory, parameterCount, parameters)) {
            throw "sellerClient::Init: can't init host\n";
        }
        m_taoHostInitializationTimer.Stop();
#ifdef TEST
        fprintf(g_logFile, "sellerClient::Init: after HostInit, pid: %d\n",
            getpid());
#endif

        // init environment
        m_taoEnvInitializationTimer.Start();
        if(!m_tcHome.EnvInit(g_envplatform, "sellerClient", DOMAIN, g_hostDirectory,
                             SELLERCLIENTSUBDIRECTORY, &m_host, g_serviceProvider, 0, NULL)) {
            throw "sellerClient::Init: can't init environment\n";
        }
        m_taoEnvInitializationTimer.Stop();
#ifdef TEST
        fprintf(g_logFile, "sellerClient::Init: after EnvInit\n");
        m_tcHome.printData();
#endif
    
        // Init global policy 
        if(!initPolicy())
            throw "sellerClient::Init: Cant init policy objects\n";

        // Initialize program private key and certificate for session
        if(!m_tcHome.privateKeyValid())
            throw "sellerClient::Init: Cant get my private key\n";
        if(!m_tcHome.myCertPtr())
            throw "sellerClient::Init: Cant get my Cert\n";

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

            // this section should move to the tao
            if(!m_opolicyCert.init(m_tcHome.policyCertPtr()))
                throw("sellerClient::Init:: Can't init policy cert 1\n");
            if(!m_opolicyCert.parsePrincipalCertElements())
                throw("sellerClient::Init:: Can't init policy key 2\n");
            m_fpolicyCertValid= true;
            RSAKey* ppolicyKey= (RSAKey*)m_opolicyCert.getSubjectKeyInfo();

            // m_tcHome.m_policyKeyValid must be true
            if(!m_clientSession.clientInit(m_tcHome.policyCertPtr(),
                                   ppolicyKey, m_tcHome.myCertPtr(),
                                   (RSAKey*)m_tcHome.privateKeyPtr()))
                throw("sellerClient::Init: Can't init policy key 3\n");

            // get principal certs
            const char* szPrincipalKeys= NULL; // readandstoreString(keyFile);
            const char* szPrincipalCerts= NULL; // readandstoreString(certFile);

            // negotiate channel
            m_protocolNegoTimer.Start();
            if(!m_clientSession.clientprotocolNego(m_fd, m_fc,
                                    szPrincipalKeys, szPrincipalCerts))
                throw("sellerClient::Init: protocolNego failed\n");
            m_protocolNegoTimer.Stop();

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


// ------------------------------------------------------------------------


extern const char*  g_szTerm;


bool sellerClient::establishConnection(safeChannel& fc, 
                                    const char* keyFile, 
                                    const char* certFile, 
                                    const char* directory,
                                    const char* serverAddress,
                                    u_short serverPort) {
    try {
#ifdef  TEST
        fprintf(g_logFile, "sellerClient main: inited g_policyPrincipalCert\n");
        fflush(g_logFile);
#endif
        // init logfile, crypto, etc
        if(!initClient(directory, serverAddress, serverPort, true))
            throw "sellerClient main: initClient() failed\n";

        // copy my public key into client public key
        if(!m_tcHome.myCertValid())
            throw "sellerClient main: Cant load client public key structures\n";

#ifdef  TEST
        fprintf(g_logFile, "sellerClient main: protocol nego\n");
        fflush(g_logFile);
#endif
        // protocol Nego
        m_protocolNegoTimer.Start();
        if(!m_clientSession.clientprotocolNego(m_fd, fc, keyFile, certFile))
            throw "sellerClient main: Cant negotiate channel\n";
        m_protocolNegoTimer.Stop();
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

#ifdef  TEST
        fprintf(g_logFile, "sellerClient main: inited g_policyPrincipalCert\n");
        fflush(g_logFile);
#endif
        // init logfile, crypto, etc
        if(!initClient(directory, serverAddress, serverPort, false))
            throw "sellerClient main: initClient() failed\n";

        // copy my public key into client public key
        if(!m_tcHome.myCertValid())
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
    const char*         szMeta= szBid;
    const char*         szSignatureName= NULL;
    const char*         szSignature= NULL;
    char                szName[256];
    char*               szSealedName= NULL;
    char*               szMetaDataName= NULL;
    char*               szMetaData= NULL;
    Sha256              oHash;
    byte                rgComputedHash[SHA256_DIGESTSIZE_BYTES];
    byte                rgSigValue[1024];
    byte                rgPadded[1024];
    bool                fRet= true;

    bnum                bnMsg(128);
    bnum                bnOut(128);
    TiXmlDocument       doc;
    TiXmlElement*       pRootElement= NULL;
    TiXmlNode*          pfirstSignatureNode= NULL;
    TiXmlNode*          psecondSignatureNode= NULL;
    TiXmlNode*          pNode= NULL;
    TiXmlNode*          pNode1= NULL;
    RSAKey*             signingKey= NULL;
    char*               szbidServerCert= NULL;
    char*               szKey= NULL;
    PrincipalCert       oPrincipal;
    int                 rgType[2]={PRINCIPALCERT, EMBEDDEDPOLICYPRINCIPAL};
    void*               rgObject[2]={NULL, NULL}; //g_policyKey};
    int                 iChain= 0;

    // construct Blob Name
    sprintf(szName, "bidServer/bids/SealedBid%s", szMeta+7);
    szSealedName= strdup(szName);
    sprintf(szName, "bidServer/bids/%s", szMeta);
    szMetaDataName= strdup(szName);
    sprintf(szName, "bidServer/bids/Signature%s", szMeta+7);
    szSignatureName= strdup(szName);

#ifdef TEST
    fprintf(g_logFile, "bidInfo::getBidInfo: \n");
    fprintf(g_logFile, "\tMetaData file: %s\n", szMetaDataName);
    fprintf(g_logFile, "\tSealedData file: %s\n", szSealedName);
    fprintf(g_logFile, "\tSignature file: %s\n", szSignatureName);
#endif

    // get metaData
    size= 8192;
    if(!getBlobfromFile(szMetaDataName, buf, &size)) {
        fprintf(g_logFile, "bidInfo::getBidInfo: cant get metadata file %d\n",
                szMetaDataName);
        return false;
    }
    szMetaData= strdup((char*)buf);

    // get sealed data
    size= 8192;
    if(!getBlobfromFile(szSealedName, buf, &size)) {
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

    // get encrypted bid
    if(!oM.setencryptedMessage(size, buf)) {
        fprintf(g_logFile, "bidInfo::getBidInfo: cant set encrypted\n");
        fRet= false;
        goto done;
    }

    // get and check Signature
    size= 8192;
    if(!getBlobfromFile(szSignatureName, buf, &size)) {
        fprintf(g_logFile, "bidInfo::getBidInfo: cant get signature\n");
        fRet= false;
        goto done;
    }

    // hash file contents
    oHash.Init();
    oHash.Update((byte*) oM.m_rgEncrypted, oM.m_sizeEncrypted);
    oHash.Final();
    oHash.GetDigest(rgComputedHash);

    // parse signature
#ifdef TEST
    fprintf(g_logFile, "bidInfo::getBidInfo, detached sig:\n%s \n", (char*) buf);
#endif
    if(!doc.Parse((char*)buf)) {
        fprintf(g_logFile, "bidInfo::getBidInfo: cant parse detached signature\n");
        fRet= false;
        goto done;
    }

    pRootElement= doc.RootElement();
    if(pRootElement==NULL) {
        fprintf(g_logFile, "bidInfo::getBidInfo: cant get root of detached signature\n");
        fRet= false;
        goto done;
    }

    pfirstSignatureNode= Search((TiXmlNode*) pRootElement, "ds:Signature");
    if(pfirstSignatureNode==NULL) {
        fprintf(g_logFile, "bidInfo::getBidInfo: cant find signature element\n");
        fRet= false;
        goto done;
    }
    pNode= Search((TiXmlNode*) pfirstSignatureNode, "ds:SignatureValue");
    if(pNode==NULL) {
        fprintf(g_logFile, "bidInfo::getBidInfo: cant parse detached Signaturevalue\n");
        fRet= false;
        goto done;
    }
    pNode1= pNode->FirstChild();
    if(pNode1==NULL) {
        fprintf(g_logFile, "bidInfo::getBidInfo: cant parse detached signatureValue string\n");
        fRet= false;
        goto done;
    }
    szSignature= pNode1->Value();

    // get signing Key
    pNode= Search((TiXmlNode*) pfirstSignatureNode, "ds:KeyInfo");
    if(pNode==NULL) {
        fprintf(g_logFile, "bidInfo::getBidInfo: cant parse detached signature\n");
        fRet= false;
        goto done;
    }
    szKey= canonicalize(pNode);
    if(szKey==NULL) {
        fprintf(g_logFile, "bidInfo::getBidInfo: cant canonicalize keyinfo\n");
        fRet= false;
        goto done;
    }

    // FIX
    signingKey= NULL; // keyfromkeyInfo(szKey);
    if(signingKey==NULL) {
        fprintf(g_logFile, "bidInfo::getBidInfo: signing key invalid\n");
        fRet= false;
        goto done;
    }

    // get signer certificate
    pNode= pfirstSignatureNode->NextSibling();
    if(pNode==NULL) {
        fprintf(g_logFile, "bidInfo::getBidInfo: no signature siblings\n");
        fRet= false;
        goto done;
    }
    psecondSignatureNode= Search((TiXmlNode*) pNode, "ds:Signature");
    if(psecondSignatureNode==NULL) {
        fprintf(g_logFile, "bidInfo::getBidInfo: cant find server cert\n");
        fRet= false;
        goto done;
    }
    szbidServerCert= canonicalize(psecondSignatureNode);
    if(szbidServerCert==NULL) {
        fprintf(g_logFile, "bidInfo::getBidInfo: cant canonicalize server cert\n");
        fRet= false;
        goto done;
    }

    // decrypt signature
    mpZeroNum(bnMsg);
    mpZeroNum(bnOut);


    size= 1024;
    memset(rgSigValue, 0, size);
    if(!fromBase64(strlen(szSignature), szSignature, &size, rgSigValue)) {
        fprintf(g_logFile, "bidInfo::getBidInfo: cant base64 decode signature\n");
        fRet= false;
        goto done;
    }
    memcpy((byte*)bnMsg.m_pValue, rgSigValue, signingKey->m_iByteSizeM);
    if(!mpRSAENC(bnMsg, *(signingKey->m_pbnE), *(signingKey->m_pbnM), bnOut)) {
        fprintf(g_logFile, "bidServer::getBidInfo: encrypt failed\n");
        fRet= false;
        goto done;
    }
    revmemcpy(rgPadded, (byte*)bnOut.m_pValue, signingKey->m_iByteSizeM);

#ifdef TEST
    fprintf(g_logFile, "bidServer::getBidInfo, signature %s \n", szSignature);
    PrintBytes((char*)"SigValue:\n", rgSigValue, signingKey->m_iByteSizeM);

    fprintf(g_logFile, "bidServer::getBidInfo: signingKey\n");
    signingKey->printMe();
    PrintBytes((char*)"rgpadded: ", rgPadded, signingKey->m_iByteSizeM);
#endif

    // depad
    if(!emsapkcsverify(SHA256HASH, rgComputedHash, signingKey->m_iByteSizeM, rgPadded)) {
        fprintf(g_logFile, "bidServer::getBidInfo: padding verification failed\n");
        fRet= false;
        goto done;
    }

    // set top key to signing key, rootKey to 
    // Validate cert chain
    if(!oPrincipal.init(szbidServerCert)) {
        fprintf(g_logFile, "bidInfo::getBidInfo: signing key invalid\n");
        fRet= false;
        goto done;
    }

    if(!oPrincipal.parsePrincipalCertElements()) {
        fprintf(g_logFile, "bidServer::getBidInfo: can't parse seal Cert\n");
        fRet= false;
        goto done;
    }

    rgObject[0]= (void*) &oPrincipal;
    // FIX iChain= VerifyChain(oSellerClient.m_clientSession.m_policy
    iChain= VerifyChain(NULL, "", NULL, 2, rgType, rgObject);
    if(iChain<0) {
        fprintf(g_logFile, "bidServer::getBidInfo: Invalid bidServer certificate chain\n");
        return false;
    }

    // decrypt bid
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
    oM.m_szXMLmetadata= NULL;
    if(szKey!=NULL) {
        free(szKey);
        szKey= NULL;
    }
    if(signingKey!=NULL) {
        delete signingKey;
        signingKey= NULL;
    }
    if(szbidServerCert!=NULL) {
        free(szbidServerCert);
        szbidServerCert= NULL;
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
    if(!m_tcHome.privateKeyValid()) {
        fprintf(g_logFile, 
                "sellerClient::resolveAuction: seller private key invalid\n");
        return false;
    }
    // FIX
    sealingKey= NULL; // (RSAKey*)m_tcHome.m_privateKey;
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
    const char*     directory= NULL;
    string          testPath("sellerClient/tests/");
    string          testFileName("tests.xml");
    bool            result;
    string          userKeyFile("bidClient/tests/basicBidTest/UserPublicKey.xml");
    string          userCertFile("bidClient/tests/basicBidTest/UserCert.xml");
    timer           aTimer;


    initLog(NULL);

#ifdef  TEST
    fprintf(g_logFile, "sellerClient test\n");
    fflush(g_logFile);
#endif

    UNUSEDVAR(result);
    UNUSEDVAR(directory);

    initLog("sellerClient.log");
#ifdef  TEST
    fprintf(g_logFile, "sellerClient main in measured loop\n");
    fflush(g_logFile);
#endif
    try {
        if(filePresent("sellerClient/getBids")) {
            bidchannelServices mychannelServices(2);
            char* auctionID= readandstoreString("./sellerClient/getBids");
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

            // get Bids
            char    buf[BIGBUFSIZE];
            int     size= BIGBUFSIZE;
            char*   p= buf;

            if(!bidconstructRequest(&p, &size, "getBids", auctionID, NULL, NULL, NULL)) {
                fprintf(g_logFile, "sellerClient::readBid: bad sellerconstructRequest\n");
                return false;
            }

            if(!mychannelServices.requestbids(oSellerClient.m_fc, NULL, buf)) {
            }
            closeLog();
            return 0;
        }
        if(!filePresent("sellerClient/resolve")) {
            fprintf(g_logFile, "sellerClient not time to resolve auction\n");
            closeLog();
            return 0;
        }

        if(filePresent("sellerClient/getBids")) {
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



