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
#include "jlmUtility.h"
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
#include "cert.h"
#include "validateEvidence.h"

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
#define BIGBUFSIZE  32768


// ------------------------------------------------------------------------


bool filePresent(const char* resFile)
{
    struct stat statBlock;
    if(stat(resFile, &statBlock)<0) {
        return false;
    }
    return true;
}


sellerClient::sellerClient ()
{
    m_clientState= NOSTATE;
    m_fChannelAuthenticated= false;
    m_szPort= NULL;
    m_szAddress= NULL;
    m_fd= 0;

    m_serverCert= NULL;

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


bool sellerClient::initClient(const char* configDirectory, const char* serverAddress, 
                              u_short serverPort, bool fInitChannel)
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


void sellerClient::closeConnection(safeChannel& fc) {
        if(fc.fd>0) {
                fc.safesendPacket((byte*) g_szTerm, strlen(g_szTerm)+1, CHANNEL_TERMINATE, 0, 1);
        }
}


// ------------------------------------------------------------------------

//
//  Application specific logic
// 

/* signedBid
 *  <ds:Signature>
 *  <ds:SignedInfo>\
 *      <ds:CanonicalizationMethod Algorithm=\http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#\ />\
 *      <ds:SignatureMethod Algorithm=\http://www.manferdelli.com/2011/Xml/algorithms/rsa%d-sha256-pkcspad#\ />\
 *  <Bid>\
 *    <AuctionID> %s </AuctionID>\
 *    <BidAmount> %s </BidAmount>\
 *    <UserName> %s </UserName>\
 *    <DateTime> %s </DateTime>\
 *    <BidderCert> %s  </BidderCert>\
 *  </Bid>\
 *  </ds:SignedInfo>;
 *  </ds:Signature>
 *
 *  <Bid>
 *      <AuctionID> </AuctionID>
 *      <BidAmount> </BidAmount>
 *      <UserName> </UserName>
 *      <DateTime> </DateTime>
 *      <BidderCert> </BidderCert>
 *  <Bid>
 */


class signedbidInfo {
public:
    TiXmlDocument   doc;
    bool            parseValid;

    signedbidInfo();
    ~signedbidInfo();

    bool          parse(const char* signedBid);
    const char*   getBidElement();
    const char*   getSignedInfoElement();
    const char*   getSignatureValue();
};


signedbidInfo::signedbidInfo()
{
    parseValid= false;
}


signedbidInfo::~signedbidInfo()
{
}


bool signedbidInfo::parse(const char* signedBid)
{
    parseValid= doc.Parse(signedBid);
    return parseValid;
}


const char*   signedbidInfo::getSignatureValue()
{
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;
    TiXmlNode*      pNode2= NULL;
    TiXmlNode*      pNodesignedInfo= NULL;

    if(!parseValid) {
        fprintf(g_logFile, "signedbidInfo::getSignatureValue: parse invalid\n");
        return false;
    }
    pRootElement= doc.RootElement();
    if(pRootElement==NULL) {
        fprintf(g_logFile, "signedbidInfo::getSignatureValue: no root element\n");
        return NULL;
    }
    pNode= Search((TiXmlNode*) pRootElement, "ds:Signature");
    if(pNode==NULL) {
        fprintf(g_logFile, "signedbidInfo::getSignatureValue: no signature element\n");
        return NULL;
    }
    pNodesignedInfo= Search((TiXmlNode*) pRootElement, "ds:SignedInfo");
    if(pNodesignedInfo==NULL) {
        fprintf(g_logFile, "signedbidInfo::getSignatureValue: no signedInfo\n");
        return NULL;
    }
    pNode= pNodesignedInfo->NextSibling();
    if(pNode==NULL) {
        fprintf(g_logFile, "signedbidInfo::getSignatureValue: no sibling\n");
        return NULL;
    }
    pNode1= Search((TiXmlNode*) pNode, "ds:SignatureValue");
    if(pNode1==NULL) {
        fprintf(g_logFile, "signedbidInfo::getSignatureValue: no SignatureValue element\n");
        return NULL;
    }
    pNode2= pNode1->FirstChild();
    if(pNode2==NULL)
        return NULL;
    return strdup((const char*)pNode2->Value());
}


const char*   signedbidInfo::getSignedInfoElement()
{
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;

    if(!parseValid) {
        fprintf(g_logFile, "signedbidInfo::getSignedInfoElement: parse invalid\n");
        return false;
    }
    pRootElement= doc.RootElement();
    if(pRootElement==NULL) {
        fprintf(g_logFile, "signedbidInfo::getSignedInfoElement: no root element\n");
        return NULL;
    }
    pNode= Search((TiXmlNode*) pRootElement, "ds:Signature");
    if(pNode==NULL) {
        fprintf(g_logFile, "signedbidInfo::getSignedInfoElement: no signature element\n");
        return NULL;
    }
    pNode1= Search((TiXmlNode*) pNode, "ds:SignedInfo");
    if(pNode1==NULL) {
        fprintf(g_logFile, "signedbidInfo::getSignedInfoElement: no SignedInfo element\n");
        return NULL;
    }
    return canonicalize(pNode1);
}


const char*   signedbidInfo::getBidElement()
{
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;
    TiXmlNode*      pNode2= NULL;

    if(!parseValid) {
        fprintf(g_logFile, "signedbidInfo::getBidElement: parse invalid\n");
        return NULL;
    }
    pRootElement= doc.RootElement();
    if(pRootElement==NULL) {
        fprintf(g_logFile, "signedbidInfo::getBidElement: no root element\n");
        return NULL;
    }
    pNode= Search((TiXmlNode*) pRootElement, "ds:Signature");
    if(pNode==NULL) {
        fprintf(g_logFile, "signedbidInfo::getBidElement: no signature element\n");
        return NULL;
    }
    pNode1= Search((TiXmlNode*) pNode, "ds:SignedInfo");
    if(pNode1==NULL) {
        fprintf(g_logFile, "signedbidInfo::getBidElement: no SignedInfo element\n");
        return NULL;
    }
    pNode2= Search((TiXmlNode*) pNode1, "Bid");
    if(pNode2==NULL) {
        fprintf(g_logFile, "signedbidInfo::getBidElement: no Bid element\n");
        return NULL;
    }
    return canonicalize(pNode2);
}


class bidInfo {
public:
    TiXmlDocument   doc;
    bool            m_parseValid;
    char*           m_auctionID;
    int             m_bidAmount;
    char*           m_userName;
    char*           m_szTime;
    struct tm       m_timeinfo;
    char*           m_bidderCert;

    bidInfo();
    ~bidInfo();

    bool        parse(const char* szBid);
    char*       getBidderCert();
    int         bidAmount();
    char*       auctionId();
    char*       userName();
    struct tm*  timeSigned();
#ifdef TEST
    void        printMe();
#endif
};


bidInfo::bidInfo() 
{
    m_parseValid= false;
    m_auctionID= NULL;
    m_bidAmount= 0;
    m_userName= NULL;
    m_bidderCert= NULL;
}


bidInfo::~bidInfo()
{
    if(m_auctionID!=NULL) {
        free(m_auctionID);
        m_auctionID= NULL;
    }
    if(m_userName!=NULL) {
        free(m_userName);
        m_userName= NULL;
    }
    if(m_bidderCert!=NULL) {
        free(m_bidderCert);
        m_bidderCert= NULL;
    }
}


#ifdef TEST
void bidInfo::printMe() 
{
    if(m_auctionID==NULL) 
        fprintf(g_logFile, "auctionID is NULL\n");
    else
        fprintf(g_logFile, "auctionID is %s\n", m_auctionID);
    fprintf(g_logFile, "bidAmount is %d\n", m_bidAmount);
    if(m_userName==NULL) 
        fprintf(g_logFile, "userName is NULL\n");
    else
        fprintf(g_logFile, "userName is %s\n", m_userName);
    printTime(&m_timeinfo);
}
#endif


bool  bidInfo::parse(const char* szBid) 
{
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;
    TiXmlElement*   pRootElement= NULL;
    const char*     szAuctionID= NULL;
    const char*     szBidAmount= NULL;
    const char*     szUserName= NULL;
    const char*     szBidTime= NULL;
    const char*     szBidderCert= NULL;

#ifdef  TEST1
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
        pNode= Search((TiXmlNode*) pRootElement, "UserName");
        if(pNode!=NULL) {
            pNode1= pNode->FirstChild();
            if(pNode1!=NULL && pNode1->Value()!=NULL) {
                szUserName= pNode1->Value();
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
        pNode= Search((TiXmlNode*) pRootElement, "BidderCert");
        if(pNode==NULL)
            throw "bidInfo::parse: No BidderCert element\n";
	pNode1= pNode->FirstChild();
	if(pNode1!=NULL)
            szBidderCert= canonicalize(pNode1);
    }
    catch(const char* szError) {
        fprintf(g_logFile, "bidInfo::parse error: %s\n");
        return false;
    }
        
    if(szAuctionID==NULL) {
        fprintf(g_logFile, "bidInfo::parse: no auctionID\n");
        return false;
    }
    m_auctionID= strdup(szAuctionID);

    if(szBidAmount!=NULL);
        m_bidAmount= atoi(szBidAmount);
    
    if(szUserName==NULL) {
        szUserName= "Anonymous";
    }
    m_userName= strdup(szUserName);

    if(!timeInfofromstring(szBidTime, m_timeinfo)) {
        fprintf(g_logFile, "bidInfo::parse: cant translate time\n");
        return false;
    }
    if(szBidderCert==NULL) {
        fprintf(g_logFile, "bidInfo::parse: cant get bidder cert\n");
        return false;
    }
    m_bidderCert= (char*)szBidderCert;

#ifdef TEST1
    fprintf(g_logFile, "bidInfo::parse succeeds\n");
    printMe();
    fflush(g_logFile);
#endif
    m_parseValid= true;
    return true;
}


char* bidInfo::getBidderCert()
{
    if(!m_parseValid)
        return NULL;
    if(m_bidderCert==NULL)
        return NULL;
    return strdup(m_bidderCert);
}


int bidInfo::bidAmount()
{
    if(!m_parseValid)
        return -1;
    return m_bidAmount;
}


char*  bidInfo::auctionId()
{
    if(!m_parseValid)
        return NULL;
    if(m_auctionID==NULL)
        return NULL;
    return strdup(m_auctionID);
}


char*  bidInfo::userName()
{
    if(!m_parseValid)
        return NULL;
    if(m_userName==NULL)
        return NULL;
    return strdup(m_userName);
}


struct tm*  bidInfo::timeSigned()
{
    if(!m_parseValid)
        return NULL;
    struct tm* time= new struct tm;
    *time= m_timeinfo;
    return time;
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
"<SignedInfo>\n"\
"  <AuctionID> %s </AuctionID>\n"\
"  <TimeofDetermination> %s </TimeofDetermination>\n"\
"    <Price> %d </Price>\n"\
"  <WinnerCert>\n %s\n </WinnerCert>\n"\
" </SignedInfo>\n";


char* sellerClient::signWinner(RSAKey* signingKey, const char* auctionID, const char* time,
                               int winningBidAmount, const char* winnerCert)
{
    char  signedInfo[BIGBUFSIZE];
    char  sigtag[256];

    sprintf(sigtag,"auction%sWinner", auctionID);
    sprintf(signedInfo, g_signedBidTemplate, auctionID, time, winningBidAmount, winnerCert);
    char* signedwinner= constructXMLRSASha256SignaturefromSignedInfoandKey(*signingKey,
                                                sigtag, signedInfo);
    return signedwinner;
}


inline void swapsignedBidinfo(signedbidInfo** a, signedbidInfo **b)
{
    signedbidInfo*      tmpsignedBidinfo= NULL;
    tmpsignedBidinfo= *a;
    *a= *b;
    *b= tmpsignedBidinfo;
}


inline void swapBidinfo(bidInfo** a, bidInfo**b)
{
    bidInfo*     tmpBidinfo= NULL;
    tmpBidinfo= *a;
    *a= *b;
    *b= tmpBidinfo;
}


inline void swapstrobj(const char** a, const char** b)
{
    const char*  t= NULL;
    t= *a;
    *a= *b;
    *b= t;
}


inline void swapintobj(int* a, int* b)
{
    int                 t;
    t= *a;
    *a= *b;
    *b= t;
}


inline void swaptimeobj(struct tm** a, struct tm** b)
{
    struct tm*  t;
    t= *a;
    *a= *b;
    *b= t;
}


bool isCertValid(RSAKey* signerKey, PrincipalCert* cert, struct tm* now, const char* stringcert)
{
    if(stringcert==NULL || cert== NULL || signerKey==NULL || !cert->init(stringcert)) {
        fprintf(g_logFile, "isCertValid cert invalid\n");
        return false;
    }
    if(!cert->parsePrincipalCertElements()) {
        fprintf(g_logFile, "isCertValid: Can't parse PrincipalCertElements\n");
        return false;
    }
    return VerifySignedEvidence(signerKey, now, PRINCIPALCERT, (void*) cert)>0;
}


bool issignedbidInfoValid(RSAKey* signerKey, signedbidInfo* bidinfo)
{
    const char*         signedInfo= NULL;
    const char*         sigValue=  NULL;
    bool                fVerify= false;

    signedInfo= bidinfo->getSignedInfoElement();
    sigValue= bidinfo->getSignatureValue();
    if(signedInfo!=NULL || sigValue!=NULL) {
        fVerify= VerifyRSASha256SignaturefromSignedInfoandKey(*signerKey,
                                                (char*)signedInfo, (char*)sigValue);
    }
    if(signedInfo!=NULL) {
        free((void*)signedInfo);
        signedInfo= NULL;
    }
    if(sigValue!=NULL) {
        free((void*)sigValue);
        sigValue= NULL;
    }
    return fVerify;
}


bool sellerClient::resolveAuction(int nBids, const char** bids)
{
    int                 i;
    int                 winningBidAmount= 0;
    int                 currentBidAmount= 0;
    const char*         signedwinningBid= NULL;
    signedbidInfo*      signedwinningBidinfo= NULL;
    const char*         winningBid= NULL;
    bidInfo*            winningBidinfo= NULL;
    const char*         signedcurrentBid= NULL;
    signedbidInfo*      signedcurrentBidinfo= NULL;
    const char*         currentBid= NULL;
    bidInfo*            currentBidinfo= NULL;
    RSAKey*             signingKey= NULL;
    struct tm*          now= timeNow();
    const char*         strnow= stringtimefromtimeInfo(now);
    struct tm*          timewinnersigned= NULL;
    struct tm*          timecurrentsigned= NULL;

#ifdef TEST
    fprintf(g_logFile, "sellerClient::resolveAuction %d bids\n", nBids);
    fflush(g_logFile);
#endif

    if(nBids<=0) {
        fprintf(g_logFile, "sellerClient::resolveAuction bid list empty\n");
        return false;
    }

    if(!m_tcHome.privateKeyValid()) {
        fprintf(g_logFile, "sellerClient::resolveAuction signing key invalid\n");
        return false;
    }
    signingKey= (RSAKey*)m_tcHome.privateKeyPtr();

    // get policy key
    RSAKey* ppolicyKey= (RSAKey*)m_opolicyCert.getSubjectKeyInfo();

    // check server cert
    PrincipalCert   serverCert;
    if(!isCertValid(ppolicyKey, &serverCert, now, m_serverCert)) {
        fprintf(g_logFile, "sellerClient::resolveAuction server cert invalid\n");
        return false;
    }
    RSAKey*         serverKey= (RSAKey*)serverCert.getSubjectKeyInfo();

    // init
    signedwinningBid= bids[0];
    signedwinningBidinfo= new signedbidInfo();
    if(!signedwinningBidinfo->parse(signedwinningBid)) {
        fprintf(g_logFile, "sellerClient::resolveAuction cant parse first signed bid\n");
        return false;
    }
#ifdef TEST1
    fprintf(g_logFile, "parsed first signed bid\n%s\n", signedwinningBid);
    fflush(g_logFile);
#endif

    // check bid signature
    if(!issignedbidInfoValid(serverKey, signedwinningBidinfo)) {
        fprintf(g_logFile, "sellerClient::resolveAuction first signed bid invalid\n");
        return false;
    }
#ifdef TEST1
    fprintf(g_logFile, "checked first bid signature\n");
    fflush(g_logFile);
#endif

    const char* winningcert= NULL;
    const char* currentcert= NULL;

    winningBid= signedwinningBidinfo->getBidElement();
    if(winningBid==NULL) {
        fprintf(g_logFile, "sellerClient::resolveAuction first signed bid has no bid\n");
        return false;
    }
#ifdef TEST1
    fprintf(g_logFile, "got first bid element\n");
    fflush(g_logFile);
    fprintf(g_logFile, "%s\n", winningBid);
    fflush(g_logFile);
#endif

    winningBidinfo= new bidInfo();
    if(!winningBidinfo->parse(winningBid)) {
        fprintf(g_logFile, "sellerClient::resolveAuction cant parse first bid\n");
        return false;
    }
    // right auction?
    const char* auctionid= winningBidinfo->auctionId();
    if(strcmp(m_szAuctionID, auctionid)!=0) {
        fprintf(g_logFile, "sellerClient::resolveAuction first bid from wrong auction\n");
        return false;
    }
    winningcert= winningBidinfo->getBidderCert();
    winningBidAmount= winningBidinfo->bidAmount();
    timewinnersigned= winningBidinfo->timeSigned();

    // check bid Cert
    PrincipalCert*  bidCert= new PrincipalCert();
    if(!isCertValid(ppolicyKey, bidCert, now, winningcert)) {
        fprintf(g_logFile, "sellerClient::resolveAuction server cert invalid\n");
        return false;
    }
    delete bidCert;
    bidCert= NULL;

    for(i=1;i<nBids; i++) {

        // next bid
        signedcurrentBid= bids[i];
        signedcurrentBidinfo= new signedbidInfo();
        if(!signedcurrentBidinfo->parse(signedcurrentBid)) {
            fprintf(g_logFile, "sellerClient::resolveAuction cant parse signed bid %d\n", i+1);
            return false;
        }

        // check bidder cert
        if(!issignedbidInfoValid(serverKey, signedcurrentBidinfo)) {
            fprintf(g_logFile, "sellerClient::resolveAuction first signed bid invalid\n");
            return false;
        }

        // get bid info
        currentBidinfo= new bidInfo();
        currentBid= signedcurrentBidinfo->getBidElement();
        if(currentBid==NULL) {
            fprintf(g_logFile, "sellerClient::resolveAuction signed bid %d has no Bid\n", i+1);
            return false;
        }
        if(!currentBidinfo->parse(currentBid)) {
            fprintf(g_logFile, "sellerClient::resolveAuction cant parse bid %d\n", i+1);
            return false;
        }

        // check bidder cert
        currentcert= currentBidinfo->getBidderCert();

        // check bid Cert
        PrincipalCert*  bidCert= new PrincipalCert();
        if(!isCertValid(ppolicyKey, bidCert, now, winningcert)) {
            fprintf(g_logFile, "sellerClient::resolveAuction server cert invalid\n");
            return false;
        }
        delete bidCert;
        bidCert= NULL;

        // right auction?
        auctionid= winningBidinfo->auctionId();
        if(strcmp(m_szAuctionID, auctionid)!=0) {
            fprintf(g_logFile, "sellerClient::resolveAuction bid %d from wrong auction\n", i+1);
            return false;
        }
        currentBidAmount= currentBidinfo->bidAmount();

        if(currentBidAmount>winningBidAmount) {
            swapsignedBidinfo(&signedcurrentBidinfo, &signedwinningBidinfo);
            swapBidinfo(&currentBidinfo, &winningBidinfo);
            swapstrobj(&signedwinningBid, &signedcurrentBid);
            swapstrobj(&winningcert, &currentcert);
            swapstrobj(&currentBid, &winningBid);
            swapintobj(&winningBidAmount, &currentBidAmount);
            swaptimeobj(&timewinnersigned, &timecurrentsigned);
        }
        else if(currentBidAmount==winningBidAmount) {
            timewinnersigned= currentBidinfo->timeSigned();
            // was the current bid earlier?
            if(timeCompare(*timewinnersigned, *timecurrentsigned)>0) {
                swapsignedBidinfo(&signedcurrentBidinfo, &signedwinningBidinfo);
                swapBidinfo(&currentBidinfo, &winningBidinfo);
                swapstrobj(&signedwinningBid, &signedcurrentBid);
                swapstrobj(&winningcert, &currentcert);
                swapstrobj(&currentBid, &winningBid);
                swapintobj(&winningBidAmount, &currentBidAmount);
                swaptimeobj(&timewinnersigned, &timecurrentsigned);
            }
        }

        // delete stuff
        if(currentBidinfo!=NULL){
            delete currentBidinfo;
            currentBidinfo= NULL;
        }
        if(signedcurrentBidinfo!=NULL){
            delete signedcurrentBidinfo;
            signedcurrentBidinfo= NULL;
        }
        if(currentBid!=NULL){
            free((void*)currentBid);
            currentBid= NULL;
        }
        if(currentcert!=NULL){
            free((void*)currentcert);
            currentcert= NULL;
        }
        if(auctionid!=NULL){
            free((void*)auctionid);
            auctionid= NULL;
        }
        if(timecurrentsigned!=NULL){
            free((void*)timecurrentsigned);
            timecurrentsigned= NULL;
        }
    }

    // record result and sign winner
    m_fWinningBidValid= true;
    m_WinningBidAmount= winningBidAmount;
    m_szSignedWinner=  signWinner(signingKey, winningBidinfo->m_auctionID, strnow, 
                                  winningBidAmount, winningcert);
#ifdef TEST
    fprintf(g_logFile, "Winning Bid %d\n%s\n", winningBidAmount, m_szSignedWinner);
    fflush(g_logFile);
#endif
    return true;
}


// ------------------------------------------------------------------------


int main(int an, char** av)
{
    sellerClient    oSellerClient;
    safeChannel     fc;
    int             iRet= 0;
    const char*     directory= NULL;
    string          testPath("sellerClient/tests/");
    string          testFileName("tests.xml");
    bool            result;

    bidchannelServices mychannelServices(2);

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
            char* auctionID= readandstoreString("./sellerClient/getBids");
            while(*auctionID!='\0') {
                if(*auctionID==' '|| *auctionID=='\n') {
                    *auctionID= 0;
                    break;
                }
                auctionID++;
            }
#ifdef  TEST
            fprintf(g_logFile, "sellerClient no private file, initializing\n");
            fflush(g_logFile);
#endif
            result = oSellerClient.establishConnection(oSellerClient.m_fc,
                        NULL, NULL, directory, "127.0.0.1", SERVICE_PORT);
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
                return 1;
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

        // get auction id
        if(!oSellerClient.initClient(directory, "127.0.0.1", SERVICE_PORT, false )) {
            fprintf(g_logFile, "sellerClient::resolveAuction: cant initializeClient for bid resolution\n");
            return 1;
        }
        oSellerClient.m_szAuctionID= readandstoreString("./sellerClient/resolve");
        if(oSellerClient.m_szAuctionID==NULL) {
            fprintf(g_logFile, "sellerClient::resolveAuction:  cant read auctionID\n");
            return 1;
        }
        char* p= oSellerClient.m_szAuctionID;
        while(*p!='\0') {
            if(*p==' '|| *p=='\n') {
                *p= 0;
                break;
            }
            p++;
        }

        fprintf(g_logFile, "sellerClient resolving auction %s\n", oSellerClient.m_szAuctionID);

        // get server cert
        char    serverCert[BIGBUFSIZE];
        int     size= BIGBUFSIZE;
        if(!getBlobfromFile("sellerClient/serverCert", (byte*)serverCert, &size)) {
            fprintf(g_logFile, "sellerClient::resolveAuction:  cant read serverCert\n");
            return 1;
        }
        oSellerClient.m_serverCert= (const char*)strdup(serverCert);

        // read bids if not present
        if(!mychannelServices.m_fBidListValid) {
#if 1
            if(!mychannelServices.retrieveBids((u32)NOENCRYPT, NULL, 
                        "./sellerClient/savedBids")) {
                fprintf(g_logFile, "sellerClient::resolveAuction:  cant retrieve bids\n");
                return 1;
            } 
#else
            char    buf[BIGBUFSIZE];
            int     size= BIGBUFSIZE;
            if(!getBlobfromFile("./sellerClient/savedBids", (byte*)buf, &size)) {
                fprintf(g_logFile, "sellerClient::resolveAuction:  cant read saved bids\n");
                return 1;
            }

            if(!mychannelServices.deserializeList((const char*)buf)) {
                fprintf(g_logFile, "sellerClient::resolveAuction:  cant deserializeList\n");
                return 1;
            }
#endif
        }

        if(oSellerClient.resolveAuction(mychannelServices.m_nBids, (const char**)mychannelServices.m_Bids))
            fprintf(g_logFile, "sellerClient: auction successfully concluded\n");
        else
            fprintf(g_logFile, "sellerClient: auction resolution unsuccessful\n");

        // save to ./sellerClient/winningbid.xml
        saveBlobtoFile("./sellerClient/winningbid.xml", (byte*)oSellerClient.m_szSignedWinner, 
                        strlen(oSellerClient.m_szSignedWinner)+1);
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



