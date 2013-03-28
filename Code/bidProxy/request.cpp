//  File: request.cpp
//      John Manferdelli
//
//  Description: file action request object
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


#define MAXNAME 2048


// -----------------------------------------------------------------------------


#include "jlmTypes.h"
#include "logging.h"
#include "jlmcrypto.h"
#include "algs.h"
#include "keys.h"
#include "session.h"
#include "channel.h"
#include "safeChannel.h"
#include "jlmUtility.h"
#include "request.h"
#include "encryptedblockIO.h"
#include "claims.h"
#include "bignum.h"
#include "mpFunctions.h"
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
#include <errno.h>


#define DEBUGPRINT


const char*   szRequest1a= "<Request>\n";
const char*   szRequest1b=  "</Request>\n";

const char*   szRequest2a= "<Action>";
const char*   szRequest2b= "</Action>\n";

const char*   szRequest3a= "    <AuctionID>";
const char*   szRequest3b=  "</AuctionID>\n";

const char*   szRequest4a= "<UserName>";
const char*   szRequest4b= "</UserName>\n";

const char*   szRequest5a= "    <Bid>";
const char*   szRequest5b=  "</Bid>\n";

const char*   szRequest6a= "<SubmiterCert>\n";
const char*   szRequest6b= "</SubmitterCert>\n";


const char*   szResponse1= "<Response>\n";
const char*   szResponse2= "<ErrorCode>";
const char*   szResponse3= "</ErrorCode>\n</Response>\n";


// ------------------------------------------------------------------------



Request::Request()
{
    m_iRequestType= 0;
    m_szAction= NULL;
    m_szAuctionID= NULL;
    m_szUserName= NULL;
    m_szBid= NULL;
    m_szBidderCert= NULL;
}


Request::~Request()
{
    if(m_szAction!=NULL) {
        free(m_szAction);
        m_szAction= NULL;
    }
    if(m_szAuctionID!=NULL) {
        free(m_szAuctionID);
        m_szAuctionID= NULL;
    }
    if(m_szUserName!=NULL) {
        free(m_szUserName);
        m_szUserName= NULL;
    }
    if(m_szBid!=NULL) {
        free(m_szBid);
        m_szBid= NULL;
    }
    if(m_szBidderCert!=NULL) {
        free(m_szBidderCert);
        m_szBidderCert= NULL;
    }
}


bool  Request::getDatafromDoc(const char* szRequest)
{
    TiXmlDocument       doc;
    TiXmlElement*       pRootElement;
    TiXmlNode*          pNode;
    TiXmlNode*          pNode1;

    const char*         szAction= NULL;
    const char*         szAuctionID= NULL;
    const char*         szUserName= NULL;
    const char*         szBidderCert= NULL;
    const char*         szBid= NULL;

    if(szRequest==NULL)
        return false;

    if(!doc.Parse(szRequest)) {
        fprintf(g_logFile, "Request::getDatafromDoc: Cant parse request\n");
        return false;
    }

    pRootElement= doc.RootElement();
    if(strcmp(pRootElement->Value(),"Request")!=0) {
        fprintf(g_logFile, "Request::getDatafromDoc: Should be request\n");
        return false;
    }
    
    pNode= pRootElement->FirstChild();
    while(pNode!=NULL) {
        if(pNode->Type()==TiXmlNode::TINYXML_ELEMENT) {
            if(strcmp(((TiXmlElement*)pNode)->Value(),"Action")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1) {
                    szAction= pNode1->Value();
                }
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"BidderCert")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL) {
                    m_szBidderCert= canonicalize(pNode1);
                }
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"AuctionID")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL) {
                    szAuctionID= pNode1->Value();
                }
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"UserName")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL) {
                    szAuctionID= pNode1->Value();
                }
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"Bid")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL) {
                    szBid= pNode1->Value();
                }
            }
        }
        pNode= pNode->NextSibling();
    }

    if(szAction==NULL || szAuctionID==NULL || szBid==NULL || szBidderCert==NULL)
        return false;

    if(szAction!=NULL)
        m_szAction= strdup(szAction);
    if(szAuctionID!=NULL)
        m_szAuctionID= strdup(szAuctionID);
    if(szUserName!=NULL)
        m_szUserName= strdup(szUserName);
    if(szBidderCert!=NULL)
        m_szBidderCert= strdup(szBidderCert);
    if(szBid!=NULL)
        m_szBid= strdup(szBid);

    if(strcmp(m_szAction, "SubmitBid")==0)
        m_iRequestType= SUBMITBID;
    else
        m_iRequestType= 0;

#ifdef TEST
    fprintf(g_logFile, "Response getdata\n");
    printMe();
#endif
    return true;
}


#ifdef TEST
void Request::printMe()
{
    fprintf(g_logFile, "\n\tRequest type: %d\n", m_iRequestType);
    if(m_szAuctionID==NULL)
        fprintf(g_logFile, "\tm_szAuctionID is NULL\n");
    else
        fprintf(g_logFile, "\tm_szAuctionID: %s \n", m_szAuctionID);
    if(m_szUserName==NULL)
        fprintf(g_logFile, "\tm_szUserName is NULL\n");
    else
        fprintf(g_logFile, "\tm_szUserName: %s \n", m_szUserName);
    if(m_szBid==NULL)
        fprintf(g_logFile, "\tm_szBid is NULL\n");
    else
        fprintf(g_logFile, "\tm_szBid: %s \n", m_szBid);
    if(m_szBidderCert==NULL)
        fprintf(g_logFile, "\tm_szBidderCert is NULL\n");
    else
        fprintf(g_logFile, "\tm_szBidderCert: %s \n", m_szBidderCert);
}
#endif


bool  Request::validateBid(sessionKeys& oKeys, const char* szAuctionID,
                           const char* szBid, const char* szBidderCert)
{
    // Access allowed?
    return true;
}

 
// ------------------------------------------------------------------------


Response::Response()
{
    m_iRequestType= 0;
    m_szErrorCode= NULL;
}


Response::~Response()
{
    if(m_szErrorCode!=NULL) {
        free(m_szErrorCode);
        m_szErrorCode= NULL;
    }
}


#ifdef TEST
void Response::printMe()
{
    fprintf(g_logFile, "\tRequestType: %d\n", m_iRequestType);
    if(m_szErrorCode==NULL)
        fprintf(g_logFile, "\tm_szErrorCode is NULL\n");
    else
        fprintf(g_logFile, "\tm_szErrorCode: %s \n", m_szErrorCode);
}
#endif


bool  Response::getDatafromDoc(char* szResponse)
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement;
    TiXmlNode*      pNode;
    TiXmlNode*      pNode1;

#ifdef TEST
    fprintf(g_logFile, "Response::getDatafromDoc\n%s\n", szResponse);
#endif
    if(!doc.Parse(szResponse)) {
        fprintf(g_logFile, "Response::getDatafromDoc: cant parse response\n");
        return false;
    }

    pRootElement= doc.RootElement();
    if(strcmp(pRootElement->Value(),"Response")!=0) {
        fprintf(g_logFile, "Response::getDatafromDoc: Should be response\n");
        return false;
    }

    pNode= pRootElement->FirstChild();
    while(pNode) {
        if(pNode->Type()==TiXmlNode::TINYXML_ELEMENT) {
            if(strcmp(((TiXmlElement*)pNode)->Value(),"ErrorCode")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL)
                    m_szErrorCode= strdup(pNode1->Value());
            }
        }
        pNode= pNode->NextSibling();
    }

#ifdef TEST
    fprintf(g_logFile, "Response getdata\n");
    printMe();
#endif
    return true;
}


// -------------------------------------------------------------------------


const char* g_szPrefix= "//www.manferdelli.com/Gauss/";


int openFile(const char* szInFile, int* psize)
{
    struct stat statBlock;
    int         iRead= -1;

    iRead= open(szInFile, O_RDONLY);
    if(iRead<0) {
        return -1;
    }
    if(stat(szInFile, &statBlock)<0) {
        return -1;
    }
    *psize= statBlock.st_size;

    return iRead;
}

bool emptyChannel(safeChannel& fc, int size, int enckeyType, byte* enckey,
             int intkeyType, byte* intkey)
{
    int         type= CHANNEL_REQUEST;
    byte        multi=0;
    byte        final= 0;
    byte        fileBuf[MAXREQUESTSIZEWITHPAD];

    while(fc.safegetPacket(fileBuf, MAXREQUESTSIZE, &type, &multi, &final)>0);
    return true;
}



bool  constructRequest(char** pp, int* piLeft, const char* szAction, const char* szAuctionID,
                       const char* szUserName, const char* szBid, const char* szBidderCert)

{
#ifdef  TEST
    char*p= *pp;
#endif

    if(!safeTransfer(pp, piLeft, szRequest1a))
        return false;
    if(!safeTransfer(pp, piLeft, szRequest2a))
        return false;
    if(!safeTransfer(pp, piLeft, szAction))
        return false;
    if(!safeTransfer(pp, piLeft, szRequest2b))
        return false;

    if(!safeTransfer(pp, piLeft, szRequest3a))
        return false;
    if(!safeTransfer(pp, piLeft, szAuctionID))
        return false;
    if(!safeTransfer(pp, piLeft, szRequest3b))
        return false;

    if(szUserName!=NULL) {
        if(!safeTransfer(pp, piLeft, szRequest4a))
            return false;
        if(!safeTransfer(pp, piLeft, szUserName))
            return false;
        if(!safeTransfer(pp, piLeft, szRequest4b))
            return false;
    }

    if(!safeTransfer(pp, piLeft, szRequest5a))
        return false;
    if(!safeTransfer(pp, piLeft, szBid))
        return false;
    if(!safeTransfer(pp, piLeft, szRequest5b))
        return false;

    if(!safeTransfer(pp, piLeft, szRequest6a))
        return false;
    if(!safeTransfer(pp, piLeft, szBidderCert))
        return false;
    if(!safeTransfer(pp, piLeft, szRequest6b))
        return false;

    if(!safeTransfer(pp, piLeft, szRequest1b))
        return false;

#ifdef  TEST
    fprintf(g_logFile, "constructRequest completed\n%s\n", p);
#endif
    return true;
}


bool  constructResponse(bool fError, char** pp, int* piLeft)
{
    bool    fRet= true;
    // int     n= 0;

#ifdef  TEST
    char*   p= *pp;
#endif

    try {
        if(!safeTransfer(pp, piLeft, szResponse1))
            throw "constructResponse: Can't construct response\n";

        if(!safeTransfer(pp, piLeft, szResponse2))
            throw "Can't construct response\n";

        if(fError) {
            if(!safeTransfer(pp, piLeft, "reject"))
                throw "constructResponse: Can't construct response\n";
        }
        else {
            if(!safeTransfer(pp, piLeft, "accept"))
                throw "constructResponse: Can't construct response\n";
        }

        if(!safeTransfer(pp, piLeft, szResponse3))
            throw "constructResponse: Can't construct response\n";
    }
    catch(const char* szConstructError) {
        fRet= false;
        fprintf(g_logFile, "%s", szConstructError);
    }

#ifdef  TEST
    fprintf(g_logFile, "constructResponse completed\n%s\n", p);
#endif
    return fRet;
}


// -------------------------------------------------------------------------


//
//      Application logic
//


bool saveBid(RSAKey* sealingKey, RSAKey* signingKey, const char* bidBody)
{
    encapsulatedMessage     oM;
    Sha256                  oHash;
    byte                    rgHash[SHA256_DIGESTSIZE_BYTES];
    char                    szMetaName[256];
    char                    szSealedName[256];
    u64*                    pl1;
    u64*                    pl2;

    // hash
    oHash.Init();
    oHash.Update((byte*) bidBody, strlen(bidBody));
    oHash.Final();
    oHash.GetDigest(rgHash);

    pl1= (u64*) &rgHash[0];
    pl2= (u64*) &rgHash[16];

    sprintf(szMetaName, "bidServer/bids/BidMeta%016lx%016lx", *pl1, *pl2);
    sprintf(szSealedName, "bidServer/bids/SealedBid%016lx%016lx", *pl1, *pl2);


    if(!oM.setplainMessage(strlen(bidBody), (byte*)bidBody)) {
        fprintf(g_logFile, "saveBid: cant set plaintext\n");
        return false;
    }

    // seal key
    if(!oM.sealKey(sealingKey)) {
        fprintf(g_logFile, "saveBid: cant seal key\n");
        return false;
    }
                                      
    if(!oM.encryptMessage()) {
        fprintf(g_logFile, "saveBid: cant encrypt message\n");
        return false;
    }

    // serialize metadata
    oM.m_szXMLmetadata= oM.serializeMetaData();
    if(oM.m_szXMLmetadata==NULL) {
        fprintf(g_logFile, "saveBid: cant serialize metadata\n");
        return false;
    }

    // write metadata
    if(!saveBlobtoFile(szMetaName, (byte*)oM.m_szXMLmetadata, strlen(oM.m_szXMLmetadata)+1)) {
        fprintf(g_logFile, "saveBid: cant write metadata %s\n", szMetaName);
        return false;
    }

    // write encrypted data
    if(!saveBlobtoFile(szSealedName, oM.m_rgEncrypted, oM.m_sizeEncrypted)) {
        fprintf(g_logFile, "saveBid: cant write encrypted data to %s\n", szSealedName);
        return false;
    }

  return true;
}


bool clientsendbidtoserver(safeChannel& fc, 
                    const char* szAuctionID,  const char* szUserName,
                    const char* szBid, const char* szBidderCert,
                    int encType, byte* key, timer& encTimer)
{
    char        szBuf[MAXREQUESTSIZEWITHPAD];
    int         iLeft= MAXREQUESTSIZE;
    char*       p= szBuf;
    Response    oResponse;
    int         n= 0;
    int         type= CHANNEL_REQUEST;
    byte        multi=0;
    byte        final= 0;
    const char* szAction= "SubmitBid";

#ifdef  TEST
    fprintf(g_logFile, "clientsendbidtoserver(%s, %s)\n", szAuctionID, szUserName);
#endif
    // send request
    if(!constructRequest(&p, &iLeft, szAction, szAuctionID, szUserName, 
                         szBid, szBidderCert)) {
        return false;
    }
#ifdef  TEST
    fprintf(g_logFile, "clientsendbidtoserver request\n%s\n", szBuf);
#endif
    if((n=fc.safesendPacket((byte*)szBuf, strlen(szBuf)+1, CHANNEL_REQUEST, 0, 0)) <0) {
        return false;
    }

    // should be a CHANNEL_RESPONSE, not multipart
    n= fc.safegetPacket((byte*)szBuf, MAXREQUESTSIZE, &type, &multi, &final);
    if(n<0) {
        fprintf(g_logFile, "clientsendbidtoserver: getCredential error %d\n", n);
        fprintf(g_logFile, "clientsendbidtoserver: server response %s\n", szBuf);
        return false;
    }
    szBuf[n]= 0;
    oResponse.getDatafromDoc(szBuf);

#ifdef TEST
    fprintf(g_logFile, "Got a response from the server\n");
    fflush(g_logFile);
#endif

    // check response
    if(strcmp(oResponse.m_szErrorCode, "accept")!=0) {
        fprintf(g_logFile, "Error: %s\n", oResponse.m_szErrorCode);
        return false;
    }
    
#ifdef TEST
    fprintf(g_logFile, "The response was an accept message: %s\n", szBuf);
    fflush(g_logFile);
#endif

    return true;
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

static char* s_szBidTemplate= (char*)
"<Bid>\n  <AuctionID> %s </AuctionID>\n  <BidAmount> %s </BidAmount>"\
"<SubjectName> %s </SubjectName>\n  <DateTime> %s </DateTime>\n"\
"  <BidderCert>\n %s\n  </BidderCert>\n </Bid>\n";


char*  constructBid(Request& oReq)
{
    char            rgbid[2048];

    char*           szBidderCert= NULL;
    char*           szAuctionID= NULL;
    char*           szBidAmount= NULL;
    char*           szUserName= NULL;
    char            szTimeNow[256];
    time_t          now;
    struct tm *     timeinfo;

    time(&now);
    timeinfo= gmtime(&now);
    // 2011-01-01Z00:00.00
    sprintf(szTimeNow,"%04d-%02d-%02dZ%02d:%02d.%02d", timeinfo->tm_year, timeinfo->tm_mon,
            timeinfo->tm_mday, timeinfo->tm_hour, timeinfo->tm_min, timeinfo->tm_sec);

    szAuctionID= oReq.m_szAuctionID;
    szBidAmount= oReq.m_szBid;
    szBidderCert= oReq.m_szBidderCert;
    szUserName= oReq.m_szUserName;

    sprintf(rgbid, s_szBidTemplate, szAuctionID, szBidAmount, 
                   szUserName, szTimeNow, szBidderCert);

    return strdup(rgbid);
}


bool serversendresponsetoclient(RSAKey* sealingKey, RSAKey* signingKey,
                                safeChannel& fc, Request& oReq,
                                sessionKeys& oKeys, int encType, byte* key,
                                timer& accessTimer, timer& decTimer)
{
    bool        fError= false;
    byte        szBuf[MAXREQUESTSIZEWITHPAD];
    int         iLeft= MAXREQUESTSIZE;
    char*       p= (char*)szBuf;
    int         type= CHANNEL_RESPONSE;
    byte        multi= 0;
    byte        final= 0;
    char*       szBid= NULL;

#ifdef  TEST
    fprintf(g_logFile, "serversendresponsetoclient\n");
#endif
    // validate request (including access check) and get file location
    accessTimer.Start();
    // fError= !oReq.validateRequest(oKeys);
    accessTimer.Stop();

    if(!fError) {
        szBid= constructBid(oReq);
        if(szBid==NULL) {
            fprintf(g_logFile, "serversendresponsetoclient: can't construct proto cert\n");
            return false;
        }
        // save bid
        if(!saveBid(sealingKey, signingKey, szBid)) {
            fprintf(g_logFile, "serversendresponsetoclient: can't save bid\n");
            return false;
        }
    }

    // construct response
    if(!constructResponse(fError, &p, &iLeft)) {
        fprintf(g_logFile, "serversendresponsetoclient: constructResponse error\n");
        return false;
    }

    // send response
    fc.safesendPacket(szBuf, (int)strlen(reinterpret_cast<char*>(szBuf))+1, type, multi, final);

    if (fError) 
        return false;
#ifdef  TEST
    fprintf(g_logFile, "serversendresponsetoclientreturns true\n");
#endif
    return true;
}


// ---------------------------------------------------------------------------------


