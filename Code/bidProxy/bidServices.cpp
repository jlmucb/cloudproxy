//
//  File: bidServices.cpp
//      John Manferdelli
//
//  Description: Sever for bidServices
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
#include "bidServer.h"
#include "serviceChannel.h"
#include "jlmcrypto.h"
#include "channel.h"
#include "safeChannel.h"
#include "channelServices.h"
#include "channelstate.h"
#include "jlmUtility.h"
#include "tinyxml.h"
#include "session.h"
#include "sha256.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "cryptoHelper.h"
#include "request.h"
#include "bidRequest.h"
#include "tcIO.h"

#include "tao.h"

#include "objectManager.h"
#include "cert.h"
#include "validateEvidence.h"
#include "attest.h"
#include "trustedKeyNego.h"
#include "encryptedblockIO.h"
#include "domain.h"

#include "encapsulate.h"
#include "taoSetupglobals.h"
#include "bidServices.h"

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


#define BIGBUFSIZE  16384


#ifndef BIDCLIENT
// request loop for bidServer
#define TIMER(x) ((bidServerLocals*)(service->m_pchannelLocals))->m_pServerObj->x
#define LOCALOBJ(x) ((bidServerLocals*)(service->pchannelLocals))->m_pServerObj->x
#define SERVICESOBJ(x) ((bidchannelServices*)(service->m_pchannelServices))->x
#endif


// ------------------------------------------------------------------------


/*
 *  <Bid>
 *      <AuctionID> </AuctionID>
 *      <BidAmount> </BidAmount>
 *      <SubjectName> </SubjectName>
 *      <DateTime> </DateTime>
 *      <BidderCert> </BidderCert>
 *  <Bid>
 */


static const char* s_szBidTemplate= (char*)
"<ds:SignedInfo>\n"\
"    <ds:CanonicalizationMethod Algorithm=\"http://www.manferdelli.com/2011/Xml/canonicalization/tinyxmlcanonical#\" />\n"\
"    <ds:SignatureMethod Algorithm=\"http://www.manferdelli.com/2011/Xml/algorithms/rsa%d-sha256-pkcspad#\" />\n"\
"<Bid>\n"\
"  <AuctionID> %s </AuctionID>\n"\
"  <BidAmount> %s </BidAmount>\n"\
"  <UserName> %s </UserName>\n"\
"  <DateTime> %s </DateTime>\n"\
"  <BidderCert>\n %s\n  </BidderCert>\n"\
"</Bid>\n"\
"</ds:SignedInfo>\n";


char*  constructBid(bidRequest& oReq)
{
    char            rgbid[BIGBUFSIZE];
    const char*     szBidderCert= NULL;
    const char*     szAuctionID= NULL;
    const char*     szBidAmount= NULL;
    const char*     szUserName= NULL;
    char            szTimeNow[256];
    time_t          now;
    struct tm *     timeinfo;
    int             keysize= 2048; 

#ifdef  TEST1
    fprintf(g_logFile, "constructBid\n");
    fflush(g_logFile);
#endif
    time(&now);
    timeinfo= gmtime(&now);
    if(timeinfo==NULL) {
        fprintf(g_logFile, "constructBid: can't get current time\n");
        szTimeNow[0]= 0;
    }
    else {
        // 2011-01-01Z00:00.00
        sprintf(szTimeNow,"%04d-%02d-%02dZ%02d:%02d.%02d",
                1900+timeinfo->tm_year, timeinfo->tm_mon+1,
                timeinfo->tm_mday, timeinfo->tm_hour,
                timeinfo->tm_min, timeinfo->tm_sec);
    }

    szAuctionID= oReq.m_szAuctionId;
    szBidAmount= oReq.m_szBid;
    szBidderCert= oReq.m_szEvidence;
    szUserName= oReq.m_szUserName;
    if(szBidderCert==NULL)
        szBidderCert= (char*)"";
    if(szUserName==NULL)
        szUserName= (char*)"Anonymous";

    if((strlen(s_szBidTemplate)+strlen(szAuctionID)+strlen(szBidAmount)+strlen(szUserName)+
        strlen(szTimeNow)+strlen(szBidderCert))>(BIGBUFSIZE-8)) {
        fprintf(g_logFile, "constructBid: bid too large\n");
        fflush(g_logFile);
        return NULL;
    }

    sprintf(rgbid, s_szBidTemplate, keysize, szAuctionID, szBidAmount,
                  szUserName, szTimeNow, szBidderCert);

#ifdef  TEST1
    fprintf(g_logFile, "constructBid returning %s\n", rgbid);
    fflush(g_logFile);
#endif
    return strdup(rgbid);
}



// ------------------------------------------------------------------------


bidchannelServices::bidchannelServices(u32 type) : channelServices(type)
{
    m_fBidListValid= false;
    m_nBids= 0;
    m_Bids= NULL;
}


bidchannelServices::~bidchannelServices() 
{
}


bool channelServices::enablechannelServices(serviceChannel* service, void* pLocal)
{
    return true;
}


bool channelServices::initchannelServices(serviceChannel* service, void* pLocals)
{
    service->m_fServicesPresent= true; 
    return true;
}


bool channelServices::closechannelServices()
{
    return true;
}


#ifndef BIDCLIENT

bool bidchannelServices::acceptBid(bidRequest& oReq, serviceChannel* service, timer& myTimer)
{
    char*       file= (char*)"bidServer/bidssofar.enc";
    bool        fError= false;
    char        buf[BIGBUFSIZE];
    char*       p= buf;
    int         nLeft= BIGBUFSIZE;
    char*       channelError= NULL;
    int         type= CHANNEL_RESPONSE;
    byte        multi= 0;
    byte        final= 0;

    // construct Bid
    const char* signedbid= NULL;
    const char* bidsigninfoBody= constructBid(oReq);
#ifdef  TEST
    fprintf(g_logFile, "bidchannelServices::acceptBid, signed bid prototype\n%s\n", 
            bidsigninfoBody);
    fflush(g_logFile);
#endif
    if(bidsigninfoBody==NULL) {
        fError= true;
        channelError= (char*) "can't construct bid";
        goto done;
    }

#ifdef  TEST
    fprintf(g_logFile, "bidchannelServices::acceptBid start\n");
    fflush(g_logFile);
    fprintf(g_logFile, "bidchannelServices::acceptBid, signing key %08x  %08x  %08x\n",
            service->m_pchannelLocals,
            ((bidServerLocals*)(service->m_pchannelLocals))->m_pServerObj,
            ((bidServerLocals*)(service->m_pchannelLocals))->m_pServerObj->m_signingKey);
    fflush(g_logFile);
#endif

    // sign it and put it on list
    signedbid= constructXMLRSASha256SignaturefromSignedInfoandKey(
           *(((bidServerLocals*)(service->m_pchannelLocals))->m_pServerObj->m_signingKey), 
           "Bid",
           bidsigninfoBody);
    if(signedbid==NULL) {
        fError= true;
        channelError= (char*) "can't sign bid";
        goto done;
    }
    appendBid(signedbid);
    // free(signedbid); signedbid= NULL;

#ifdef  TEST
    fprintf(g_logFile, "bidchannelServices::acceptBid signed\n%s\n", signedbid);
    fflush(g_logFile);
#endif

    // save bids
    if(!saveBids(service,
        (u32)DEFAULTENCRYPT, 
        (byte*)((bidServerLocals*)(service->m_pchannelLocals))->m_pServerObj->m_bidKeys,
             file)) {
        fError= true;
        channelError= (char*) "can't save bid";
        goto done;
    }

done:
    if(!bidconstructResponse(fError, &p, &nLeft, NULL, channelError)) {
        fprintf(g_logFile, "bidchannelServices::bidconstructResponse failed\n");
        return false;
    }

    // send response
    service->m_oSafeChannel.safesendPacket((byte*)buf, (int)strlen(reinterpret_cast<char*>(buf))+1,
                                   type, multi, final);
    return true;
}


bool bidchannelServices::getBids(bidRequest& oReq, serviceChannel* service, timer& myTimer)
{
    bool    fError= false;
    char    buf[BIGBUFSIZE];
    char*   p= buf;
    int     nLeft= BIGBUFSIZE;
    char*   channelError= NULL;

#ifdef  TEST
    fprintf(g_logFile, "bidchannelServices::getBids\n");
    fflush(g_logFile);
#endif

    // authenticate requestor
    // This should be the sellerClient program

    // serialize bids
    const char*  allbids= serializeList();
    if(allbids==NULL) {
        fError= true;
        channelError= (char*) "Cant serialize list";
        goto done;
    }

done:
    // construct response and transmit
    if(!bidconstructResponse(fError, &p, &nLeft, NULL, channelError)) {
        fprintf(g_logFile, "bidchannelServices::bidconstructResponse failed\n");
        return false;
    }
    // send bids if no error
    if(!fError) {
    }
    return true;
}


const char* bidchannelServices::serializeList()
{
    char    buf[BIGBUFSIZE];
    int     size= BIGBUFSIZE;
    char*   p= buf;
    int     i, n;

#ifdef  TEST
    fprintf(g_logFile, "bidchannelServices::serializeList\n%d bids\n", m_nBids);
    fflush(g_logFile);
#endif

    sprintf(p, "<Bids nbids='%d'>\n", m_nBids);
    n= strlen(buf);
    p+= n;
    size-= n;
    for(i=0; i<m_nBids; i++) {
        if(m_Bids[i]==NULL) {
            return NULL;
        }
        n= strlen(m_Bids[i]);
        if(n>(size-16)) {
            return NULL;
        }
        memcpy(p, m_Bids[i], n+1);
        p+= n;
        size-= n;
    }
    if(size<16) {
        return NULL;
    }
    sprintf(p, "</Bids>\n");
    return strdup(buf);
}


bool bidchannelServices::deserializeList(const char* list)
{
    TiXmlDocument   doc;
    char*           pbid= NULL;
    int             n= 0;

#ifdef  TEST
    fprintf(g_logFile, "bidchannelServices::deserializeList\n");
    fflush(g_logFile);
#endif

    if(!doc.Parse(list)) {
        fprintf(g_logFile, "bidchannelServices::deserializeList cant parse list\n");
        return false;
    }

    TiXmlElement*   pRootElement= doc.RootElement();
    TiXmlNode*      pNode= NULL;
    if(strcmp(pRootElement->Value(),"Bids")!=0) {
        fprintf(g_logFile, "bidchannelServices::deserializeList no Bids element\n");
        return false;
    }
    pRootElement->QueryIntAttribute ("nbids", &m_nBids);

    pNode= pRootElement->FirstChild();
    while(pNode!=NULL) {
        pbid= canonicalize(pNode);
        if(n>=(m_maxnBids-1)) {
            return false;
        }
        m_Bids[n++]= pbid;
        pNode= pNode->NextSibling();
    }

    if(n!=m_nBids)
        m_nBids= n;
    return true;
}


bool  bidchannelServices::appendBid(const char* bid)
{

#ifdef  TEST
    fprintf(g_logFile, "bidchannelServices::appendBid\n%s\n", bid);
    fflush(g_logFile);
#endif
    if(m_maxnBids<=m_nBids)
        return false;
    m_Bids[m_nBids++]= (char*) bid;
    return true;
}



bool  bidchannelServices::saveBids(serviceChannel* service, u32 enctype, byte* keys, const char* file)
{
    byte*   encrypted= NULL;
    int     sizeencrypted= 0;

#ifdef  TEST
    fprintf(g_logFile, "bidchannelServices::saveBids\n");
    fflush(g_logFile);
#endif

    // serialize bids
    const char* bids= serializeList();
    if(bids==NULL) {
        fprintf(g_logFile, "bidchannelServices::saveBids cant serialize\n");
        return false;
    }

#ifdef  TEST
    fprintf(g_logFile, "serialized bids\n%s\n", bids);
    fflush(g_logFile);
#endif

    // encrypt bids
    sizeencrypted= strlen(bids)+128;
    encrypted= (byte*)malloc(sizeencrypted);
    if(encrypted==NULL) {
        fprintf(g_logFile, "bidchannelServices::saveBids cant alloc\n");
        return false;
    }
    if(!AES128CBCHMACSHA256SYMPADEncryptBlob(strlen(bids)+1, (byte*)bids, 
                        &sizeencrypted, encrypted, &keys[0], &keys[16])) {
        fprintf(g_logFile, "bidchannelServices::saveBids cant decrypt\n");
        return false;
    }

    // save it to file
    if(!saveBlobtoFile(file, encrypted, sizeencrypted)) {
        fprintf(g_logFile, "bidchannelServices::saveBids cant save\n");
        return false;
    }
    return true;
}


bool  bidchannelServices::retrieveBids(u32 enctype, byte* keys, const char* file)
{
    byte*   encrypted= NULL;
    int     sizeEncrypted= 0;
    int     sizeout= 256;
    byte*   outbuf;

#ifdef  TEST
    fprintf(g_logFile, "bidchannelServices::retrieveBids\n");
    fflush(g_logFile);
#endif

    // read file
    if(!getBlobfromFile(file, encrypted, &sizeEncrypted)) {
        fprintf(g_logFile, "bidchannelServices::retrieveBids cant getBlob\n");
        return false;
    }
    sizeout= sizeEncrypted;
    outbuf= (byte*)malloc(sizeout);

    // decrypt it
    if(!AES128CBCHMACSHA256SYMPADDecryptBlob(sizeEncrypted, encrypted, &sizeout, outbuf,
                                                &keys[0], &keys[16])) {
        fprintf(g_logFile, "bidchannelServices::retrieveBids cant decrypt\n");
        return false;
    }

    // deserialize bid list
    if(!deserializeList((const char*) outbuf)) {
        fprintf(g_logFile, "bidchannelServices::retrieveBids cant deserialize\n");
        return false;
    }

    m_fBidListValid= true;
    return true;
}


bool bidchannelServices::servergetProtectedFileKey(bidRequest& oReq, timer& accessTimer)
{
    return false;
}


#else


bool bidchannelServices::clientgetProtectedFileKey(const char* file, timer& accessTimer)
{
    return false;
}


bool sendBlob(safeChannel& fc, byte* blob, int blobsize)
{
    int         type= CHANNEL_TRANSFER;
    byte        multi= 1;
    byte        final= 0;
    int         n;

    for(;;) {
        n= (blobsize>MAXREQUESTSIZE)?MAXREQUESTSIZE:blobsize;
        blobsize-= n;
        if(blobsize<=0)
            final= 1;
        fc.safesendPacket(blob, n, type, multi, final);
        if(final>0)
            break;
    }
    return true;
}


bool bidchannelServices::clientsendBid(safeChannel& fc, byte* keys, const char* request,
                              timer& accessTimer)
{
    int         n;
    char        buf[BIGBUFSIZE];
    bidResponse oResponse;
    int         type= CHANNEL_RESPONSE;
    byte        multi= 0;
    byte        final= 0;

#ifdef TEST
    fprintf(g_logFile, "bidClient::clientsendBid\n%s\n", request);
    fflush(g_logFile);
#endif
    // send and get response
    if((n=fc.safesendPacket((byte*)request, strlen(request)+1, CHANNEL_REQUEST, 
                            0, 0))<0) {
        fprintf(g_logFile, 
                "clientsendBid: safesendPacket after constructRequest returns false\n");
        return false;
    }

    // should be a CHANNEL_RESPONSE, not multipart
    n= fc.safegetPacket((byte*)buf, MAXREQUESTSIZE, &type, &multi, &final);
    if(n<0) {
        fprintf(g_logFile, "clientsendBid: transmit error %d\n", n);
        return false;
    }
    buf[n]= 0;

#ifdef TEST
    fprintf(g_logFile, "bidClient::clientsendBid response %d\n%s\n", n, buf);
    fflush(g_logFile);
#endif
    oResponse.getDatafromDoc(buf);

    // check response
    if(oResponse.m_szAction==NULL || strcmp(oResponse.m_szAction, "accept")!=0) {
        fprintf(g_logFile, "clientsendBid: response is false\n");
        return false;
    }

#ifdef  TEST
    fprintf(g_logFile, "clientsendBid sending file\n");
    fflush(g_logFile);
#endif
    // send blob
    if(!sendBlob(fc, (byte*) request, n)) {
        fprintf(g_logFile, "clientsendBid cant send blob\n");
        return false;
    }

#ifdef  TEST
    fprintf(g_logFile, "clientsendBid returns true\n");
    fflush(g_logFile);
#endif
   return true;
}


bool bidchannelServices::requestbids(safeChannel& fc, byte* keys, const char* auctionID,
        timer& accessTimer)
{
    return false;
}

#endif


// ------------------------------------------------------------------------


#ifndef BIDCLIENT

// request loop for bidServer


int bidServerrequestService(const char* request, serviceChannel* service)
{
     bidRequest     oReq;

     if(!oReq.getDatafromDoc(request)) {
        fprintf(g_logFile, "fileServerrequestService: cant parse: %s\n",
                request);
            return -1;
     }
    if(strcmp(oReq.m_szAction, "submitBid")==0) {
         if(!SERVICESOBJ(acceptBid)(oReq, service, TIMER(m_decTimer))) {
             fprintf(g_logFile, "acceptBid failed 1\n");
             return -1;
         }
         return 1;
     }
    else if(strcmp(oReq.m_szAction, "getBids")==0) {
         if(!SERVICESOBJ(getBids)(oReq, service, TIMER(m_decTimer))) {
             fprintf(g_logFile, "acceptBid failed 1\n");
             return -1;
         }
         return 1;
     }
    else if(strcmp(oReq.m_szAction, "getProtectedKey")==0) {
        if(!SERVICESOBJ(servergetProtectedFileKey)(oReq, TIMER(m_accessCheckTimer))) {
            fprintf(g_logFile, 
                "bidServerrequestService:: servergetProtectedKey failed\n");
            return -1;
        }
        return 1;
    }
    else {
        fprintf(g_logFile, "bidServerrequestService: invalid request type\n");
        return -1;
    }
}
#endif


// ----------------------------------------------------------------------------


