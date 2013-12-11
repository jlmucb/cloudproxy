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


bool bidchannelServices::acceptBid(bidRequest& oReq, serviceChannel* service, timer& myTimer)
{
    // construct Bid

    // const char* bidBody= NULL;

    // sign it and put it on list

    // save bids
    if(!saveBids(u32 enctype, byte* keys, const char* file)) {
        return false;
    }

    // construct response

    return true;
}


bool bidchannelServices::getBids(bidRequest& oReq, serviceChannel* service, timer& myTimer)
{
    // authenticate requestor

    // serialize bids
    const char*  allbids= serialize();
    if(*allbids==NULL) {
        return false;
    }

    // construct response and transmit

    return true;
}


#ifndef BIDCLIENT


const char* bidchannelServices::serializeList()
{
    char    buf[16384];
    // int  size= 16384;
    p= buf;

    sprintf(p, "<Bids nbids='%d'>\n", m_nBids);
    sprintf(p, "</Bids>\n");
    return strdup(buf);
}


bool bidchannelServices::deserializeList(const char* list)
{
    // TiXmlDocument   doc;
    return true;
}


bool  bidchannelServices::appendBid(const char* bid)
{
    if(m_maxnBids<=m_nBids)
        return false;
    m_Bids[m_nBids++]= bid;
    return true;
}



bool  bidchannelServices::saveBids(u32 enctype, byte* keys, const char* file)
{
    byte*   encrypted= NULL;
    int     sizeencrypted= 0;

    // serialize bids

    // encrypt bids

    // save it to file
    if(!saveBlobtoFile(file, encrypted, sizeencrypted)) {
        return false;
    }
    return true;
}


bool  bidchannelServices::retrieveBids(u32 enctype, byte* keys, const char* file)
{
    byte*   encrypted= NULL;
    int     sizeencrypted= 0;

    // read file
    if(!getBlobfromFile(file, encrypted, &sizeencrypted)) {
        return false;
    }

    // decrypt it

    // deserialize bid list

    return true;
}


bool bidchannelServices::servergetProtectedFileKey(bidRequest& oReq, timer& accessTimer)
{
#if 0
    bool                fError= true;
    byte                buf[MAXREQUESTSIZEWITHPAD];
    int                 iLeft= MAXREQUESTSIZE;
    char*               p= (char*)buf;
    int                 type= CHANNEL_RESPONSE;
    byte                multi= 0;
    byte                final= 0;
    encapsulatedMessage oM;
    int                 plainKeyBlobsize;
    char                szbase64encryptedKey[8192];
    int                 base64encryptedKeysize= 8192;
    char*               szEncapsulateKeyInfo= NULL;
    RSAKey*             sealingKey= NULL;
    const char*         szProtectedElement= NULL;
    const char*         szError= NULL;

#ifdef TEST
    fprintf(g_logFile, "fileServices::servergetProtectedFileKey\n");
    oReq.printMe();
    fflush(g_logFile);
#endif

    // oReq.m_szResourceName should be key name but we don't look at it now
    if(g_szFileKeyEscrowCert==NULL) {
        fprintf(g_logFile, 
              "fileServices::servergetProtectedFileKey: This app does not support escrow\n");
        fflush(g_logFile);
        fError= true;
        goto done;
    }

    // encapsulate and produce metadata
    // get embedded encapsulating key certificate
    oM.m_szCert= strdup(g_szFileKeyEscrowCert);

    // get key from Cert
    szEncapsulateKeyInfo= oM.getSubjectKeyInfo();
    if(szEncapsulateKeyInfo==NULL) {
        fprintf(g_logFile, 
                "fileServices::servergetProtectedFileKey: cant extract sealing key from %s\n", 
                oM.m_szCert);
        fError= true;
        goto done;
    }

    // Make RSAKey
    sealingKey= (RSAKey*)RSAKeyfromkeyInfo(szEncapsulateKeyInfo);
    if(sealingKey==NULL) {
        fprintf(g_logFile, "fileServices::servergetProtectedFileKey: cant parse key\n");
        fError= true;
        goto done;
    }

    // get key and encrypt
    if(m_encType==DEFAULTENCRYPT) {
        plainKeyBlobsize= 16;  // AES128
    }
    else {
        fprintf(g_logFile, "fileServices::servergetProtectedFileKey: unsupported file encryption key\n");
        fError= true;
        goto done;
    }
    if(!oM.setplainMessage(plainKeyBlobsize, m_metadataKey)) {
        fprintf(g_logFile, "fileServices::servergetProtectedFileKey: cant set plaintext\n");
        fError= true;
        goto done;
    }

    // seal key
    if(!oM.sealKey(sealingKey)) {
        fprintf(g_logFile, "fileServices::servergetProtectedFileKey: cant seal key\n");
        fError= true;
        goto done;
    }

    if(!oM.encryptMessage()) {
        fprintf(g_logFile, "fileServices::servergetProtectedFileKey: cant encrypt message\n");
        fError= true;
        goto done;
    }

    // serialize metadata
    oM.m_szXMLmetadata= oM.serializeMetaData();
    if(oM.m_szXMLmetadata==NULL) {
        fprintf(g_logFile, "fileServices::servergetProtectedFileKey: cant serialize metadata\n");
        fError= true;
        goto done;
    }

    // base64 encode encrypted key
    if(!toBase64(oM.m_sizeEncrypted, oM.m_rgEncrypted, 
                 &base64encryptedKeysize, szbase64encryptedKey)) {
        fprintf(g_logFile, "fileServices::servergetProtectedFileKey: cant base64 encode blob\n");
        fError= true;
        goto done;
    }
    szProtectedElement= constructProtectedElement(oM.m_szXMLmetadata, 
                                        (const char*) szbase64encryptedKey);
    if(szProtectedElement==NULL) {
        fprintf(g_logFile, 
              "fileServices::servergetProtectedFileKey: cant construct protected element\n");
        fError= true;
    }
    fError= false;

done: 
#ifdef TEST
    fprintf(g_logFile, "fileServices::servergetProtectedFileKey at done\n");
    fflush(g_logFile);
#endif
    // send response
    p= (char*)buf;
    if(!bidconstructResponse(fError, &p, &iLeft,  szProtectedElement, szError)) {
        fprintf(g_logFile, "fileServices::servergetProtectedFileKey: constructResponse failed\n");
        fflush(g_logFile);
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "HERE\n");
    fflush(g_logFile);
#endif
    m_pSafeChannel->safesendPacket(buf, strlen((char*)buf)+1, type, multi, final);
#ifdef TEST
    fprintf(g_logFile, "HERE\n");
    fflush(g_logFile);
#endif

    if(szProtectedElement!=NULL) {
        free((void*)szProtectedElement);
        szProtectedElement= NULL;
    }

#ifdef TEST
    fprintf(g_logFile, "fileServices::servergetProtectedFileKey returns %d\n", !fError);
    fflush(g_logFile);
#endif

    return !fError;
#else
    return true;
#endif
}

#else


bool bidchannelServices::clientgetProtectedFileKey(const char* file, timer& accessTimer)
{
#if 0
    char        szBuf[MAXREQUESTSIZEWITHPAD];
    int         iLeft= MAXREQUESTSIZE;
    char*       p= (char*)szBuf;
    Response    oResponse;
    int         n= 0;
    int         type= CHANNEL_REQUEST;
    byte        multi=0;
    byte        final= 0;

#ifdef  TEST
    fprintf(g_logFile, "clientgetProtectedFileKey()\n");
    fflush(g_logFile);
#endif
    // send request
    if(!constructRequest(&p, &iLeft, "getProtectedKey", NULL, "ServerFileKey", 0, NULL)) {
        fprintf(g_logFile, "clientgetProtectedFileKey: constructRequest returns false\n");
        return false;
    }
#ifdef  TEST1
    fprintf(g_logFile, "clientgetProtectedFileKey request\n%s\n", szBuf);
    fflush(g_logFile);
#endif
    if((n=m_pSafeChannel->safesendPacket((byte*)szBuf, strlen(szBuf)+1, CHANNEL_REQUEST, 0, 0))<0) {
        return false;
    }

    // should be a CHANNEL_RESPONSE, not multipart
    n= m_pSafeChannel->safegetPacket((byte*)szBuf, MAXREQUESTSIZE, &type, &multi, &final);
    if(n<0) {
        fprintf(g_logFile, "clientgetProtectedFileKey: sendResource error %d\n", n);
        return false;
    }
    szBuf[n]= 0;
    oResponse.getDatafromDoc(szBuf);
    if(strcmp(oResponse.m_szAction, "accept")!=0) {
        fprintf(g_logFile, "clientgetProtectedFileKey: rejected request\n");
        return false;
    }

    if(oResponse.m_szProtectedElement==NULL) {
        fprintf(g_logFile, "clientgetProtectedFileKey: no protected element in response\n");
        return false;
    }

    // save to file
    if(!saveBlobtoFile(file, (byte*) oResponse.m_szProtectedElement,
                       strlen(oResponse.m_szProtectedElement)+1)) {
        fprintf(g_logFile, "clientgetProtectedFileKey: can't write blob file\n");
        return false;
    }
#endif

    return true;
}
#endif


// ------------------------------------------------------------------------


// request loop for bidServer
#define TIMER(x) ((bidServerLocals*)(service->m_pchannelLocals))->m_pServerObj->x
#define LOCALOBJ(x) ((bidServerLocals*)(service->pchannelLocals))->m_pServerObj->x
#define SERVICESOBJ(x) ((bidchannelServices*)(service->m_pchannelServices))->x


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
    else if(strcmp(oReq.m_szAction, "getProtectedKey")==0) {
        if(!SERVICESOBJ(servergetProtectedFileKey)(oReq, TIMER(m_accessCheckTimer))) {
            fprintf(g_logFile, 
                "fileServerrequestService:: servergetProtectedKey failed\n");
            return -1;
        }
        return 1;
    }
    else {
        fprintf(g_logFile, "fileServerrequestService: invalid request type\n");
        return -1;
    }
}


// ----------------------------------------------------------------------------


