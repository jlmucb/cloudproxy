//  File: bidRequest.cpp
//  Description: cloudProxy request response objects
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
#include "bidRequest.h"
#include "encryptedblockIO.h"

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


const char*   s_szRequestTemplate=
"<Request>\n"\
"  <Action> %s </Action>\n"\
"  <AuctionID> %s </AuctionID>\n"\
"  <UserName> %s </UserName>\n"\
"  <Bid> %s </Bid>\n"\
"  <BidderCert> %s </BidderCert>\n"\
"%s"\
"</Request>\n";


const char*   s_szResponseTemplate=
"<Response>\n"\
"  <Action> %s </Action>\n"\
"  %s"\
"</Response>\n";


// ------------------------------------------------------------------------


bidRequest::bidRequest() : Request()
{
    m_szAction= NULL;
    m_szEvidence= NULL;
}


bidRequest::~bidRequest() 
{
    if(m_szEvidence!=NULL) {
        free((void*)m_szEvidence);
        m_szEvidence= NULL;
    }
    if(m_szAction!=NULL) {
        free(m_szAction);
        m_szAction= NULL;
    }
    if(m_szBid!=NULL) {
        free((void*)m_szBid);
        m_szBid= NULL;
    }
    if(m_szUserName!=NULL) {
        free((void*)m_szUserName);
        m_szUserName= NULL;
    }
    if(m_szAuctionId!=NULL) {
        free((void*)m_szAuctionId);
        m_szAuctionId= NULL;
    }
}


bool  bidRequest::getDatafromDoc(const char* szRequest)
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;

    const char*     szAction= NULL;
    const char*     szAuctionID= NULL;
    const char*     szUserName= NULL;
    const char*     szBid= NULL;
    const char*     szEvidence= NULL;

    if(szRequest==NULL)
        return false;

    if(!doc.Parse(szRequest)) {
        fprintf(g_logFile, "bidRequest::getDatafromDoc: Cant parse request\n");
        return false;
    }

    pRootElement= doc.RootElement();
    if(strcmp(pRootElement->Value(),"Request")!=0) {
        fprintf(g_logFile, "bidRequest::getDatafromDoc: Should be request\n");
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
            if(strcmp(((TiXmlElement*)pNode)->Value(),"UserName")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1) {
                    szUserName= pNode1->Value();
                }
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"AuctionID")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1) {
                    szAuctionID= pNode1->Value();
                }
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"Bid")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1) {
                    szBid= pNode1->Value();
                }
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"BidderCert")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL)
                    szEvidence= canonicalize(pNode1);
                else
                    szEvidence= NULL;
            }
        }
        pNode= pNode->NextSibling();
    }

    if(szAction==NULL)
        return false;
    else
        m_szAction= strdup(szAction);

    if(szEvidence!=NULL)
        m_szEvidence= strdup(szEvidence);
    if(szBid!=NULL)
        m_szBid= strdup(szBid);
    if(szUserName!=NULL)
        m_szUserName= strdup(szUserName);
    if(szAuctionID!=NULL)
        m_szAuctionId= strdup(szAuctionID);

#ifdef TEST1
    fprintf(g_logFile, "bidRequest getdata\n");
    printMe();
    fflush(g_logFile);
#endif
    return true;
}


#ifdef TEST
void bidRequest::printMe()
{
    fprintf(g_logFile, "\n\tbidRequest action: %s\n", m_szAction);
    if(m_szEvidence==NULL)
        fprintf(g_logFile, "\tm_szEvidence is NULL\n");
    else
        fprintf(g_logFile, "\tm_szEvidence: %s \n", m_szEvidence);
    if(m_szAuctionId==NULL)
        fprintf(g_logFile, "\tm_szAuctionId is NULL\n");
    else
        fprintf(g_logFile, "\tm_szAuctionId: %s \n", m_szAuctionId);
    if(m_szUserName==NULL)
        fprintf(g_logFile, "\tm_szUserName is NULL\n");
    else
        fprintf(g_logFile, "\tm_szUserName: %s \n", m_szEvidence);
    if(m_szBid==NULL)
        fprintf(g_logFile, "\tm_szBid is NULL\n");
    else
        fprintf(g_logFile, "\tm_szBid: %s \n", m_szBid);
}
#endif


// ------------------------------------------------------------------------


#ifdef BIDCLIENT


bool getchannelBlob(safeChannel& fc, byte* buf, int* pdatasize)
{
    int                 type= CHANNEL_RESPONSE;
    byte                multi, final;
    int                 n= 0;
    int                 total= 0;

#ifdef TEST
    fprintf(g_logFile, "getchannelBlob %d\n", *pdatasize);
    fflush(g_logFile);
#endif

    // read channel
    type= CHANNEL_TRANSFER;
    multi= 1;
    final= 0;
    for(;;) {
	if(total>=*pdatasize) { // fix
	    fprintf(g_logFile, "getchannelBlob: list too big\n");
	    return false;
	}
        n= fc.safegetPacket(buf, MAXREQUESTSIZE, &type, &multi, &final);
	total+= n;
	buf+= n;
        if(final>0)
            break;
    }
#ifdef TEST
    fprintf(g_logFile, "getchannelBlob returns true, %d bytes\n", total);
    fflush(g_logFile);
#endif
    *pdatasize= total;
    return true;
}


#else

bool sendchannelBlob(safeChannel& fc, byte* buf, int size)
{
    int                 type= CHANNEL_RESPONSE;
    byte                multi, final;
    int                 n= 0;

#ifdef TEST
    fprintf(g_logFile, "sendchannelBlob %d bytes\b", size);
    fflush(g_logFile);
#endif

    // write channel
    type= CHANNEL_TRANSFER;
    multi= 1;
    final= 0;
    for(;;) {
	n= (size>MAXREQUESTSIZE)?MAXREQUESTSIZE:size;
        size-= n;
        if(size<=0)
            final= 1;
        fc.safesendPacket(buf, n, type, multi, final);
        if(final>0)
            break;
	buf+= n;
    }
#ifdef  TEST
    fprintf(g_logFile, "endchannelBlob returns true\n");
#endif
    return true;
}
#endif    // BIDCLIENT


bidResponse::bidResponse()
{
    m_szAction= NULL;
    m_szErrorCode= NULL;
}


bidResponse::~bidResponse()
{
    if(m_szAction!=NULL) {
        free(m_szAction);
        m_szAction= NULL;
    }
    if(m_szErrorCode!=NULL) {
        free(m_szErrorCode);
        m_szErrorCode= NULL;
    }
}


#ifdef TEST
void bidResponse::printMe()
{
    if(m_szAction==NULL)
        fprintf(g_logFile, "\tm_szAction is NULL\n");
    else
        fprintf(g_logFile, "\tm_szAction: %s \n", m_szAction);
    if(m_szErrorCode==NULL)
        fprintf(g_logFile, "\tm_szErrorCode is NULL\n");
    else
        fprintf(g_logFile, "\tm_szErrorCode: %s \n", m_szErrorCode);
}
#endif


bool  bidResponse::getDatafromDoc(char* szResponse)
{
    TiXmlDocument   doc;
    TiXmlElement*   pRootElement= NULL;
    TiXmlNode*      pNode= NULL;
    TiXmlNode*      pNode1= NULL;

#ifdef TEST1
    fprintf(g_logFile, "bidResponse::getDatafromDoc\n%s\n", szResponse);
    fflush(g_logFile);
#endif
    if(!doc.Parse(szResponse)) {
        fprintf(g_logFile, "bidResponse::getDatafromDoc: cant parse response\n");
        return false;
    }

    pRootElement= doc.RootElement();
    if(strcmp(pRootElement->Value(),"Response")!=0) {
        fprintf(g_logFile, "bidResponse::getDatafromDoc: Should be response\n");
        return false;
    }

    pNode= pRootElement->FirstChild();
    while(pNode) {
        if(pNode->Type()==TiXmlNode::TINYXML_ELEMENT) {
            if(strcmp(((TiXmlElement*)pNode)->Value(),"Action")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL)
                    m_szAction= strdup(pNode1->Value());
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"ErrorCode")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL)
                    m_szErrorCode= strdup(pNode1->Value());
                else
                    m_szErrorCode= NULL;
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"ResourceName")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL)
                    m_szErrorCode= strdup(pNode1->Value());
                else
                    m_szErrorCode= NULL;
            }
            if(strcmp(((TiXmlElement*)pNode)->Value(),"ResourceLength")==0) {
                pNode1= pNode->FirstChild();
                if(pNode1!=NULL)
                    m_szErrorCode= strdup(pNode1->Value());
                else
                    m_szErrorCode= NULL;
            }
        }
        pNode= pNode->NextSibling();
    }

#ifdef TEST1
    fprintf(g_logFile, "bidResponse getdata\n");
    printMe();
    fflush(g_logFile);
#endif
    return true;
}


// -------------------------------------------------------------------------


bool  bidconstructRequest(char** pp, int* piLeft, const char* szAction, 
                       const char* szAuctionID, const char* szUserName,
                       const char* szBid, const char* szEvidence)
{
    const char*   szNoEvidence= "  <EvidenceCollection count='0'/>\n";
    int           size= strlen(s_szRequestTemplate)+strlen(szAction);

    if(szEvidence==NULL) {
        szEvidence= szNoEvidence;
    }
    size+= strlen(szEvidence);
    if(szAuctionID==NULL) {
        fprintf(g_logFile, "bidconstructRequest: no auctionid\n");
        return false;
    }
    size+= strlen(szAuctionID);
    if(szBid==NULL) {
        fprintf(g_logFile, "bidconstructRequest: no bid\n");
        return false;
    }
    size+= strlen(szBid);
    if(szUserName==NULL) {
        fprintf(g_logFile, "bidconstructRequest: no user name\n");
        return false;
    }
    size+= strlen(szUserName);

    if((size+8)>*piLeft) {
        fprintf(g_logFile, "bidconstructRequest: request too large %d %d\n", size, *piLeft);
        return false;
    }    
    sprintf(*pp, s_szRequestTemplate, szAction, szAuctionID, szUserName, szBid, szEvidence, "");
    int len= strlen(*pp);
    *piLeft-= len;
    *pp+= len;
#ifdef  TEST1
    fprintf(g_logFile, "bidconstructRequest completed\n%s\n", p);
    fflush(g_logFile);
#endif
    return true;
}


bool  bidconstructResponse(bool fError, char** pp, int* piLeft, 
                        const char* szExtraResponseElements,
                        const char* szChannelError)
{
/*
 * <Response>
 *   %s
 *   <ResourceName> %s </ResourceName>
 *   <ResourceLength> %d </ResourceLength>
 * %s        Extra
 * </Response>
 */
#ifdef  TEST
    char* p= *pp;
#endif
    const char*   szErrorFormat= " <ErrorCode> %s </ErrorCode>\n";
    char          szErrorElement[256];
    const char*   szRes= NULL;

    int size= strlen(s_szResponseTemplate);
    if(fError)
        szRes= "reject";
    else
        szRes= "accept";
    size+= strlen(szRes);
    if(szExtraResponseElements!=NULL)
        size+= strlen(szExtraResponseElements);
    else
        szExtraResponseElements= "";
    if(szChannelError!=NULL) {
        if((strlen(szErrorFormat)+strlen(szChannelError)+8)>256) {
            fprintf(g_logFile, "bidconstructResponse: too large\n");
            return false;
        }
        sprintf(szErrorElement, szErrorFormat, szChannelError);
        size+= strlen(szErrorElement);
    }
    else {
        szErrorElement[0]= 0;
    }
    if((size+16)>*piLeft) {
        fprintf(g_logFile, "bidconstructResponse: response too large\n");
        return false;
    }

    sprintf(*pp, s_szResponseTemplate,  szRes, szErrorElement, szExtraResponseElements);

    int len= strlen(*pp);
    *piLeft-= len;
    *pp+= len;
#ifdef TEST
    fprintf(g_logFile, "bidconstructResponse completed\n%s\n", p);
    fflush(g_logFile);
#endif
    return true;
}


// -------------------------------------------------------------------------


