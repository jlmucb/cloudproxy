//
//  File: bidrequest.h
//  Description: cloudProxy channel request-response channel defines
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


// -----------------------------------------------------------------------------


#ifndef _BIDREQUEST__H
#define _BIDREQUEST__H

#include "jlmTypes.h"
#include "jlmUtility.h"
#include "keys.h"
#include "session.h"
#include "channel.h"
#include "request.h"
#include "safeChannel.h"
#include "timer.h"


/*
 *  <Request>
 *      <Action> submitBid </Action>
 *      <EvidenceCollection count='2'>
 *          <EvidenceList count='1'>
 *          </EvidenceList>
 *      </EvidenceCollection>
 *      <AuctionID> </AuctionID>
 *      <UserID> </UserID>
 *      <Bid> </Bid>
 *      <Cert> </Cert>
 *  </Request>
 *
 *  <Response>
 *      <Action> accept, reject</Action>
 *      <ErrorCode> </ErrorCode>
 *  </Response>
 */


class bidRequest : public Request {
public:

                bidRequest();
                ~bidRequest();
    const char* m_szAuctionId;
    const char* m_szUserName;
    const char* m_szBid;
    const char* m_szEvidence;

    bool        getDatafromDoc(const char* szRequest);
#ifdef TEST
    void        printMe();
#endif
};


class bidResponse : public Response {
public:
    char*           m_szAction;
    char*           m_szErrorCode;
    char*           m_ResourceName;
    int             m_ResourceLength;

                    bidResponse();
                    ~bidResponse();

    bool            getDatafromDoc(char* szResponse);
#ifdef TEST
    void            printMe();
#endif
};


bool    bidconstructRequest(char** pp, int* piLeft, const char* szAction, 
                            const char*  szAuctionID, const char* szUserName, 
                            const char* szBid, const char* szEvidence);
bool    bidconstructResponse(bool fError, char** pp, int* piLeft, 
                        const char* szExtraResponseElements,
                        const char* szChannelError);

#ifdef SELLERCLIENT

bool getchannelBlob(safeChannel& fc, byte* buf, int* pdatasize);

#else

bool sendchannelBlob(safeChannel& fc, byte* buf, int size);

#endif   // SELLERCLIENT

#endif


// ------------------------------------------------------------------------------


