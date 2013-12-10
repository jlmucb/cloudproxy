//
//  File: request.h
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


#ifndef _REQUEST__H
#define _REQUEST__H

#include "jlmTypes.h"
#include "jlmUtility.h"
#include "keys.h"
#include "session.h"
#include "channel.h"
#include "safeChannel.h"
#include "timer.h"


#define ACCEPT         100
#define REJECT         200


/*
 *  <Request>
 *      <Action> 
 *         app dependent
 *      </Action>
 *      <EvidenceCollection count='2'>
 *          <EvidenceList count='1'>
 *          </EvidenceList>
 *      </EvidenceCollection>
 *      additional fields are app dependent
 *  </Request>
 *
 *  <Response>
 *      <Action> accept, reject</Action>
 *      <ErrorCode> </ErrorCode>
 *	additional fileds are app dependent
 *      <ResoureName> </ResoureName>
 *      <ResoureLength> </ResoureLength>
 *  </Response>
 */


class Request {
public:
    char*       m_szAction;
    char*       m_szEvidence;

                Request();
                ~Request();

    bool        getDatafromDoc(const char* szRequest);
};


class Response {
public:
    char*           m_szAction;
    char*           m_szErrorCode;

                    Response();
                    ~Response();

    bool        getDatafromDoc(const char* szRequest);
};


#endif


// ------------------------------------------------------------------------------


