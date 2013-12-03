//
//  File: bidServices.h
//      John Manferdelli
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


//----------------------------------------------------------------------


#ifndef _BIDSERVICES__H
#define _BIDSERVICES__H

#include "tao.h"

#include "session.h"
#include "channel.h"
#include "serviceChannel.h"
#include "channelServices.h"
#include "safeChannel.h"
#include "objectManager.h"
#include "cert.h"
#include "algs.h"
#include "timer.h"
#include <pthread.h>


#define  MAXNUMCLIENTS  50


class bidServerLocals{
public:
    bidServer*          m_pServerObj;
};


class bidchannelServices : public channelServices {
public:
    bidchannelServices(u32 type);
    ~bidchannelServices();

#ifndef BIDCLIENT
    bool        servergetProtectedFileKey(Request& oReq, timer& accessTimer);
    bool        acceptBid(Request& oReq, serviceChannel* service, timer& myTimer);
#else
    bool        submitBid(Request& oReq, serviceChannel* service, timer& myTimer);
    bool        clientgetProtectedFileKey(Request& oReq, timer& accessTimer);
#endif
    bool        closechannelServices();
};


#endif


//-------------------------------------------------------------------------


