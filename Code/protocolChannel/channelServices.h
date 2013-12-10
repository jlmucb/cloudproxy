//
//  File: channelServices.h
//  Description: cloudProxy channel services prototype
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


#ifndef _CHANNELSERVICES__H
#define _CHANNELSERVICES__H

#include "jlmTypes.h"
#include "jlmUtility.h"
#include "keys.h"
#include "session.h"
#include "channel.h"
#include "safeChannel.h"
#include "request.h"
#include "timer.h"


class serviceChannel;


class channelServices {
public:
    u32         m_serviceType;
    bool        m_fserviceEnabled;
    enum        {FILESERVICES= 1, BIDSERVICES= 2};

    channelServices(u32 type);
    ~channelServices();
    bool        enablechannelServices(serviceChannel* service, void* pLocal);
    bool        initchannelServices(serviceChannel* service, void* pLocal);
    bool        closechannelServices();
};


#endif


// ------------------------------------------------------------------------------


