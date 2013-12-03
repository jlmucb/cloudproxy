//
//  File: serviceChannel.h
//  Description: serviceChannel defines
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


#ifndef _SERVICECHANNEL__H
#define _SERVICECHANNEL__H

#include "tao.h"

#include "session.h"
#include "channel.h"
#include "safeChannel.h"
#include "request.h"
#include "cert.h"
#include "algs.h"
#include "fileServices.h"
#include "channelServices.h"
#include "timer.h"
#include <pthread.h>


#define  MAXNUMCLIENTS  50


// Thread management for clients
class serviceThread {
public:
    bool                m_fthreadValid;
    pthread_t           m_threadData;
    int                 m_threadID;

    serviceThread();
    ~serviceThread();
};


void* channelThread(void* ptr);


class serviceChannel {
public:
    char*               m_serverType;
    int                 m_serverState;
    session             m_serverSession;

    int                 m_fdChannel;
    safeChannel         m_oSafeChannel;

    PrincipalCert*      m_pPolicyCert;
    KeyInfo*            m_policyKey;

    // these will be replaced by generic services
    bool                m_fServicesPresent;
    channelServices*    m_pchannelServices;
    void*               m_pchannelLocals;

    taoHostServices*    m_ptaoHost;
    taoEnvironment*     m_ptaoEnv;

    serviceThread*      m_pmyThread;

    // custom loop for service requests
    int (*m_requestService)(Request&, serviceChannel* service); 

    serviceChannel();
    ~serviceChannel();

    bool                initServiceChannel(const char* serverType, int newfd, 
                                PrincipalCert* pPolicyCert, taoHostServices* ptaoHost,
                                taoEnvironment * ptaoEnv, serviceThread* pmyThread,
                                int (*requestService)(Request&, serviceChannel*),
                                channelServices* pmyServices, void* pmyLocals);
    bool                runServiceChannel();
    int                 processRequests();
};


#endif


//-------------------------------------------------------------------------


