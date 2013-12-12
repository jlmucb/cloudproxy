//
//  File: bidServer.h
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


#ifndef _BIDSERVER__H
#define _BIDSERVER__H

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



class bidServer {
public:
    char*               m_szPort;
    char*               m_szAddress;

    int                 m_iNumClients;
    serviceThread       m_serverThreads[MAXNUMCLIENTS];

    bool                m_fpolicyCertValid;
    PrincipalCert       m_opolicyCert;

    taoHostServices     m_host;
    taoEnvironment      m_tcHome;

    channelServices*    m_pchannelServices;


    //    Keys for bid encryption
    bool                m_fEncryptFiles;
    bool                m_fKeysValid;
    u32                 m_uAlg;
    u32                 m_uMode;
    u32                 m_uPad;
    u32                 m_uHmac;
    char*               m_szSealedKeyFile;
    int                 m_sizeKey;
    byte                m_bidKeys[GLOBALMAXSYMKEYSIZE];

    char*               m_szsigningCert;
    char*               m_szSigningCertFile;
    RSAKey*             m_signingKey;
    timer               m_sealTimer;
    timer               m_unsealTimer;
    timer               m_taoEnvInitializationTimer;
    timer               m_taoHostInitializationTimer;
    timer               m_protocolNegoTimer;
    timer               m_accessCheckTimer;
    timer               m_encTimer;
    timer               m_decTimer;

    bidServer();
    ~bidServer();

    bool    initServer(const char* configDirectory);
    bool    closeServer();
    bool    initPolicy();
    bool    initFileKeys();
    bool    initSigningandSealingKeys();

    bool    server();

    void    printTimers(FILE* log);
    void    resetTimers();      
};


#define SERVICENAME             "bidServer"
#define SERVICE_PORT            6000


#endif


//-------------------------------------------------------------------------


