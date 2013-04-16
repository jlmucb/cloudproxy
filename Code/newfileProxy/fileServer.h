//
//  File: fileServer.h
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


#ifndef _FILESERVER__H
#define _FILESERVER__H

#include "tao.h"

#include "session.h"
#include "channel.h"
#include "safeChannel.h"
#include "objectManager.h"
#include "resource.h"
#include "cert.h"
#include "accessControl.h"
#include "algs.h"
#include "timer.h"
#include "vault.h"
#include <pthread.h>


#define  MAXNUMCLIENTS  50



class fileServer {
public:
    char*               m_szPort;
    char*               m_szAddress;

    int                 m_iNumClients;
    bool                m_fthreadValid[MAXNUMCLIENTS];
    pthread_t           m_threadData[MAXNUMCLIENTS];
    int                 m_threadIDs[MAXNUMCLIENTS];

    taoHostServices     m_host;
    taoEnvironment      m_tcHome;

    metaData            m_oMeta;

    //    Keys for file encryption
    bool                m_fEncryptFiles;
    char*               m_szSealedKeyFile;
    bool                m_fKeysValid;
    u32                 m_uAlg;
    u32                 m_uMode;
    u32                 m_uPad;
    u32                 m_uHmac;
    int                 m_sizeKey;
    byte                m_fileKeys[SMALLKEYSIZE];

    timer               m_sealTimer;
    timer               m_unsealTimer;
    timer               m_taoEnvInitializationTimer;
    timer               m_taoHostInitializationTimer;
    timer               m_protocolNegoTimer;
    timer               m_accessCheckTimer;
    timer               m_encTimer;
    timer               m_decTimer;

    fileServer();
    ~fileServer();

    bool    initServer(const char* configDirectory);
    bool    closeServer();
    bool    initPolicy();
    bool    initFileKeys();

    bool    server();

    void    printTimers(FILE* log);
    void    resetTimers();	
};


//  thread for client channel
void* channelThread(void* ptr);


class theServiceChannel {
public:
    fileServer*         m_pParent;
    int                 m_myPositionInParent;
    int                 m_serverState;
    accessGuard         m_oAG;

    session             m_serverSession;
    bool                m_fChannelAuthenticated;
    int                 m_fdChannel;
    safeChannel         m_oSafeChannel;

    theServiceChannel();
    ~theServiceChannel();

    bool    initServiceChannel();
    int     processRequests();
    bool    serviceChannel();
};


#define SERVICENAME             "fileServer"
#define SERVICE_PORT            6000


#endif


//-------------------------------------------------------------------------


