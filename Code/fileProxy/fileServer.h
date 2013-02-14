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
#include "secPrincipal.h"
#include "accessControl.h"
#include "algs.h"
#include "vault.h"


class fileServer {
public:
    int                 m_serverState;
    bool                m_fChannelAuthenticated;
    char*               m_szPort;
    char*               m_szAddress;

    taoHostServices     m_host;
    taoEnvironment      m_tcHome;

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

    fileServer();
    ~fileServer();

    bool    initServer(const char* configDirectory);
    bool    closeServer();
    bool    initPolicy();
    bool    initFileKeys();

    bool    protocolNego(int fd, safeChannel&, sessionKeys&);
    bool    initSafeChannel(int fd, safeChannel& fc, sessionKeys& oKeys);
    int     processRequests(safeChannel&, sessionKeys&, accessGuard&);
    bool    serviceChannel(int fd);
    bool    server();
};


#define SERVICENAME             "fileServer"
#define SERVICE_PORT            6000


#endif


//-------------------------------------------------------------------------


