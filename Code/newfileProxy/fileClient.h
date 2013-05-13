//
//  File: fileClient.h
//      John Manferdelli
//
//  Description: Symbol and class definitions for fileClient
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


//------------------------------------------------------------------------------------


#ifndef _FILECLIENT__H
#define _FILECLIENT__H


#include "channel.h"
#include "safeChannel.h"
#include "session.h"
#include "fileServices.h"
#include "objectManager.h"
#include "cert.h"
#include "tao.h"
#include "timer.h"

// #include "resource.h"
// #include "vault.h"

#include <string>


using std::string;


class fileClient {
public:
    taoHostServices     m_host;
    taoEnvironment      m_tcHome;
    fileServices        m_oServices;

    bool                m_fEncryptFiles;
    char*               m_szSealedKeyFile;
    bool                m_fKeysValid;
    u32                 m_uAlg;
    u32                 m_uMode;
    u32                 m_uPad;
    u32                 m_uHmac;
    int                 m_sizeKey;
    byte                m_fileKeys[SMALLKEYSIZE];

    session             m_clientSession;
    char*               m_szPort;
    char*               m_szAddress;
    int                 m_fd;
    safeChannel         m_fc;

    timer               m_sealTimer;
    timer               m_unsealTimer;
    timer               m_taoEnvInitializationTimer;
    timer               m_taoHostInitializationTimer;
    timer               m_protocolNegoTimer;
    timer               m_encTimer;
    timer               m_decTimer;

    fileClient();
    ~fileClient();

    bool    initClient(const char* configDirectory, const char* serverAddress, 
                       u_short serverPort, const char* certFile, 
                       const char* keyFile);
    bool    initPolicy();
    bool    initFileKeys();
    bool    closeClient();

    // testing interfaces
    void    closeConnection();
    bool    createResource(const string& subject, 
                    const string& evidenceFileName, const string& resource);
    bool    deleteResource(const string& subject, 
                    const string& evidenceFileName, const string& resource);
    bool    readResource(const string& subject, const string& evidenceFileName, 
                    const string& remoteResource, const string& localOutput);
    bool    writeResource(const string& subject, const string& evidenceFileName, 
                    const string& remoteResource, const string& fileName);
    bool    establishConnection(const char* keyFile, const char* certFile, 
                    const char* directory, const char* serverAddress, 
                    u_short serverPort);
    bool    compareFiles(const string& firstFile, const string& secondFile);
    void    printTimers(FILE* log);
    void    resetTimers();
};


#define SERVICENAME             "fileServer"
#define SERVICE_PORT            6000


#endif


//-------------------------------------------------------------------------------


