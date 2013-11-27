//
//  File: serviceChannel.cpp
//      John Manferdelli
//
//  Description: serviceChannel for CloudProxy
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


// ------------------------------------------------------------------------


#include "jlmTypes.h"
#include "logging.h"
#include "jlmcrypto.h"
#include "channel.h"
#include "safeChannel.h"
#include "channelstate.h"
#include "jlmUtility.h"
#include "tinyxml.h"
#include "session.h"
#include "request.h"
#include "tcIO.h"

#include "tao.h"

#include "serviceChannel.h"
#include "fileServices.h"
#include "cert.h"
#include "domain.h"

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
#include <pthread.h>
#include <errno.h>
#ifdef LINUX
#include <wait.h>
#endif


bool     g_fTerminateServer= false;


// ------------------------------------------------------------------------


serviceThread::serviceThread() 
{
    m_fthreadValid= false;
    m_threadData= 0;
    m_threadID= -1;
}


serviceThread::~serviceThread() 
{
}


// ------------------------------------------------------------------------


serviceChannel::serviceChannel()
{
    m_serverState= NOSTATE;
    m_serverType= NULL;
    m_fdChannel= -1;
    m_pPolicyCert= NULL;
    m_ptaoHost= NULL;
    m_ptaoEnv= NULL;
    m_pmyThread= NULL;
    m_sharedServices= NULL;
    m_requestService= NULL;
    m_policyKey= NULL;
    m_encType= 0;
    m_fileKeys= NULL;     
    m_pMetaData= NULL;    
    m_fFileServicesPresent= false;
}


serviceChannel::~serviceChannel()
{
    // No deletions required
    m_serverState= NOSTATE;
    m_serverType= 0;
    m_fdChannel= -1;
    m_pPolicyCert= NULL;
    m_ptaoHost= NULL;
    m_ptaoEnv= NULL;
    m_pmyThread= NULL;
    m_sharedServices= NULL;
    m_requestService= NULL;
    if(m_serverType!=NULL) {
        free(m_serverType);
        m_serverType= NULL;
    }
}


int serviceChannel::processRequests()
{
    byte    request[MAXREQUESTSIZEWITHPAD];
    int     type= 0;
    byte    multi= 0;
    byte    final= 0;
    int     len= 0;

#ifdef TEST
    fprintf(g_logFile, "\n\nserviceChannel: processRequest\n");
    fflush(g_logFile);
#endif
    m_serverState= REQUESTSTATE;

    len= m_oSafeChannel.safegetPacket(request, MAXREQUESTSIZE, &type, &multi, &final);
    if(len==0) {
#ifdef TEST
        fprintf(g_logFile, "serviceChannel::processRequests: 0 return, channel close\n");
        fflush(g_logFile);
#endif
        return 0;
    }
    if(len<(int)sizeof(packetHdr)) {
        fprintf(g_logFile, "serviceChannel::processRequests: Can't get ProcessRequest packet\n");
        return -1;
    }

#ifdef TEST
    fprintf(g_logFile, "serviceChannel::processRequests: packetType %d, serverstate %d\n", 
            type, m_serverState);
    fflush(g_logFile);
#endif
    if(type==CHANNEL_TERMINATE) {
        fprintf(g_logFile, "Received CHANNEL_TERMINATE; returning 0 from serviceChannel::processRequests\n");
#ifdef TEST1
        tcBufferprint((tcBuffer*) request);
        fflush(g_logFile);
#endif
        fflush(g_logFile);
        return 0;
    }
    if(type!=CHANNEL_REQUEST) {
        fprintf(g_logFile, "serviceChannel::processRequests: Not a channel request\n");
        return -1;
    }

    {
        Request oReq;

        if(!oReq.getDatafromDoc(reinterpret_cast<char*>(request))) {
            fprintf(g_logFile, "serviceChannel::processRequests: cant parse: %s\n", 
                    request);
            return -1;
        }

        return m_requestService(oReq, this);
    }
}


bool serviceChannel::runServiceChannel()
{
    bool    fRet= true;
    int     n= 0;

#ifdef  TEST
    fprintf(g_logFile, "serviceChannel::runServiceChannel\n");
    fflush(g_logFile);
#endif

    try {
        m_serverState= INITSTATE;

        // Initialize program private key and certificate for session
        if(!m_serverSession.serverInit(m_ptaoEnv->policyCertPtr(),
                                   m_policyKey, 
                                   m_ptaoEnv->myCertPtr(),
                                   (KeyInfo*)m_ptaoEnv->privateKeyPtr())) 
            throw "serviceChannel::runServiceChannel: session serverInit failed\n";

#ifdef  TEST
        fprintf(g_logFile, "serviceChannel::runServiceChannel, serverInit complete\n");
        fflush(g_logFile);
#endif

        // copy my public key into server public key
        if(!m_ptaoEnv->myCertValid() || !m_serverSession.getServerCert(m_ptaoEnv->myCertPtr())) 
            throw "serviceChannel::runServiceChannel: Cant load client public key structures\n";

        // negotiate channel
#if 0
        m_pParent->m_protocolNegoTimer.Start();
#endif
        if(!m_serverSession.serverprotocolNego(m_fdChannel, m_oSafeChannel)) 
            throw "serviceChannel::runServiceChannel: protocolNego failed\n";
#if 0
    m_pParent->m_protocolNegoTimer.Stop();
#endif

        if(m_fFileServicesPresent) {
            if(!m_ofileServices.initFileServices(&m_serverSession, m_pPolicyCert, 
                                        m_ptaoEnv, m_encType, m_fileKeys,
                                        m_pMetaData, &m_oSafeChannel))
            throw("serviceChannel::runServiceChannel: can't initFileServices\n");
        }
    
        m_serverState= REQUESTSTATE;
        while((n=processRequests())!=0) {
            if(n<0)
                fprintf(g_logFile, "serviceChannel::runServiceChannel processRequest error\n");
#if 0
            m_pParent->printTimers(g_logFile);
            m_pParent->resetTimers();
#endif
        }
        m_serverState= SERVICETERMINATESTATE;

#ifdef TEST
        fprintf(g_logFile, "serviceChannel::runServiceChannel terminating\n");
        fflush(g_logFile);
#endif
    }
    catch(const char* szErr) {
        fprintf(g_logFile, "serviceChannel::runServiceChannel error: %s\n", szErr);
        fRet= false;
    }

#ifdef TEST
    fprintf(g_logFile, "serviceChannel: runServiceChannel terminating\n");
    fflush(g_logFile);
#endif

    if(m_fdChannel>0) {
        close(m_fdChannel);
        m_fdChannel= -1;
    }

    return fRet;
}


bool serviceChannel::enableFileServices(u32 encType, byte* fileKeys, metaData* pMetaData)
{
    m_fFileServicesPresent= true;
    m_encType= encType;
    m_fileKeys= fileKeys;     
    m_pMetaData= pMetaData;    
    return true;
}


bool serviceChannel::initServiceChannel(const char* serverType, int newfd, 
                                        PrincipalCert* pPolicyCert,
                                        taoHostServices* ptaoHost,
                                        taoEnvironment * ptaoEnv, serviceThread* pmyThread,
                                        int (*requestService)(Request&, serviceChannel*),
                                        void* pmySharedServices)
{
#ifdef  TEST
    fprintf(g_logFile, "serviceChannel::initserviceChannel\n");
    fflush(g_logFile);
#endif

    if(serverType!=NULL)
        m_serverType= strdup(serverType);
    if(newfd<0) {
        fprintf(g_logFile, "serviceChannel::initserviceChannel bad channel\n");
        return false;
    }
    m_fdChannel= newfd;

    if(pPolicyCert==NULL) {
        fprintf(g_logFile, "serviceChannel::initserviceChannel bad policy cert\n");
        return false;
    }
    m_pPolicyCert= pPolicyCert;

    m_policyKey= (KeyInfo*)m_pPolicyCert->getSubjectKeyInfo();

    if(ptaoHost==NULL) {
        fprintf(g_logFile, "serviceChannel::initserviceChannel bad tao Host\n");
        return false;
    }
    m_ptaoHost= ptaoHost;

    if(ptaoEnv==NULL) {
        fprintf(g_logFile, "serviceChannel::initserviceChannel bad tao Environment\n");
        return false;
    }
    m_ptaoEnv= ptaoEnv;

    if(pmyThread==NULL) {
        fprintf(g_logFile, "serviceChannel::initserviceChannel bad thread structure\n");
        return false;
    }
    m_pmyThread= pmyThread;

    if(requestService==NULL) {
        fprintf(g_logFile, "serviceChannel::initserviceChannel bad service request function\n");
        return false;
    }
    m_requestService= requestService;

    if(pmySharedServices==NULL) {
        fprintf(g_logFile, "serviceChannel::initserviceChannel bad shared services pointer\n");
        return false;
    }
    m_sharedServices= pmySharedServices;

    return true;
}


void* channelThread(void* ptr)
{

    // pthread_detatch(pthread_self());
    try {
        serviceChannel*  poSc= (serviceChannel*) ptr;

#ifdef TEST
        fprintf(g_logFile, "channelThread activated\n");
        fflush(g_logFile);
#endif
        if(!poSc->runServiceChannel())
            throw("channelThread: startServiceChannel failed\n");


        // delete enty in thread table in parent
        poSc->m_pmyThread->m_fthreadValid= false;
#ifdef TEST
        fprintf(g_logFile, "channelThread exiting\n");
        fflush(g_logFile);
#endif
        delete  poSc;
    } 
    catch (const char* err) {
        fprintf(g_logFile, "Server thread exited with error: %s\n", err);
        fflush(g_logFile);
    }

    pthread_exit(NULL);
    return NULL;
}
    

// ----------------------------------------------------------------------------


