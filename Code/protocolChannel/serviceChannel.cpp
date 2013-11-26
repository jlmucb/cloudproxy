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
#include "fileServer.h"
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
#include "resource.h"
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
int      iQueueSize= 5;

#include "./policyCert.inc"
#include "./taoSetupglobals.h"
#define DEFAULTDIRECTORY    "/home/jlm/jlmcrypt"


#ifdef TEST
void printResources(objectManager<resource>* pRM);
#endif


// ------------------------------------------------------------------------


serviceChannel::serviceChannel()
{
    m_serverState= NOSTATE;
    m_fdChannel= -1;
    m_fChannelAuthenticated= false;
    m_ptaoHost= NULL;
    m_ptaoEnvironment= NULL;
    m_fThreadValid= false;
}


serviceChannel::~serviceChannel()
{
    //FIX: delete metadata?
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

        if(oReq.m_szResourceName==NULL) {
            fprintf(g_logFile, "serviceChannel::processRequests: Empty resource name\n");
            return -1;
        }

        if(strcmp(oReq.m_szAction, "getResource")==0) {
            if(!m_fileServices.serversendResourcetoclient(oReq,
                        m_pParent->m_accessCheckTimer, m_pParent->m_decTimer)) {
                fprintf(g_logFile, "serversendResourcetoclient failed 1\n");
                return -1;
            }
            return 1;
        }
        else if(strcmp(oReq.m_szAction, "sendResource")==0) {
            if(!m_fileServices.servergetResourcefromclient(oReq,  
                        m_pParent->m_accessCheckTimer, m_pParent->m_encTimer)) {
                fprintf(g_logFile, "servercreateResourceonserver failed\n");
                return -1;
            }
            return 1;
        }
        else if(strcmp(oReq.m_szAction, "createResource")==0) {
            if(!m_fileServices.servercreateResourceonserver(oReq,
                        m_pParent->m_accessCheckTimer)) {
                fprintf(g_logFile, "servercreateResourceonserver failed\n");
                return -1;
            }
            return 1;
        }
        else if(strcmp(oReq.m_szAction, "addOwner")==0) {
            if(!m_fileServices.serverchangeownerofResource(oReq,
                        m_pParent->m_accessCheckTimer)) {
                fprintf(g_logFile, "serveraddownertoResourcefailed\n");
                return -1;
            }
            return 1;
        }
        else if(strcmp(oReq.m_szAction, "removeOwner")==0) {
            if(!m_fileServices.serverchangeownerofResource(oReq,
                        m_pParent->m_accessCheckTimer)) {
                fprintf(g_logFile, "serverremoveownerfromResource failed\n");
                return -1;
            }
            return 1;
        }
        else if(strcmp(oReq.m_szAction, "deleteResource")==0) {
            if(!m_fileServices.serverdeleteResource(oReq,
                        m_pParent->m_accessCheckTimer)) {
                fprintf(g_logFile, "serverdeleteResource failed\n");
                return -1;
            }
            return 1;
        }
        else if(strcmp(oReq.m_szAction, "getProtectedKey")==0) {
            if(!m_fileServices.servergetProtectedFileKey(oReq,
                        m_pParent->m_accessCheckTimer)) {
                fprintf(g_logFile, 
                    "serviceChannel::processRequests: servergetProtectedKey failed\n");
                return -1;
            }
            return 1;
        }
        else {
            fprintf(g_logFile, 
                    "serviceChannel::processRequests: invalid request type\n");
            return -1;
        }
    }
}


bool serviceChannel::initServiceChannel(metaData* pMetaData, 
                                           safeChannel* pSafeChannel)
{
    int     n= 0;

#ifdef  TEST
    fprintf(g_logFile, "serviceChannel::initserviceChannel(%08x, %08x)\n",
            pMetaData, pSafeChannel);
    fflush(g_logFile);
#endif

    m_serverState= INITSTATE;

    RSAKey* ppolicyKey= (RSAKey*)m_pParent->m_opolicyCert.getSubjectKeyInfo();

    // Initialize program private key and certificate for session
    if(!m_serverSession.serverInit(m_pParent->m_tcHome.policyCertPtr(),
                                   ppolicyKey, m_pParent->m_tcHome.myCertPtr(),
                                   (RSAKey*)m_pParent->m_tcHome.privateKeyPtr())) {
        fprintf(g_logFile, "serviceChannel::serviceChannel: session serverInit failed\n");
        return false;
    }
#ifdef  TEST
    fprintf(g_logFile, "serviceChannel::initserviceChannel, serverInit complete\n");
    fflush(g_logFile);
#endif

    // copy my public key into server public key
    if(!m_pParent->m_tcHome.myCertValid() ||
           !m_serverSession.getServerCert(m_pParent->m_tcHome.myCertPtr())) {
        fprintf(g_logFile, "serviceChannel::serviceChannel: Cant load client public key structures\n");
        return false;
    }

    // negotiate channel
    m_pParent->m_protocolNegoTimer.Start();
    if(!m_serverSession.serverprotocolNego(m_fdChannel, m_oSafeChannel))
        throw("fileServer::Init: protocolNego failed\n");
    m_pParent->m_protocolNegoTimer.Stop();

    if(!m_fileServices.initFileServices(&m_serverSession, 
                                        &(m_pParent->m_opolicyCert),
                                        &(m_pParent->m_tcHome), 
                                        m_pParent->m_encType, m_pParent->m_fileKeys, 
                                        pMetaData, pSafeChannel)) {
        throw("serviceChannel::serviceChannel: can't init fileServices\n");
    }

    m_serverState= REQUESTSTATE;
    while((n=processRequests())!=0) {
        if(n<0)
            fprintf(g_logFile, "serviceChannel::serviceChannel: processRequest error\n");
        fflush(g_logFile);
        m_pParent->printTimers(g_logFile);
        m_pParent->resetTimers();
    }
    m_serverState= SERVICETERMINATESTATE;

#ifdef TEST
    fprintf(g_logFile, "serviceChannel: serviceChannel terminating\n");
    fflush(g_logFile);
#endif

    if(m_fdChannel>0) {
        close(m_fdChannel);
        m_fdChannel= -1;
    }
    return true;
}


void* channelThread(void* ptr)
{
    try {
        serviceChannel*  poSc= (serviceChannel*) ptr;

#ifdef TEST
        fprintf(g_logFile, "channelThread activated\n");
        fprintf(g_logFile, "\tptr: %08x\n", ptr);
        fprintf(g_logFile, "\tchannel: %d, parent: %08x\n",
                    poSc->m_fdChannel, poSc->m_pParent);
        fflush(g_logFile);
#endif
        // pthread_detatch(pthread_self());
        if(!poSc->initServiceChannel(poSc->m_pMetaData,
                                     &poSc->m_oSafeChannel))
            throw("channelThread: initServiceChannel failed\n");

        // delete enty in thread table in parent
        if(poSc->m_myPositionInParent>=0) 
            poSc->m_pParent->m_fthreadValid[poSc->m_myPositionInParent]= false;
        poSc->m_myPositionInParent= -1;
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


