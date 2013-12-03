//
//  File: bidServer.cpp
//      John Manferdelli
//
//  Description: Sever for bidServer
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
#include "bidServer.h"
#include "serviceChannel.h"
#include "jlmcrypto.h"
#include "channel.h"
#include "safeChannel.h"
#include "channelServices.h"
#include "channelstate.h"
#include "jlmUtility.h"
#include "tinyxml.h"
#include "session.h"
#include "sha256.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "cryptoHelper.h"
#include "request.h"
#include "tcIO.h"

#include "tao.h"

#include "bidServices.h"
#include "objectManager.h"
#include "cert.h"
#include "validateEvidence.h"
#include "attest.h"
#include "trustedKeyNego.h"
#include "encryptedblockIO.h"
#include "domain.h"

#include "encapsulate.h"
#include "taoSetupglobals.h"

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


extern bool g_fTerminateServer;
int              iQueueSize= 5;

#include "./policyCert.inc"


int bidServerrequestService(Request& oReq, serviceChannel* service);


// ----------------------------------------------------------------------------


bidServer::bidServer()
{
    m_szPort= NULL;
    m_szAddress= NULL;
    m_iNumClients= 0;
    m_pchannelServices= NULL;
    m_fpolicyCertValid= false;

    m_fEncryptFiles= false;
    m_szSealedKeyFile= NULL;
    m_fKeysValid= false;
    m_uAlg= 0;
    m_uMode= 0;
    m_uPad= 0;
    m_uHmac= 0;
    m_sizeKey= GLOBALMAXSYMKEYSIZE;
    m_szSigningCertFile= NULL;
    m_szSealingCertFile= NULL;
    m_szsigningCert= NULL;
    m_szsealingCert= NULL;
    m_signingKey= NULL;
    m_sealingKey= NULL;
}


bidServer::~bidServer()
{
    if(m_szPort!=NULL) {
        free(m_szPort);
        m_szPort= NULL;
    }
    if(m_szAddress!=NULL) {
        free(m_szAddress);
        m_szAddress= NULL;
    }
    if(m_fKeysValid)
        memset(m_bidKeys, 0, m_sizeKey);
    m_fKeysValid= false;
    if(m_szSealedKeyFile!=NULL)
        free(m_szSealedKeyFile);
    m_szSealedKeyFile= NULL;

    if(m_szsigningCert!=NULL) {
        free(m_szsigningCert);
        m_szsigningCert= NULL;
    }
    if(m_sealingKey!=NULL) {
        delete m_sealingKey;
        m_sealingKey= NULL;
    }
    if(m_szsealingCert!=NULL) {
        free(m_szsealingCert);
        m_szsealingCert= NULL;
    }
}


bool bidServer::initPolicy()
{
#ifdef TEST
    fprintf(g_logFile, "bidServer::initPolicy\n");
    fflush(g_logFile);
#endif
    if(!m_tcHome.isValid()) {
        fprintf(g_logFile, "bidServer::initPolicy(): environment invalid\n");
        return false;
    }

    if(!m_tcHome.policyCertValid())  {
        fprintf(g_logFile, "fileServer::initPolicy(): policyKey invalid\n");
        return false;
    }

    // initialize policy cert
    if(!m_opolicyCert.init(m_tcHome.policyCertPtr())) {
        fprintf(g_logFile, "fileServer::Init:: Can't init policy cert 1\n");
        return false;
    }
    if(!m_opolicyCert.parsePrincipalCertElements()) {
        fprintf(g_logFile, "fileServer::Init:: Can't init policy key 2\n");
        return false;
    }
    m_fpolicyCertValid= true;

#ifdef TEST
    fprintf(g_logFile, "bidServer::initPolicy, returning true\n");
    fflush(g_logFile);
#endif
    return true;
}


bool bidServer::initSigningandSealingKeys()
{
    if(!m_tcHome.privateKeyValid()) {
        fprintf(g_logFile, "bidServer::initSigningandSealingKeys: private key not valid\n");
        return false;
    }

    // FIX
#if 0
    int     size= 4096;
    int     bufSize= 4096;
    byte    buf[4096];

    m_signingKey= (RSAKey*)m_tcHome.m_privateKey;
    if(m_signingKey==NULL) {
        fprintf(g_logFile, "bidServer::initSigningandSealingKeys: private key empty\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "bidServer::initSigningandSealingKeys: signingKey\n");
    m_signingKey->printMe();
#endif

    m_szSigningCertFile= strdup("./bidServer/cert");
    if(!getBlobfromFile(m_szSigningCertFile, buf, &size)) {
        fprintf(g_logFile, 
                "bidServer::initSigningandSealingKeys: Can't read signing cert, %s\n", 
                m_szsigningCert);
        return false;
    }
    m_szsigningCert= strdup((char *)buf);

    m_szsealingCert= strdup("./bidServer/sealingCert");
    size= bufSize;      
    if(!getBlobfromFile(m_szsealingCert, buf, &size)) {
        fprintf(g_logFile, "bidServer::initSigningandSealingKeys: Can't read sealing cert, %s\n", m_szsealingCert);
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "Got a sealing cert of length %d\n", size);
    fflush(g_logFile);
#endif
    
    m_szsealingCert= strdup((char *)buf);

    // Fix: validate sealing principal

    // get keyinfo from sealing Cert and initialize key
    if(!g_sealingPrincipal.init(m_szsealingCert)) {
        fprintf(g_logFile, "bidServer::initSigningandSealingKeys: can't init seal Cert\n");
        return false;
    }

    if(!g_sealingPrincipal.parsePrincipalCertElements()) {
        fprintf(g_logFile, "bidServer::initSigningandSealingKeys: can't parse seal Cert\n%s\n",
                m_szsealingCert);
        return false;
    }

    m_sealingKey= NULL;  // FIX (RSAKey*)g_sealingPrincipal.getSubjectKeyInfo();
    if(m_sealingKey==NULL) {
        fprintf(g_logFile, "bidServer::initSigningandSealingKeys: can't get keyinfo from seal Cert\n");
        fflush(g_logFile);
        return false;
    }
#endif

    return true;
}


bool bidServer::initFileKeys()
{
    struct stat statBlock;
    char        szName[256];
    int         size= 0;
    byte        keyBuf[GLOBALMAXSYMKEYSIZE];
    int         n= 0;
    int         m= 0;
    byte        sealedkeyBuf[GLOBALMAXSEALEDKEYSIZE];
   
    if(m_tcHome.m_fileNames.m_szdirectory==NULL) {
        fprintf(g_logFile, "initFileKeys: No home directory for keys\n");
        return false;
    }
    sprintf(szName, "%s/fileKeys", m_tcHome.m_fileNames.m_szdirectory);
    m_szSealedKeyFile= strdup(szName);
    if(stat(m_szSealedKeyFile, &statBlock)<0) {
        // Keys don't exist, generate and save them
        m_uAlg= AES128;
        m_uMode= CBCMODE;
        m_uPad= SYMPAD;
        m_uHmac= HMACSHA256;
        if(m_sizeKey<32) {
            fprintf(g_logFile, "initFileKeys: key size too small\n");
            return false;
        }
        m_sizeKey= 32;
        if(!getCryptoRandom(m_sizeKey*NBITSINBYTE, m_bidKeys)) {
            fprintf(g_logFile, "initFileKeys: cant generate keys\n");
            return false;
        }

        // key buf: sizeKey,alg,mode,pad,hmac, key
        memcpy(&keyBuf[n], &m_sizeKey, sizeof(int));
        n+= sizeof(int);
        memcpy(&keyBuf[n], &m_uAlg, sizeof(u32));
        n+= sizeof(u32);
        memcpy(&keyBuf[n], &m_uMode, sizeof(u32));
        n+= sizeof(u32);
        memcpy(&keyBuf[n], &m_uPad, sizeof(u32));
        n+= sizeof(u32);
        memcpy(&keyBuf[n], &m_uHmac, sizeof(u32));
        n+= sizeof(u32);
        memcpy(&keyBuf[n], m_bidKeys, m_sizeKey);
        n+= m_sizeKey;

        if(!m_tcHome.measurementValid()) {
            fprintf(g_logFile, "initFileKeys: measurement invalid\n");
            return false;
        }
        // seal and save
        size= GLOBALMAXSEALEDKEYSIZE;
        if(!m_tcHome.Seal(m_tcHome.measurementSize(), m_tcHome.measurementPtr(),
                        n, keyBuf, &size, sealedkeyBuf)) {
            fprintf(g_logFile, "initFileKeys: cant seal keys\n");
            return false;
        }
        if(!saveBlobtoFile(m_szSealedKeyFile, sealedkeyBuf, size)) {
            fprintf(g_logFile, "initFileKeys: cant save sealed keys\n");
            return false;
        }
        m_fKeysValid= true;
    }
    else {
        // keys exist, unseal them
        size= GLOBALMAXSEALEDKEYSIZE;
        if(!getBlobfromFile(m_szSealedKeyFile, sealedkeyBuf, &size)) {
            fprintf(g_logFile, "initFileKeys: cant get sealed keys\n");
            return false;
        }
        if(!m_tcHome.measurementValid()) {
            fprintf(g_logFile, "initFileKeys: measurement invalid\n");
            return false;
        }
        m= GLOBALMAXSYMKEYSIZE;
        if(!m_tcHome.Unseal(m_tcHome.measurementValid(), m_tcHome.measurementPtr(),
                        size, sealedkeyBuf, &m, keyBuf)) {
            fprintf(g_logFile, "initFileKeys: cant unseal keys\n");
            return false;
        }
        memcpy(&m_sizeKey, &keyBuf[n], sizeof(int));
        n+= sizeof(int);
        memcpy(&m_uAlg, &keyBuf[n], sizeof(u32));
        n+= sizeof(u32);
        memcpy(&m_uMode, &keyBuf[n], sizeof(u32));
        n+= sizeof(u32);
        memcpy(&m_uPad, &keyBuf[n], sizeof(u32));
        n+= sizeof(u32);
        memcpy(&m_uHmac, &keyBuf[n], sizeof(u32));
        n+= sizeof(u32);
        memcpy(m_bidKeys, &keyBuf[n], m_sizeKey);
        n+= m_sizeKey;
        if(n>m) {
            fprintf(g_logFile, "initFileKeys: unsealed keys wrong size\n");
            return false;
        }
        m_fKeysValid= true;
    }

#ifdef  TEST
    fprintf(g_logFile, "initFileKeys\n");
    PrintBytes("fileKeys\n", m_bidKeys, m_sizeKey);
    fflush(g_logFile);
#endif
    return true;
}


#define DEFAULTDIRECTORY    "/home/jlm/jlmcrypt"


bool bidServer::initServer(const char* configDirectory)
{
    bool            fRet= true;
    const char*     directory= NULL;

    try {

        const char** parameters = NULL;
        int parameterCount = 0;
        if(configDirectory==NULL) {
            directory= DEFAULTDIRECTORY;
            
        } else {
            directory= configDirectory;
            parameters= &directory;
            parameterCount= 1;
        }

        if(!initAllCrypto()) {
            throw "bidServer::Init: can't initcrypto\n";
        }

        // init Host and Environment
        m_taoHostInitializationTimer.Start();
        if(!m_host.HostInit(g_hostplatform, g_hostProvider, g_hostDirectory,
                            g_hostsubDirectory, parameterCount, parameters)) {
            throw "bidServer::Init: can't init host\n";
        }
        m_taoHostInitializationTimer.Stop();
#ifdef TEST
        fprintf(g_logFile, "bidServer::Init: after HostInit, pid: %d\n",
            getpid());
#endif

        // init environment
        m_taoEnvInitializationTimer.Start();
        if(!m_tcHome.EnvInit(g_envplatform, "bidServer", DOMAIN, g_hostDirectory,
                             "fileServer", &m_host, g_serviceProvider, 0, NULL)) {
            throw "bidServer::Init: can't init environment\n";
        }
        m_taoEnvInitializationTimer.Stop();
#ifdef TEST
        fprintf(g_logFile, "bidServer::Init: after EnvInit\n");
        m_tcHome.printData();
#endif

        // Init global policy 
        if(!initPolicy())
            throw "bidServer::Init: Cant init policy objects\n";
#ifdef TEST
        fprintf(g_logFile, "initServer has private key and public key\n");
        fflush(g_logFile);
#endif

        // Initialize file encryption keys
        if(!initFileKeys())
            throw "bidServer::Init: can't init file keys\n";
#ifdef TEST
        fprintf(g_logFile, "bidServer::Init: after initFileKeys\n");
        m_tcHome.printData();
#endif

        if(!initSigningandSealingKeys())
            throw "bidServer::Init: Cant init signing keys\n";

#ifdef TEST
        fprintf(g_logFile, "initServer about to initPolicy();\n");
        fflush(g_logFile);
#endif
    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "bidServer error: %s\n", szError);
        fflush(g_logFile);
    }

#ifdef TEST
    if(fRet)
        fprintf(g_logFile, "bidServer initialized\n");
    else
        fprintf(g_logFile, "bidServer initialization failed\n");
#endif
    return fRet;
}


bool bidServer::closeServer()
{
    return true;
}


bool bidServer::server()
{
    int                 fd, newfd;
    struct sockaddr_in  server_addr, client_addr;
    int                 slen= sizeof(struct sockaddr_in);
    int                 clen= sizeof(struct sockaddr);
    int                 iError;

    fd= socket(AF_INET, SOCK_STREAM, 0);
    if(fd<0) {
        fprintf(g_logFile, "bidServer::server: Can't open socket\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "bidServer::server: socket opened\n");
    fflush(g_logFile);
#endif

    memset((void*) &server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family= AF_INET;
    server_addr.sin_addr.s_addr= htonl(INADDR_ANY);     // 127.0.0.1
    server_addr.sin_port= htons(SERVICE_PORT);

    iError= bind(fd,(const struct sockaddr *) &server_addr, slen);
    if(iError<0) {
        fprintf(g_logFile, "Can't bind socket: %s", strerror(errno));
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "bidServer::server: bind succeeded\n");
    fflush(g_logFile);
#endif

    listen(fd, iQueueSize);

    // set the signal disposition of SIGCHLD to not create zombies
    struct sigaction sigAct;
    memset(&sigAct, 0, sizeof(sigAct));
    sigAct.sa_handler = SIG_DFL;
    sigAct.sa_flags = SA_NOCLDWAIT; // don't zombify child processes
    int sigRv = sigaction(SIGCHLD, &sigAct, NULL);
    if (sigRv < 0) {
        fprintf(g_logFile, "Failed to set signal disposition for SIGCHLD\n");
    } 
    else {
        fprintf(g_logFile, "Set SIGCHLD to avoid zombies\n");
    }


    serviceChannel*     poSc= NULL;
    int                 i;
    for(;;) {
#ifdef TEST
        fprintf(g_logFile, "bidServer: top of accept loop\n");
        fflush(g_logFile);
#endif
        newfd= accept(fd, (struct sockaddr*) &client_addr, (socklen_t*)&clen);
        if(newfd<0) {
            fprintf(g_logFile, "Can't accept socket", strerror(errno));
            return false;
        }
#ifdef TEST
        fprintf(g_logFile, "bidServer: accept succeeded\n");
        fflush(g_logFile);
#endif

        poSc= new serviceChannel();

        if(poSc!=NULL) {

            for(i=0; i<m_iNumClients; i++) {
                if(!m_serverThreads[i].m_fthreadValid)
                    break;
            }

            if(i==m_iNumClients) {
                if(m_iNumClients>=MAXNUMCLIENTS) {
                    fprintf(g_logFile, "fileServer::server: Can't allocate theServiceChannel\n");
                    return false;
                }
                i= m_iNumClients++;
            }

            // TODO: delete this object
            bidchannelServices* pmyServices= new bidchannelServices(0);
            bidServerLocals* pmyLocals= new bidServerLocals();

            // pmySharedServices->m_pServerObj= this;
            if(!poSc->initServiceChannel("bidServer", newfd, &m_opolicyCert, &m_host,
                                         &m_tcHome, &m_serverThreads[i],
                                         bidServerrequestService, pmyServices, pmyLocals)) {
                fprintf(g_logFile, "fileServer::server: Can't initServiceChannel\n");
                return false;
            }

            // poSc->m_signingKey=  m_signingKey;
            // poSc->m_sealingKey=  m_sealingKey;
#ifdef TEST
            fprintf(g_logFile, "\tnewfd: %d\n", newfd);
            fflush(g_logFile);
#endif
            memset(&m_serverThreads[i].m_threadData, 0, sizeof(pthread_t));
            m_serverThreads[i].m_threadID= pthread_create(&m_serverThreads[i].m_threadData, NULL,
                                    channelThread, poSc);
#ifdef TEST
            fprintf(g_logFile, "fileServer: pthread create returns: %d\n",
                    m_serverThreads[i].m_threadID);
            fflush(g_logFile);
#endif
            if(m_serverThreads[i].m_threadID>=0)
                m_serverThreads[i].m_fthreadValid= true;
            else
                m_serverThreads[i].m_fthreadValid= false;
        }
        else {
            fprintf(g_logFile, "fileServer::server: Can't allocate theServiceChannel\n");
        }


        poSc= NULL;
        newfd= -1;
        if(g_fTerminateServer)
            break;
    }

    close(fd);
    fflush(g_logFile);
    return true;
}


// --------------------------------------------------------------------------


int main(int an, char** av)
// bidServer.exe [-initKeys address-of-managementserver]
{
    bidServer  oServer;
    int         i;
    int         iRet= 0;
    const char* directory= NULL;


    initLog(NULL);
#ifdef TEST
    fprintf(g_logFile, "bidServer main: bidServer started\n");
    fflush(g_logFile);
#endif
    // check arguments
    if(an>1) {
        for(i=0;i<an;i++) {
            if(strcmp(av[i],"-address")==0) {
                oServer.m_szAddress= strdup(av[++i]);
             }
            if(strcmp(av[i],"-directory")==0) {
                directory= strdup(av[++i]);
            }
        }
    }

#ifdef DONTENCRYPTFILES
    oServer.m_fEncryptFiles= false;
#else
    oServer.m_fEncryptFiles= true;
#endif

    initLog("bidServer.log");
#ifdef TEST
        fprintf(g_logFile, "bidServer main: measured server about to init server\n");
        fflush(g_logFile);
#endif

    try {
        if(!oServer.initServer(directory)) 
            throw "bidServer main: cant initServer\n";

#ifdef TEST
        fprintf(g_logFile, "bidServer main: measured server entering server loop\n");
        fflush(g_logFile);
#endif
        oServer.server();
        oServer.closeServer();
        closeLog();
    } 
    catch(const char* szError) {
        fprintf(g_logFile, "%s", szError);
        iRet= 1;
    }

    return iRet;

}


// ------------------------------------------------------------------------


void bidServer::printTimers(FILE* log) {
    if (m_sealTimer.GetMeasurements().size() > 0) {
        fprintf(log, "serverSealTimes = ");
        m_sealTimer.print(log);
    }

    if (m_unsealTimer.GetMeasurements().size() > 0) {
        fprintf(log, "serverUnsealTimes =  ");
        m_unsealTimer.print(log);
    }

    if (m_taoEnvInitializationTimer.GetMeasurements().size() > 0) {
        fprintf(log, "serverTaoEnvInitTimes = ");
        m_taoEnvInitializationTimer.print(log);
    }

    if (m_taoHostInitializationTimer.GetMeasurements().size() > 0) {
        fprintf(log, "serverTaoHostInitTimes = ");
        m_taoHostInitializationTimer.print(log);
    }

    if (m_protocolNegoTimer.GetMeasurements().size() > 0) {
        fprintf(log, "serverProtocolNegoTimes = ");
        m_protocolNegoTimer.print(log);
    }

    if (m_accessCheckTimer.GetMeasurements().size() > 0) {
        fprintf(log, "serverAccessCheckTimes = ");
        m_accessCheckTimer.print(log);
    }

    if (m_encTimer.GetMeasurements().size() > 0) {
        fprintf(log, "serverEncTimes = ");
        m_encTimer.print(log);
    }

    if (m_decTimer.GetMeasurements().size() > 0) {
        fprintf(log, "serverDecTimes = ");
        m_decTimer.print(log);
    }
}

void bidServer::resetTimers() {
    m_sealTimer.Clear();
    m_unsealTimer.Clear();
    m_taoEnvInitializationTimer.Clear();
    m_taoHostInitializationTimer.Clear();
    m_protocolNegoTimer.Clear();
    m_accessCheckTimer.Clear();
    m_encTimer.Clear();
    m_decTimer.Clear();
}

// ------------------------------------------------------------------------




