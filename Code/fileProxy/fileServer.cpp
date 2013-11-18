//
//  File: fileServer.cpp
//      John Manferdelli
//
//  Description: Sever for fileServer
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
#include "sha256.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "request.h"
#include "tcIO.h"

#include "tao.h"

#include "objectManager.h"
#include "resource.h"
#include "cert.h"
#include "accessControl.h"
#include "vault.h"
#include "trustedKeyNego.h"
#include "encryptedblockIO.h"
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


theServiceChannel::theServiceChannel()
{
    m_pParent= NULL;
    m_fdChannel= -1;
    m_serverState= NOSTATE;
    m_fChannelAuthenticated= false;
    m_pMetaData= NULL;
}


theServiceChannel::~theServiceChannel()
{
    //FIX: delete metadata?
}


int theServiceChannel::processRequests()
{
    byte    request[MAXREQUESTSIZEWITHPAD];
    int     type= 0;
    byte    multi= 0;
    byte    final= 0;

#ifdef TEST
    fprintf(g_logFile, "\n\ntheServiceChannel: processRequest\n");
#endif
    m_serverState= REQUESTSTATE;

    if(m_oSafeChannel.safegetPacket(request, MAXREQUESTSIZE, &type, &multi, &final)<
                    (int)sizeof(packetHdr)) {
        fprintf(g_logFile, "theServiceChannel::processRequests: Can't get ProcessRequest packet\n");
        return -1;
    }

#ifdef TEST
    fprintf(g_logFile, "theServiceChannel::processRequests: packetType %d, serverstate %d\n", 
            type, m_serverState);
    fflush(g_logFile);
#endif
    if(type==CHANNEL_TERMINATE) {
        fprintf(g_logFile, "Received CHANNEL_TERMINATE; returning 0 from theServiceChannel::processRequests\n");
#ifdef TEST
        tcBufferprint((tcBuffer*) request);
        fflush(g_logFile);
#endif
        fflush(g_logFile);
        return 0;
    }
    if(type!=CHANNEL_REQUEST) {
        fprintf(g_logFile, "theServiceChannel::processRequests: Not a channel request\n");
        return -1;
    }

    {
        Request oReq;

        if(!oReq.getDatafromDoc(reinterpret_cast<char*>(request))) {
            fprintf(g_logFile, "theServiceChannel::processRequests: cant parse: %s\n", 
                    request);
            return -1;
        }

        if(oReq.m_szResourceName==NULL) {
            fprintf(g_logFile, "theServiceChannel::processRequests: Empty resource name\n");
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
            fprintf(g_logFile, 
                    "theServiceChannel::processRequests: getProtectedKey not implemented\n");
            return -1;
        }
        else {
            fprintf(g_logFile, 
                    "theServiceChannel::processRequests: invalid request type\n");
            return -1;
        }
    }
}


bool theServiceChannel::initServiceChannel(metaData* pMetaData, 
                                           safeChannel* pSafeChannel)
{
    int     n= 0;

#ifdef  TEST
    fprintf(g_logFile, "theServiceChannel::initserviceChannel(%08x, %08x)\n",
            pMetaData, pSafeChannel);
    fflush(g_logFile);
#endif

    m_serverState= INITSTATE;

    RSAKey* ppolicyKey= (RSAKey*)m_pParent->m_opolicyCert.getSubjectKeyInfo();

    // Initialize program private key and certificate for session
    if(!m_serverSession.serverInit(m_pParent->m_tcHome.policyCertPtr(),
                                   ppolicyKey, m_pParent->m_tcHome.myCertPtr(),
                                   (RSAKey*)m_pParent->m_tcHome.privateKeyPtr())) {
        fprintf(g_logFile, "theServiceChannel::serviceChannel: session serverInit failed\n");
        return false;
    }
#ifdef  TEST
    fprintf(g_logFile, "theServiceChannel::initserviceChannel, serverInit complete\n");
    fflush(g_logFile);
#endif

    // copy my public key into server public key
    if(!m_pParent->m_tcHome.myCertValid() ||
           !m_serverSession.getServerCert(m_pParent->m_tcHome.myCertPtr())) {
        fprintf(g_logFile, "theServiceChannel::serviceChannel: Cant load client public key structures\n");
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
        throw("theServiceChannel::serviceChannel: can't init fileServices\n");
    }

    m_serverState= REQUESTSTATE;
    while((n=processRequests())!=0) {
        if(n<0)
            fprintf(g_logFile, "theServiceChannel::serviceChannel: processRequest error\n");
        fflush(g_logFile);
        m_pParent->printTimers(g_logFile);
        m_pParent->resetTimers();
    }
    m_serverState= SERVICETERMINATESTATE;

#ifdef TEST
    fprintf(g_logFile, "theServiceChannel: serviceChannel terminating\n");
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
        theServiceChannel*  poSc= (theServiceChannel*) ptr;

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


fileServer::fileServer()
{
    m_iNumClients= 0;
    m_fEncryptFiles= false;
    m_szSealedKeyFile= NULL;
    m_fKeysValid= false;
    m_uAlg= 0;
    m_uMode= 0;
    m_uPad= 0;
    m_uHmac= 0;
    m_sizeKey= GLOBALMAXSYMKEYSIZE;
    m_fpolicyCertValid= false;
}


fileServer::~fileServer()
{
    if(m_fKeysValid)
        memset(m_fileKeys, 0, m_sizeKey);
    m_fKeysValid= false;
    if(m_szSealedKeyFile!=NULL)
        free(m_szSealedKeyFile);
    m_szSealedKeyFile= NULL;
}


bool fileServer::initPolicy()
{
    if(!m_tcHome.isValid()) {
        fprintf(g_logFile, "fileServer::initPolicy(): environment invalid\n");
        return false;
    }

    if(!m_tcHome.policyCertValid())  {
        fprintf(g_logFile, "fileServer::initPolicy(): policyKey invalid\n");
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "fileServer::initPolicy, returning true\n");
    fflush(g_logFile);
#endif
    return true;
}


bool fileServer::initFileKeys()
{
    struct stat statBlock;
    char        szName[512];
    int         size= 0;
    byte        keyBuf[GLOBALMAXSYMKEYSIZE];
    int         n= 0;
    int         m= 0;
    byte        sealedkeyBuf[GLOBALMAXSEALEDKEYSIZE];
   
    if(m_tcHome.m_fileNames.m_szdirectory==NULL) {
        fprintf(g_logFile, "initFileKeys: No home directory for keys\n");
        return false;
    }
    if((strlen(m_tcHome.m_fileNames.m_szdirectory)+16)>512) {
        fprintf(g_logFile, "initFileKeys: key name too long\n");
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
        if(!getCryptoRandom(m_sizeKey*NBITSINBYTE, m_fileKeys)) {
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
        memcpy(&keyBuf[n], m_fileKeys, m_sizeKey);
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
        if(!m_tcHome.Unseal(m_tcHome.measurementSize(), m_tcHome.measurementPtr(),
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
        memcpy(m_fileKeys, &keyBuf[n], m_sizeKey);
        n+= m_sizeKey;
        if(n>m) {
            fprintf(g_logFile, "initFileKeys: unsealed keys wrong size\n");
            return false;
        }
        m_fKeysValid= true;
    }

#ifdef  TEST
    fprintf(g_logFile, "fileServer:initFileKeys complete\n");
    fflush(g_logFile);
#endif
    return true;
}


bool fileServer::initServer(const char* configDirectory)
{
    bool            fRet= true;
    const char*     directory= NULL;

    try {

        const char** parameters = NULL;
        int parameterCount = 0;
        if(configDirectory==NULL) {
            directory= DEFAULTDIRECTORY;
            
        } 
        else {
            directory= configDirectory;
            parameters= &directory;
            parameterCount= 1;
        }

        if(!initAllCrypto())
            throw "fileServer::Init: can't initcrypto\n";

        // init Host and Environment
        m_taoHostInitializationTimer.Start();
        if(!m_host.HostInit(g_hostplatform, g_hostProvider, g_hostDirectory,
                            g_hostsubDirectory, parameterCount, parameters))
            throw "fileServer::Init: can't init host\n";
        m_taoHostInitializationTimer.Stop();

#ifdef TEST
        fprintf(g_logFile, "fileServer::Init: after HostInit, pid: %d\n",
            getpid());
#endif

        // init environment
        m_taoEnvInitializationTimer.Start();
        if(!m_tcHome.EnvInit(g_envplatform, "fileServer", DOMAIN, g_hostDirectory,
                             "fileServer", &m_host, g_serviceProvider, 0, NULL)) {
            throw "fileServer::Init: can't init environment\n";
        }
        m_taoEnvInitializationTimer.Stop();

#ifdef TEST
        fprintf(g_logFile, "fileServer::Init: after EnvInit\n");
        m_tcHome.printData();
#endif
        fprintf(g_logFile, "fileServer::Init: after EnvInit\n");

        // Initialize file encryption keys
        if(!initFileKeys())
            throw "fileServer::Init: can't init file keys\n";

        // Init global policy 
        if(!initPolicy())
            throw("fileServer::Init: Cant init policy objects\n");

        // Metadata keys
        if(m_fEncryptFiles) {
            if(!m_fKeysValid) {
                fprintf(g_logFile, "fileServer::init: Encryption enabled but key invalid\n");
                return -1;
            }
            // should check
            m_encType= DEFAULTENCRYPT;
        }
        else {
            m_encType= NOENCRYPT;
        }

        // this section should move to the tao?
        if(!m_opolicyCert.init(m_tcHome.policyCertPtr())) {
            fprintf(g_logFile, "fileServer::Init:: Can't init policy cert 1\n");
            return false;
        }
        if(!m_opolicyCert.parsePrincipalCertElements()) {
            fprintf(g_logFile, "fileServer::Init:: Can't init policy key 2\n");
            return false;
        }
        m_fpolicyCertValid= true;

        // Initialize resource and principal tables
        if(!m_oMetaData.initMetaData(m_tcHome.m_fileNames.m_szdirectory, 
            "fileServer", m_encType, m_fileKeys))
            throw "fileServer::Init: Cant init metadata\n";
        if(!m_oMetaData.initFileNames())
            throw "fileServer::Init: Cant init file names\n";
    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "fileServer error: %s\n", szError);
        fflush(g_logFile);
    }

#ifdef TEST
    if(fRet)
        fprintf(g_logFile, "fileServer initialized\n");
    else
        fprintf(g_logFile, "fileServer initialization failed\n");
#endif
    return fRet;
}


bool fileServer::closeServer()
{
    return true;
}


bool fileServer::server()
{
    int                 fd, newfd;
    struct sockaddr_in  server_addr, client_addr;
    int                 slen= sizeof(struct sockaddr_in);
    int                 clen= sizeof(struct sockaddr);
    int                 iError;

    fd= socket(AF_INET, SOCK_STREAM, 0);
    if(fd<0) {
        fprintf(g_logFile, "fileServer::server: Can't open socket\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "fileServer::server: socket opened\n");
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
    fprintf(g_logFile, "fileServer::server: bind succeeded\n");
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

    theServiceChannel*  poSc= NULL;
    int                 i;
    for(;;) {
#ifdef TEST
        fprintf(g_logFile, "fileServer: top of accept loop\n");
        fflush(g_logFile);
#endif
        newfd= accept(fd, (struct sockaddr*) &client_addr, (socklen_t*)&clen);
        if(newfd<0) {
            fprintf(g_logFile, "Can't accept socket", strerror(errno));
            return false;
        }
#ifdef TEST
        fprintf(g_logFile, "fileServer: accept succeeded\n");
        fflush(g_logFile);
#endif

        poSc= new theServiceChannel();

        if(poSc!=NULL) {

            for(i=0; i<m_iNumClients; i++) {
                if(!m_fthreadValid[i])
                    break;
            }

            if(i==m_iNumClients) {
                if(m_iNumClients>=MAXNUMCLIENTS) {
                    fprintf(g_logFile, "fileServer::server: Can't allocate theServiceChannel\n");
                    return false;
                }
                i= m_iNumClients++;
            }
                    
            poSc->m_pParent= this;
            poSc->m_fdChannel= newfd;
            poSc->m_myPositionInParent= i;
            poSc->m_pMetaData= &m_oMetaData;
#ifdef TEST
            fprintf(g_logFile, "fileServer: slot %d, about to pthread_create\n", i);
            fprintf(g_logFile, "\tnewfd: %d\n", newfd);
            fflush(g_logFile);
#endif

            memset(&m_threadData[i], 0, sizeof(pthread_t));
            m_threadIDs[i]= pthread_create(&m_threadData[i], NULL, 
                                    channelThread, poSc);
#ifdef TEST
            fprintf(g_logFile, "fileServer: pthread create returns: %d\n", m_threadIDs[i]);
            fflush(g_logFile);
#endif
            if(m_threadIDs[i]>=0)
                m_fthreadValid[i]= true;
            else
                m_fthreadValid[i]= false;
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
// fileServer.exe [-initKeys address-of-managementserver]
{
    fileServer      oServer;
    int             iRet= 0;
    const char*     directory= NULL;

    initLog(NULL);
#ifdef TEST
    fprintf(g_logFile, "fileServer main: fileServer started\n");
    fflush(g_logFile);
#endif

    const char*     definedprogDirectory= getenv("CPProgramDirectory");
    const char*     definedKeyNegoAddress= getenv("CPKeyNegoAddress");
    const char*     definedfileServerAddress= getenv("CPFileServerAddress");
    UNUSEDVAR(definedprogDirectory);
    UNUSEDVAR(definedKeyNegoAddress);
    UNUSEDVAR(definedfileServerAddress);

    if(definedprogDirectory!=NULL)
        directory= strdup(definedprogDirectory);

#ifdef DONTENCRYPTFILES
    oServer.m_fEncryptFiles= false;
#else
    oServer.m_fEncryptFiles= true;
    oServer.m_encType= DEFAULTENCRYPT;
#endif

    initLog("fileServer.log");
#ifdef TEST
    fprintf(g_logFile, "fileServer main: measured server about to init server\n");
    fflush(g_logFile);
#endif

    try {
        if(!oServer.initServer(directory)) 
            throw "fileServer main: cant initServer\n";

#ifdef TEST
        fprintf(g_logFile, "fileServer main: measured server entering server loop\n");
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


#ifdef TEST

#ifdef METADATATEST
void metadataTest(const char* szDir, bool fEncrypt, byte* keys)
{
    int         encType;
    metaData    localVault;

    if(fEncrypt) {
        encType= DEFAULTENCRYPT;
    }
    else {
        encType= NOENCRYPT;
    }

    if(g_theVault.saveMetaData(encType, keys)) {
        fprintf(g_logFile, "fileServer::serviceChannel: save succeeds\n");
        fflush(g_logFile);
    }
    else {
        fprintf(g_logFile, "fileServer::serviceChannel: save fails\n");
        fflush(g_logFile);
    }

    if(!localVault.initMetaData(szDir, "fileServer")) {
        fprintf(g_logFile, "fileServer::localInit: Cant init local metadata\n");
        fflush(g_logFile);
    }
    if(!localVault.initFileNames()) {
        fprintf(g_logFile, "fileServer::localInit: Cant init file names\n");
        fflush(g_logFile);
        return;
    }
    if(!localVault.restoreMetaData(encType, keys)) {
        fprintf(g_logFile, "fileServer::localInit: Cant init file names\n");
        fflush(g_logFile);
        return;
    }

    fprintf(g_logFile, "fileServer::localInit: printing tables\n");
    fflush(g_logFile);
    printResources(localVault.m_pRM);
    printPrincipals(localVault.m_pPM);
    fflush(g_logFile);
}
#endif


void printResources(objectManager<resource>* pRM)
{
    int     i;

    fprintf(g_logFile, "%d resources\n", pRM->numObjectsinTable());
    for(i=0; i<pRM->numObjectsinTable(); i++) {
        pRM->getObject(i)->printMe();
        fprintf(g_logFile, "\n");
    }
    fprintf(g_logFile, "\n");
}


void printPrincipals(objectManager<PrincipalCert>* pPM)
{
    int     i;

    fprintf(g_logFile, "%d principals\n", pPM->numObjectsinTable());
    for(i=0; i<pPM->numObjectsinTable(); i++) {
        pPM->getObject(i)->printMe();
        fprintf(g_logFile, "\n");
    }
    fprintf(g_logFile, "\n");
}
#endif


void fileServer::printTimers(FILE* log) {
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

void fileServer::resetTimers() {
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




