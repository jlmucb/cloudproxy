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
#include "cryptoHelper.h"
#include "request.h"
#include "tcIO.h"

#include "tao.h"

#include "objectManager.h"
#include "secPrincipal.h"
#include "claims.h"
#include "trustedKeyNego.h"
#include "encryptedblockIO.h"
#include "domain.h"

#include "encapsulate.h"

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


bool             g_fTerminateServer= false;
int              iQueueSize= 5;

bool             g_globalpolicyValid= false;
// metaData         g_theVault;
PrincipalCert*   g_policyPrincipalCert= NULL;
RSAKey*          g_policyKey= NULL;
accessPrincipal* g_policyAccessPrincipal= NULL;

#include "./policyCert.inc"

PrincipalCert  g_sealingPrincipal;


// ------------------------------------------------------------------------


theServiceChannel::theServiceChannel()
{
    m_pParent= NULL;
    m_fdChannel= -1;

    m_serverState= NOSTATE;
    m_fChannelAuthenticated= false;
}


theServiceChannel::~theServiceChannel()
{
}


bool theServiceChannel::initSafeChannel()
{
    return m_osafeChannel.initChannel(m_fdChannel, AES128, CBCMODE, HMACSHA256, 
                          AES128BYTEKEYSIZE, AES128BYTEKEYSIZE,
                          m_oKeys.m_rguEncryptionKey2, m_oKeys.m_rguIntegrityKey2, 
                          m_oKeys.m_rguEncryptionKey1, m_oKeys.m_rguIntegrityKey1);
}



int theServiceChannel::processRequests()
{
    byte    request[MAXREQUESTSIZEWITHPAD];
    int     type= 0;
    byte    multi= 0;
    byte    final= 0;
    int     encType= NOENCRYPT;
    byte*   key= NULL;

#ifdef TEST
    fprintf(g_logFile, "\n\ntheServiceChannel: processRequest\n");
#endif
    m_serverState= REQUESTSTATE;

    if(m_osafeChannel.safegetPacket(request, MAXREQUESTSIZE, &type, &multi, &final)<(int)sizeof(packetHdr)) {
        fprintf(g_logFile, "theServiceChannel::processRequests: Can't get ProcessRequest packet\n");
        return -1;
    }

#ifdef TEST
    fprintf(g_logFile, "theServiceChannel::processRequests: packetType %d, serverstate %d\n", type, m_serverState);
#endif
    if(type==CHANNEL_TERMINATE) {
        fprintf(g_logFile, "Received CHANNEL_TERMINATE; returning 0 from theServiceChannel::processRequests\n");
        fflush(g_logFile);
        return 0;
    }
    if(type!=CHANNEL_REQUEST) {
        fprintf(g_logFile, "theServiceChannel::processRequests: Not a channel request\n");
        return -1;
    }

    if(m_pParent->m_fEncryptFiles) {
        if(!m_pParent->m_fKeysValid) {
            fprintf(g_logFile, "theServiceChannel::processRequests: Encryption enabled but key invalid\n");
            return -1;
        }
        encType= DEFAULTENCRYPT;
        key= m_pParent->m_bidKeys;
    }

    int     iRequestType= 0;
    {
        Request oReq;

        if(!oReq.getDatafromDoc(reinterpret_cast<char*>(request))) {
            fprintf(g_logFile, "theServiceChannel::processRequests: cant parse: %s\n", request);
            return -1;
        }

#ifdef TEST
        fprintf(g_logFile, "parsed oReq from request: %s\n", request);
#endif


        iRequestType= oReq.m_iRequestType;
        switch(iRequestType) {
          case SUBMITBID:
            if(!serversendresponsetoclient(m_sealingKey, m_signingKey,
                                    m_osafeChannel, oReq,  m_oKeys, encType, key, 
                                    m_pParent->m_accessCheckTimer, m_pParent->m_decTimer)) {
                fprintf(g_logFile, "serversendCredentialtoclient failed 1\n");
                return -1;
            }
            return 1;
          default:
            fprintf(g_logFile, "theServiceChannel::processRequests: invalid request type\n");
            return -1;
        }
    }
}


bool theServiceChannel::initServiceChannel()
{
    int     n= 0;

#ifdef  TEST
    fprintf(g_logFile, "theServiceChannel::initserviceChannel\n");
    fflush(g_logFile);
#endif

    m_serverState= INITSTATE;

    // Initialize program private key and certificate for session
    if(!m_pParent->m_tcHome.m_privateKeyValid ||
           !m_oKeys.getMyProgramKey((RSAKey*)m_pParent->m_tcHome.m_privateKey)) {
        fprintf(g_logFile, "theServiceChannel::serviceChannel: Cant get my private key\n");
        return false;
    }
#ifdef  TEST
    fprintf(g_logFile, "theServiceChannel::serviceChannel: program key set\n");
    fflush(g_logFile);
#endif
    if(!m_pParent->m_tcHome.m_myCertificateValid ||
           !m_oKeys.getMyProgramCert(m_pParent->m_tcHome.m_myCertificate)) {
        fprintf(g_logFile, "theServiceChannel::serviceChannel: Cant get my Cert\n");
        return false;
    }

    // copy my public key into server public key
    if(!m_pParent->m_tcHome.m_myCertificateValid ||
           !m_oKeys.getServerCert(m_pParent->m_tcHome.m_myCertificate)) {
        fprintf(g_logFile, "theServiceChannel::serviceChannel: Cant load client public key structures\n");
        return false;
    }

    m_pParent->m_protocolNegoTimer.Start();
    if(!protocolNego())
        return false;
    m_pParent->m_protocolNegoTimer.Stop();

#ifdef  TEST
    fprintf(g_logFile, "theServiceChannel::serviceChannel, about to init guard\n");
    fflush(g_logFile);
#endif

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
        if(!poSc->initServiceChannel()) {
            fprintf(g_logFile, "channelThread: initServiceChannel failed\n");
        }

        // delete enty in thread table in parent
        if(poSc->m_myPositionInParent>=0) 
            poSc->m_pParent->m_fthreadValid[poSc->m_myPositionInParent]= false;
        poSc->m_myPositionInParent= -1;
#ifdef TEST
        fprintf(g_logFile, "channelThread exiting\n");
        fflush(g_logFile);
#endif
        delete  poSc;
    } catch (const char* err) {
        fprintf(g_logFile, "Server thread exited with error: %s\n", err);
        fflush(g_logFile);
    }

    pthread_exit(NULL);
    return NULL;
}
    

// ----------------------------------------------------------------------------


bidServer::bidServer()
{
    m_szPort= NULL;
    m_szAddress= NULL;
    m_iNumClients= 0;

    m_fEncryptFiles= false;
    m_szSealedKeyFile= NULL;
    m_fKeysValid= false;
    m_uAlg= 0;
    m_uMode= 0;
    m_uPad= 0;
    m_uHmac= 0;
    m_sizeKey= SMALLKEYSIZE;
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
    if(!m_tcHome.m_envValid) {
        fprintf(g_logFile, "bidServer::initPolicy(): environment invalid\n");
        return false;
    }

    if(!m_tcHome.m_policyKeyValid)  {
        fprintf(g_logFile, "bidServer::initPolicy(): policyKey invalid\n");
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "bidServer::initPolicy: about to initpolicy Cert\n",
            m_tcHome.m_policyKey);
    fflush(g_logFile);
#endif
    if(!g_policyPrincipalCert->init(reinterpret_cast<char*>(m_tcHome.m_policyKey))) {
        fprintf(g_logFile, "bidServer::initPolicy: Can't init policy cert 1\n");
        fflush(g_logFile);
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "bidServer::initPolicy, about to parse policy Cert\n");
    fprintf(g_logFile, "bidServer::initPolicy, policy Cert\n%s\n",
            m_tcHome.m_policyKey);
    fflush(g_logFile);
#endif
    if(!g_policyPrincipalCert->parsePrincipalCertElements()) {
        fprintf(g_logFile, "initPolicy: Can't init policy key 2\n");
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "bidServer::initPolicy, about to get policy key\n");
    fflush(g_logFile);
#endif
    g_policyKey= (RSAKey*)g_policyPrincipalCert->getSubjectKeyInfo();
    if(g_policyKey==NULL) {
        fprintf(g_logFile, "initPolicy: Can't init policy key 3\n");
        return false;
    }

    g_globalpolicyValid= true;
#ifdef TEST
    fprintf(g_logFile, "bidServer::initPolicy, returning true\n");
    fflush(g_logFile);
#endif
    return true;
}


bool bidServer::initSigningandSealingKeys()
{
    int     size= 4096;
    int     bufSize= 4096;
    byte    buf[4096];

    if(!m_tcHome.m_privateKeyValid) {
        fprintf(g_logFile, "bidServer::initSigningandSealingKeys: private key not valid\n");
        return false;
    }
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
        fprintf(g_logFile, "bidServer::initSigningandSealingKeys: Can't read signing cert, %s\n", m_szsigningCert);
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

    m_sealingKey= (RSAKey*)g_sealingPrincipal.getSubjectKeyInfo();
    if(m_sealingKey==NULL) {
        fprintf(g_logFile, "bidServer::initSigningandSealingKeys: can't get keyinfo from seal Cert\n");
        fflush(g_logFile);
        return false;
    }

    return true;
}


bool bidServer::initFileKeys()
{
    struct stat statBlock;
    char        szName[256];
    int         size= 0;
    byte        keyBuf[SMALLKEYSIZE];
    int         n= 0;
    int         m= 0;
    byte        sealedkeyBuf[BIGKEYSIZE];
   
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

        if(!m_tcHome.m_myMeasurementValid) {
            fprintf(g_logFile, "initFileKeys: measurement invalid\n");
            return false;
        }
        // seal and save
        size= BIGKEYSIZE;
        if(!m_tcHome.Seal(m_tcHome.m_myMeasurementSize, m_tcHome.m_myMeasurement,
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
        size= BIGKEYSIZE;
        if(!getBlobfromFile(m_szSealedKeyFile, sealedkeyBuf, &size)) {
            fprintf(g_logFile, "initFileKeys: cant get sealed keys\n");
            return false;
        }
        if(!m_tcHome.m_myMeasurementValid) {
            fprintf(g_logFile, "initFileKeys: measurement invalid\n");
            return false;
        }
        m= SMALLKEYSIZE;
        if(!m_tcHome.Unseal(m_tcHome.m_myMeasurementSize, m_tcHome.m_myMeasurement,
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
        if(!m_host.HostInit(PLATFORMTYPELINUX, parameterCount, parameters)) {
            throw "bidServer::Init: can't init host\n";
        }
        m_taoHostInitializationTimer.Stop();
#ifdef TEST
        fprintf(g_logFile, "bidServer::Init: after HostInit, pid: %d\n",
            getpid());
#endif

        // init environment
        m_taoEnvInitializationTimer.Start();
        if(!m_tcHome.EnvInit(PLATFORMTYPELINUXAPP, "bidServer",
                             DOMAIN, directory,
                             &m_host, 0, NULL)) {
            throw "bidServer::Init: can't init environment\n";
        }
        m_taoEnvInitializationTimer.Stop();
#ifdef TEST
        fprintf(g_logFile, "bidServer::Init: after EnvInit\n");
        m_tcHome.printData();
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
        // Init global policy 
        if(!initPolicy())
            throw "bidServer::Init: Cant init policy objects\n";
#ifdef TEST
        fprintf(g_logFile, "initServer has private key and public key\n");
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


    theServiceChannel*  poSc= NULL;
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

        poSc= new theServiceChannel();

        if(poSc!=NULL) {

            for(i=0; i<m_iNumClients; i++) {
                if(!m_fthreadValid[i])
                    break;
            }

            if(i==m_iNumClients) {
                if(m_iNumClients>=MAXNUMCLIENTS) {
                    fprintf(g_logFile, "bidServer::server: Can't allocate theServiceChannel\n");
                    return false;
                }
                i= m_iNumClients++;
            }
                    
            poSc->m_pParent= this;
            poSc->m_fdChannel= newfd;
            poSc->m_myPositionInParent= i;
            poSc->m_signingKey=  m_signingKey;
            poSc->m_sealingKey=  m_sealingKey;
#ifdef TEST
            fprintf(g_logFile, "Signing key\n");
            poSc->m_signingKey->printMe();
            fprintf(g_logFile, "Sealing key\n");
            poSc->m_sealingKey->printMe();
            fprintf(g_logFile, "bidServer: slot %d, about to pthread_create\n", i);
            fprintf(g_logFile, "\tnewfd: %d\n", newfd);
            fflush(g_logFile);
#endif

            memset(&m_threadData[i], 0, sizeof(pthread_t));
            m_threadIDs[i]= pthread_create(&m_threadData[i], NULL, 
                                    channelThread, poSc);
#ifdef TEST
            fprintf(g_logFile, "bidServer: pthread create returns: %d\n", m_threadIDs[i]);
            fflush(g_logFile);
#endif
            if(m_threadIDs[i]>=0)
                m_fthreadValid[i]= true;
            else
                m_fthreadValid[i]= false;
        }
        else {
            fprintf(g_logFile, "bidServer::server: Can't allocate theServiceChannel\n");
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
    bool        fInitProg= false;
    const char* directory= NULL;


    initLog(NULL);
#ifdef TEST
    fprintf(g_logFile, "bidServer main: bidServer started\n");
    fflush(g_logFile);
#endif
    // check arguments
    if(an>1) {
        for(i=0;i<an;i++) {
             if(strcmp(av[i],"-initProg")==0) {
                fInitProg= true;
             }
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

    // am I alread measured?
    if(fInitProg) {
#ifdef TEST
        fprintf(g_logFile, "bidServer main: start measured program %s\n", av[0]);
#endif
        if(!startMeAsMeasuredProgram(an, av)) {
#ifdef TEST
            fprintf(g_logFile, "bidServer main: measured program failed, exiting\n");
#endif
            return 1;
        }
#ifdef TEST
        fprintf(g_logFile, "bidServer main: measured program started\n");
#endif
        return 0;
    }

    initLog("bidServer.log");
#ifdef TEST
        fprintf(g_logFile, "bidServer main: measured server about to init server\n");
        fflush(g_logFile);
#endif

    try {
        g_policyPrincipalCert= new PrincipalCert();
        if(g_policyPrincipalCert==NULL)
            throw "bidServer main: failed to new Principal\n";

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




