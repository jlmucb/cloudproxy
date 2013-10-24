//  File: fileClient.cpp
//      John Manferdelli
//
//  Description: Client for fileServer.
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
#include "jlmUtility.h"
#include "jlmcrypto.h"

#include "session.h"
#include "logging.h"

#include "channel.h"
#include "safeChannel.h"
#include "channelstate.h"
#include "tao.h"

#include "bignum.h"
#include "mpFunctions.h"
#include "sha256.h"
#include "cryptoHelper.h"
#include "domain.h"
#include "tcIO.h"
#include "timer.h"

#include "tinyxml.h"

#include "objectManager.h"

#include "fileClient.h"
#include "fileTester.h"
#include "request.h"
#include "trustedKeyNego.h"
#include "encryptedblockIO.h"
#include "hashprep.h"

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
#include <arpa/inet.h>
#include <errno.h>
#include <dirent.h>

#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
using std::string;
using std::ifstream;
using std::ofstream;
using std::stringstream;
// const char* szServerHostAddr= "127.0.0.1";

#include "./policyCert.inc"
#include "./taoSetupglobals.h"

extern const char*  g_szTerm;
const char* g_szClientPrincipalCertsFile= "fileClient/principalPublicKeys.xml";
const char* g_szClientPrincipalPrivateKeysFile= "fileClient/principalPrivateKeys.xml";


// ------------------------------------------------------------------------


fileClient::fileClient ()
{
    m_fd= 0;

    m_fEncryptFiles= false;
    m_szSealedKeyFile= NULL;
    m_fKeysValid= true;
    m_uAlg= 0;
    m_uMode= 0;
    m_uPad= 0;
    m_uHmac= 0;
    m_sizeKey= SMALLKEYSIZE;
    m_fpolicyCertValid= false;
}


fileClient::~fileClient ()
{
    m_sizeKey= SMALLKEYSIZE;
    if(m_fKeysValid)
        memset(m_fileKeys, 0, m_sizeKey);
    m_fKeysValid= false;
    if(m_szSealedKeyFile!=NULL)
        free(m_szSealedKeyFile);
    m_szSealedKeyFile= NULL;
}


bool fileClient::initPolicy()
{
#ifdef TEST
    fprintf(g_logFile, "fileClient::initPolicy\n");
    fflush(g_logFile);
#endif
    // doesn't do much any more
    if(!m_tcHome.m_envValid) {
        fprintf(g_logFile, "fileClient::initPolicy(): environment invalid\n");
        return false;
    }
    if(!m_tcHome.m_policyKeyValid)  {
        fprintf(g_logFile, "fileClient::initPolicy(): policyKey invalid\n");
        return false;
    }
    return true;
}


bool fileClient::initFileKeys()
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
            fprintf(g_logFile, "initFileKeys: key size too small %d\n", m_sizeKey);
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

        if(!m_tcHome.m_myMeasurementValid) {
            fprintf(g_logFile, "initFileKeys: measurement invalid\n");
            return false;
        }
        // seal and save
        size= BIGKEYSIZE;
        m_sealTimer.Start();
        if(!m_tcHome.Seal(m_tcHome.m_myMeasurementSize, m_tcHome.m_myMeasurement,
                        n, keyBuf, &size, sealedkeyBuf)) {
            fprintf(g_logFile, "initFileKeys: cant seal keys\n");
            return false;
        }
        m_sealTimer.Stop();
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
        m_unsealTimer.Start();
        if(!m_tcHome.Unseal(m_tcHome.m_myMeasurementSize, m_tcHome.m_myMeasurement,
                        size, sealedkeyBuf, &m, keyBuf)) {
            fprintf(g_logFile, "initFileKeys: cant unseal keys\n");
            return false;
        }
        m_unsealTimer.Stop();

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
    fprintf(g_logFile, "initFileKeys\n");
    PrintBytes("fileKeys\n", m_fileKeys, m_sizeKey);
    fflush(g_logFile);
#endif
    return true;
}


bool fileClient::initClient(const char* configDirectory, const char* serverAddress, 
                    u_short serverPort, const char* certFile, const char* keyFile)
{
    struct sockaddr_in  server_addr;
    int                 slen= sizeof(struct sockaddr_in);
    int                 iError;
    bool                fRet= true;
    const char*         directory= NULL;
    const char*         szPrincipalKeys= NULL;
    const char*         szPrincipalCerts= NULL;

#ifdef  TEST
    fprintf(g_logFile, "initClient\n");
    fflush(g_logFile);
#endif

    try {
        const char** parameters= NULL;
        int parameterCount= 0;
        if(configDirectory==NULL) {
            directory= DEFAULTDIRECTORY;
        } 
        else {
            directory= configDirectory;
            parameters= &directory;
            parameterCount= 1;
        }

        if(!initAllCrypto()) 
            throw("fileClient::Init: can't initcrypto\n");

        // init Host and Environment
        m_taoHostInitializationTimer.Start();
        if(!m_host.HostInit(g_hostplatform, g_hostProvider, g_hostDirectory,
                            g_hostsubDirectory, parameterCount, parameters)) 
            throw("fileClient::Init: can't init host\n");
        m_taoHostInitializationTimer.Stop();

#ifdef TEST
        fprintf(g_logFile, "fileClient::Init: after HostInit, pid: %d\n",
            getpid());
    	fflush(g_logFile);
#endif

        // init environment
        m_taoEnvInitializationTimer.Start();
        if(!m_tcHome.EnvInit(g_envplatform, "fileClient", DOMAIN, g_hostDirectory,
                             "fileClient", &m_host, g_serviceProvider, 0, NULL))
            throw("fileClient::Init: can't init environment\n");
        m_taoEnvInitializationTimer.Stop();

#ifdef TEST
        fprintf(g_logFile, "fileClient::Init: after EnvInit\n");
        m_tcHome.printData();
#endif

        // Initialize file encryption keys
        if(!initFileKeys())
            throw("fileClient::Init: can't init file keys\n");
#ifdef TEST
        fprintf(g_logFile, "fileClient::Init: after initFileKeys\n");
        m_tcHome.printData();
#endif

        // Init global policy 
        if(!initPolicy())
            throw("fileClient::Init: Cant init policy objects\n");

        // open sockets
        m_fd= socket(AF_INET, SOCK_STREAM, 0);
        if(m_fd<0) 
            throw( "Can't get socket\n");
        memset((void*) &server_addr, 0, sizeof(struct sockaddr_in));

#ifdef  TEST
        fprintf(g_logFile, "initClient: socket opened\n");
    	fflush(g_logFile);
#endif

        server_addr.sin_family= AF_INET;

        if (!inet_aton(serverAddress, &server_addr.sin_addr))
          throw("Can't create the address for the fileServer");
        server_addr.sin_port= htons(serverPort);
    
        iError= connect(m_fd, (const struct sockaddr*) &server_addr, (socklen_t) slen);
        if(iError!=0)
            throw( "fileClient::Init: Can't connect");

        // this section should move to the tao
        if(!m_opolicyCert.init(reinterpret_cast<char*>(m_tcHome.m_policyKey))) 
          throw("fileClient::Init:: Can't init policy cert 1\n");
        if(!m_opolicyCert.parsePrincipalCertElements())
          throw("fileClient::Init:: Can't init policy key 2\n");

    	m_fpolicyCertValid= true;
        RSAKey* ppolicyKey= (RSAKey*)m_opolicyCert.getSubjectKeyInfo();

        // m_tcHome.m_policyKeyValid must be true
        if(!m_clientSession.clientInit(reinterpret_cast<char*>(m_tcHome.m_policyKey), 
                                   ppolicyKey, m_tcHome.m_myCertificate, 
                                   (RSAKey*)m_tcHome.m_privateKey)) 
            throw("fileClient::Init: Can't init policy key 3\n");

        // get principal certs
        szPrincipalKeys= readandstoreString(keyFile);
        szPrincipalCerts= readandstoreString(certFile);

        // negotiate channel
        m_protocolNegoTimer.Start();
        if(!m_clientSession.clientprotocolNego(m_fd, m_fc, 
                                    szPrincipalKeys, szPrincipalCerts))
            throw("fileClient::Init: protocolNego failed\n");
        m_protocolNegoTimer.Stop();

        // Fix
        m_oServices.initFileServices(&m_clientSession, &m_opolicyCert, &m_fc);


#ifdef TEST
        fprintf(g_logFile, "initClient: initialization completed\n");
        fflush(g_logFile);
#endif
    }
    catch(const char* szError) {
        fRet= false;
        fprintf(g_logFile, "Error: %s\n", szError);
        fflush(g_logFile);
        m_tcHome.EnvClose();
        m_host.HostClose();
    }

    return fRet;
}


// -------------------------------------------------------------------------


bool fileClient::closeClient()
{
#ifdef TEST
    fprintf(g_logFile,"in closeClient()\n");
    fflush(g_logFile);
#endif

    if(m_fd>0) {
        close(m_fd);
        m_fd= 0;
    }

#ifdef TEST
    fprintf(g_logFile,"closeClient returning\n");
    fflush(g_logFile);
#endif
    return true;
}


void fileClient::closeConnection() 
{
    if(m_fc.fd>0) 
        m_fc.safesendPacket((byte*) g_szTerm, strlen(g_szTerm)+1, CHANNEL_TERMINATE, 0, 1);
#ifdef TEST
    fprintf(g_logFile,"closeConnection returning\n");
    fflush(g_logFile);
#endif
}


// ------------------------------------------------------------------------


bool fileClient::establishConnection(const char* keyFile, 
                                    const char* certFile, 
                                    const char* directory,
                                    const char* serverAddress,
                                    u_short serverPort) 
{
    try {

        // init logfile, crypto, etc
        if(!initClient(directory, serverAddress, serverPort,
                        certFile, keyFile))
            throw "fileClient main: initClient() failed\n";
    }
    catch(const char* szError) {
        fprintf(g_logFile, "Error: %s\n", szError);
        fflush(g_logFile);
        return false;
    }

  return true;
}


bool fileClient::compareFiles(const string& firstFile, const string& secondFile) {
    // compare the two files to see if the file returned by the server is exactly the file we sent
    ifstream origFile;
    ifstream newFile;
    int pos = 0;
    bool failed = false;
    origFile.open(firstFile.c_str(), ifstream::in);
    newFile.open(secondFile.c_str(), ifstream::in);
    
    while(origFile.good() && newFile.good()) {
        char co = origFile.get();
        char cn = newFile.get();
        if (co != cn) {
#ifdef TEST
            fprintf(g_logFile, "The file returned by the server failed to match the file sent at byte %d\n", pos);
#endif
            failed = true;
            break;
        }

        ++pos;
    }

    // when we get here without hitting a character mismatch, one of the streams is no longer good
    // if one is still good, then the files are not the same length
    if (!failed && (origFile.good() || newFile.good())) {
#ifdef TEST
        fprintf(g_logFile, "The file returned by the server was not the same length as the file sent to the server\n");
#endif
        failed = true;
    } 

#ifdef TEST
    if (!failed) {
        fprintf(g_logFile, "The file returned by the server is identical to the one sent to the server\n");
    }
#endif

    return !failed;
}



int main(int an, char** av)
{
    fileClient      oFileClient;
    safeChannel     fc;
    int             iRet= 0;
    const char*     directory= NULL;
    string          testPath("fileClient/tests/");
    string          testFileName("tests.xml");
    initLog(NULL);

#ifdef  TEST
    fprintf(g_logFile, "fileClient test\n");
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
    oFileClient.m_fEncryptFiles= false;
#else
    oFileClient.m_fEncryptFiles= true;
#endif
    // jlm: removed initProg stuff.  Replaced by tcLaunch

    initLog("fileClient.log");
#ifdef  TEST
    fprintf(g_logFile, "fileClient main in measured loop\n");
    fflush(g_logFile);
#endif
    try {
        // read the testPath and iterate through the set of tests, running each in turn
        DIR* testDir = opendir(testPath.c_str());
        if (NULL == testDir) {
            throw "Could not open the test directory\n";
        }

#ifdef TEST
        fprintf(g_logFile, "reading directory %s\n", testPath.c_str());    
#endif
        // each child directory is a test
        struct dirent* entry = NULL;
        string curDir(".");
        string parentDir("..");
        while((entry = readdir(testDir))) {
            if (curDir.compare(entry->d_name) == 0 || 
                parentDir.compare(entry->d_name) == 0) {
                continue;
            }
#ifdef TEST
            fprintf(g_logFile, "Got entry with name %s\n", entry->d_name);
#endif
            if (DT_DIR == entry->d_type) {
                string path = testPath + string(entry->d_name) + string("/");
                fileTester ft(path, testFileName);
                ft.Run(directory);
            }
        }

#ifdef TEST
        if (0 != errno) {
            fprintf(g_logFile, "Got error %d\n", errno);
        } else {
            fprintf(g_logFile, "Finished reading test directory without error\n");
        }
        
        fprintf(g_logFile, "fileClient main: At close client\n");
#endif
        closeLog();

    } 
    catch (const char* err) {
        fprintf(g_logFile, "execution failed with error %s\n", err);
        iRet= 1;
    }

    return iRet;
}


void fileClient::printTimers(FILE* log) {
    if (m_sealTimer.GetMeasurements().size() > 0) {
        fprintf(log, "clientSealTimes = ");
        m_sealTimer.print(log);
    }

    if (m_unsealTimer.GetMeasurements().size() > 0) {
        fprintf(log, "clientUnsealTimes =  ");
        m_unsealTimer.print(log);
    }

    if (m_taoEnvInitializationTimer.GetMeasurements().size() > 0) {
        fprintf(log, "clientTaoEnvInitTimes = ");
        m_taoEnvInitializationTimer.print(log);
    }

    if (m_taoHostInitializationTimer.GetMeasurements().size() > 0) {
        fprintf(log, "clientTaoHostInitTimes = ");
        m_taoHostInitializationTimer.print(log);
    }

    if (m_protocolNegoTimer.GetMeasurements().size() > 0) {
        fprintf(log, "clientProtocolNegoTimes = ");
        m_protocolNegoTimer.print(log);
    }

    if (m_encTimer.GetMeasurements().size() > 0) {
        fprintf(log, "clientEncTimes = ");
        m_encTimer.print(log);
    }

    if (m_decTimer.GetMeasurements().size() > 0) {
        fprintf(log, "clientDecTimes = ");
        m_decTimer.print(log);
    }
}

void fileClient::resetTimers() {
    m_sealTimer.Clear();
    m_unsealTimer.Clear();
    m_taoEnvInitializationTimer.Clear();
    m_taoHostInitializationTimer.Clear();
    m_protocolNegoTimer.Clear();
    m_encTimer.Clear();
    m_decTimer.Clear();
}


bool fileClient::createResource(const string& subject, 
                const string& evidenceFileName, const string& resource) 
{
    char*   szEvidence= readandstoreString(evidenceFileName.c_str());
 
    if(m_oServices.clientcreateResourceonserver(resource.c_str(), subject.c_str(), 
                                                szEvidence)) {
        fprintf(g_logFile, "fileClient createResourceTest: create resource successful\n");
        fflush(g_logFile);
    } 
    else {
        fprintf(g_logFile, "fileClient createResourceTest: create resource unsuccessful\n");
        fflush(g_logFile);
        return false;
    }

    return true;
}


bool fileClient::deleteResource(const string& subject, const string& evidenceFileName, 
                                const string& resource) 
{
    char*   szEvidence= readandstoreString(evidenceFileName.c_str());
 
    if(m_oServices.clientdeleteResource(resource.c_str(), subject.c_str(), 
                        szEvidence)) {
        fprintf(g_logFile, "fileClient deleteResourceTest: delete resource successful\n");
        fflush(g_logFile);
    } else {
        fprintf(g_logFile, "fileClient deleteResourceTest: delete resource unsuccessful\n");
        fflush(g_logFile);
        return false;
    }

    return true;
}


bool fileClient::readResource(const string& subject, 
            const string& evidenceFileName, const string& remoteResource, 
            const string& localOutput) 
{
    char* szEvidence= readandstoreString(evidenceFileName.c_str());
 
    if(m_oServices.clientgetResourcefromserver(
                                   remoteResource.c_str(),
                                   szEvidence,
                                   localOutput.c_str(),
                                   m_encTimer)) {
        fprintf(g_logFile, "fileClient fileTest: read file successful\n");
        fflush(g_logFile);
    } else {
        fprintf(g_logFile, "fileClient fileTest: read file unsuccessful\n");
        fflush(g_logFile);
        return false;
    }

    return true;
}


bool fileClient::writeResource(const string& subject, 
            const string& evidenceFileName, const string& remoteResource, 
            const string& fileName) 
{
    char*  szEvidence= readandstoreString(evidenceFileName.c_str());
 
    if(m_oServices.clientsendResourcetoserver(
                                  subject.c_str(),
                                  remoteResource.c_str(),
                                  szEvidence,
                                  fileName.c_str(),
                                  m_decTimer)) {
        fprintf(g_logFile, "fileClient fileTest: write file successful\n");
        fflush(g_logFile);
    } else {
        fprintf(g_logFile, "fileClient fileTest: write file unsuccessful\n");
        fflush(g_logFile);
        return false;
    }

    return true;
}


// ------------------------------------------------------------------------


