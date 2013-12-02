//  File: bidClient.cpp
//      John Manferdelli
//
//  Description: Client for bidServer.
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
#include "bidClient.h"
#include "session.h"
#include "channel.h"
#include "safeChannel.h"
#include "channelstate.h"
#include "bignum.h"
#include "mpFunctions.h"
#include "jlmUtility.h"
#include "request.h"
#include "sha256.h"
#include "tinyxml.h"
#include "domain.h"
#include "tcIO.h"
#include "timer.h"
#include "bidTester.h"

#include "objectManager.h"
#include "tao.h"
#include "taoSetupglobals.h"

#include "trustedKeyNego.h"
#include "encryptedblockIO.h"
#include "cert.h"
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
using std::istreambuf_iterator;
using std::stringstream;
const char* szServerHostAddr= "127.0.0.1";

#if 0
bool             g_globalpolicyValid= false;
// metaData         g_theVault;
PrincipalCert*   g_policyPrincipalCert= NULL;
RSAKey*          g_policyKey= NULL;
accessPrincipal* g_policyAccessPrincipal= NULL;
#endif

#include "./policyCert.inc"

const char* g_szClientPrincipalCertsFile= "bidClient/principalPublicKeys.xml";
const char* g_szClientPrincipalPrivateKeysFile= "bidClient/principalPrivateKeys.xml";

#define DEFAULTDIRECTORY    "/home/jlm/jlmcrypt"


// ------------------------------------------------------------------------


bidClient::bidClient ()
{
    m_clientState= NOSTATE;
    m_fChannelAuthenticated= false;
    m_szPort= NULL;
    m_szAddress= NULL;
    m_fd= 0;

    m_fEncryptFiles= false;
    m_szSealedKeyFile= NULL;
    m_fKeysValid= true;
    m_uAlg= 0;
    m_uMode= 0;
    m_uPad= 0;
    m_uHmac= 0;
    m_sizeKey= GLOBALMAXSYMKEYSIZE;
}


bidClient::~bidClient ()
{
    m_clientState= NOSTATE;
    m_fChannelAuthenticated= false;

    if(m_szPort!=NULL) {
        free(m_szPort);
        m_szPort= NULL;
    }
    if(m_szAddress!=NULL) {
        free(m_szAddress);
        m_szAddress= NULL;
    }
    m_sizeKey= GLOBALMAXSYMKEYSIZE;
    if(m_fKeysValid)
        memset(m_bidKeys, 0, m_sizeKey);
    m_fKeysValid= false;
    if(m_szSealedKeyFile!=NULL)
        free(m_szSealedKeyFile);
    m_szSealedKeyFile= NULL;
}


bool bidClient::initPolicy()
{
#ifdef TEST
    fprintf(g_logFile, "bidClient::initPolicy\n");
    fflush(g_logFile);
#endif
    if(!m_tcHome.isValid()) {
        fprintf(g_logFile, "bidClient::initPolicy(): environment invalid\n");
        return false;
    }

    if(!m_tcHome.policyCertValid())  {
        fprintf(g_logFile, "bidClient::initPolicy(): policyKey invalid\n");
        return false;
    }

// FIX
#if 0
#ifdef TEST1
    fprintf(g_logFile, "bidClient::initPolicy, about to initpolicy Cert\n%s\n",
            m_tcHome.m_policyKey);
    fflush(g_logFile);
    if(g_policyPrincipalCert==NULL)
        g_policyPrincipalCert= new PrincipalCert();
#endif
    if(!g_policyPrincipalCert->init(reinterpret_cast<char*>(m_tcHome.m_policyKey))) {
        fprintf(g_logFile, "initPolicy: Can't init policy cert 1\n");
        return false;
    }
    if(!g_policyPrincipalCert->parsePrincipalCertElements()) {
        fprintf(g_logFile, "initPolicy: Can't init policy key 2\n");
        return false;
    }
    g_policyKey= (RSAKey*)g_policyPrincipalCert->getSubjectKeyInfo();
    if(g_policyKey==NULL) {
        fprintf(g_logFile, "initPolicy: Can't init policy key 3\n");
        return false;
    }
    g_policyAccessPrincipal= registerPrincipalfromCert(g_policyPrincipalCert);
    if(g_policyAccessPrincipal==NULL) {
        fprintf(g_logFile, "initPolicy: Can't init policy key 3\n");
        return false;
    }
#endif

    g_globalpolicyValid= true;
    return true;
}


bool bidClient::initFileKeys()
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
            fprintf(g_logFile, "initFileKeys: key size too small %d\n", m_sizeKey);
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
        size= GLOBALMAXSEALEDKEYSIZE;
        m_sealTimer.Start();
        if(!m_tcHome.Seal(m_tcHome.measurementSize(), m_tcHome.measurementPtr(),
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
        size= GLOBALMAXSEALEDKEYSIZE;
        if(!getBlobfromFile(m_szSealedKeyFile, sealedkeyBuf, &size)) {
            fprintf(g_logFile, "initFileKeys: cant get sealed keys\n");
            return false;
        }
        if(!m_tcHome.m_myMeasurementValid) {
            fprintf(g_logFile, "initFileKeys: measurement invalid\n");
            return false;
        }
        m= GLOBALMAXSYMKEYSIZE;
        m_unsealTimer.Start();
        if(!m_tcHome.Unseal(m_tcHome.measurementSize(), m_tcHome.measurementPtr(),
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


bool bidClient::initClient(const char* configDirectory, const char* serverAddress, u_short serverPort)
{
    struct sockaddr_in  server_addr;
    int                 slen= sizeof(struct sockaddr_in);
    int                 iError;
    bool                fRet= true;
    const char*         directory= NULL;

#ifdef  TEST
    fprintf(g_logFile, "initClient\n");
#endif

    try {
        const char** parameters= NULL;
        int parameterCount= 0;
        if(configDirectory==NULL) {
            directory= DEFAULTDIRECTORY;
        } else {
            directory= configDirectory;
            parameters= &directory;
            parameterCount= 1;
        }

        if(!initAllCrypto()) {
            throw "bidClient::Init: can't initcrypto\n";
        }
        m_oKeys.m_fClient= true;

        // init Host and Environment
        m_taoHostInitializationTimer.Start();
        if(!m_host.HostInit(g_hostplatform, g_hostProvider, g_hostDirectory,
                            g_hostsubDirectory, parameterCount, parameters)) {
            throw "bidClient::Init: can't init host\n";
        }
        m_taoHostInitializationTimer.Stop();
#ifdef TEST
        fprintf(g_logFile, "bidClient::Init: after HostInit, pid: %d\n",
            getpid());
#endif

        // init environment
        m_taoEnvInitializationTimer.Start();
        if(!m_tcHome.EnvInit((g_envplatform, "fileClient", DOMAIN, g_hostDirectory,
                             BIDCLIENTSUBDIRECTORY, &m_host, g_serviceProvider, 0, NULL)) {
            throw "bidClient::Init: can't init environment\n";
        }
        m_taoEnvInitializationTimer.Stop();
#ifdef TEST
        fprintf(g_logFile, "bidClient::Init: after EnvInit\n");
        m_tcHome.printData();
#endif

        // Initialize file encryption keys
        if(!initFileKeys())
            throw "bidClient::Init: can't init file keys\n";
#ifdef TEST
        fprintf(g_logFile, "bidClient::Init: after initFileKeys\n");
        m_tcHome.printData();
#endif

        // Initialize program private key and certificate for session
        if(!m_tcHome.privateKeyValid()|| 
               !m_oKeys.getMyProgramKey((RSAKey*)m_tcHome.privateKeyPtr()))
            throw "bidClient::Init: Cant get my private key\n";
        if(!m_tcHome.myCertValid()|| 
               !m_oKeys.getMyProgramCert(m_tcHome.myCertPtr()))
            throw "bidClient::Init: Cant get my Cert\n";
    
        // Init global policy 
        if(!initPolicy())
            throw "bidClient::Init: Cant init policy objects\n";

        // open sockets
        m_fd= socket(AF_INET, SOCK_STREAM, 0);
        if(m_fd<0) 
            throw  "Can't get socket\n";
        memset((void*) &server_addr, 0, sizeof(struct sockaddr_in));

#ifdef  TEST
        fprintf(g_logFile, "initClient: socket opened\n");
#endif

        server_addr.sin_family= AF_INET;

        // Fix: set up bidClient and bidServer to pass arguments down to
        // their measured versions so we can control this by arguments
        if (!inet_aton(serverAddress, &server_addr.sin_addr)) {
          throw "Can't create the address for the bidServer";
        }
        server_addr.sin_port= htons(serverPort);
    
        iError= connect(m_fd, (const struct sockaddr*) &server_addr, (socklen_t) slen);
        if(iError!=0)
            throw  "bidClient::Init: Can't connect";

#ifdef TEST
        fprintf(g_logFile, "initClient: connect completed\n");
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


bool bidClient::closeClient()
{

    m_clientState= SERVICETERMINATESTATE;

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


bool bidClient::initSafeChannel(safeChannel& fc)
{
    return fc.initChannel(m_fd, AES128, CBCMODE, HMACSHA256, 
                          AES128BYTEKEYSIZE, AES128BYTEKEYSIZE,
                          m_oKeys.m_rguEncryptionKey1, m_oKeys.m_rguIntegrityKey1, 
                          m_oKeys.m_rguEncryptionKey2, m_oKeys.m_rguIntegrityKey2);
}


// ------------------------------------------------------------------------


const char*  g_szTerm= "terminate channel\n";


#define BIDCLIENTTEST
#ifdef  BIDCLIENTTEST

bool bidClient::establishConnection(safeChannel& fc, const char* keyFile, 
                                    const char* certFile, const char* directory,
                                    const char* serverAddress, u_short serverPort) 
{
    try {
#ifdef  TEST
        fprintf(g_logFile, "bidClient main: inited g_policyPrincipalCert\n");
        fflush(g_logFile);
#endif
        // init logfile, crypto, etc
        if(!initClient(directory, serverAddress, serverPort))
            throw "bidClient main: initClient() failed\n";

        // copy my public key into client public key
        if(!m_tcHome.policyCertValid()|| 
               !m_oKeys.getClientCert(m_tcHome.policyCertValid()))
            throw "bidClient main: Cant load client public key structures\n";

#ifdef  TEST
        fprintf(g_logFile, "bidClient main: protocol nego\n");
        fflush(g_logFile);
#endif
        // protocol Nego
        m_protocolNegoTimer.Start();
        // FIX: szPrincipalKeys, szPrincipalCerts
        if(!!m_clientSession.clientprotocolNego(m_fd, m_fc, NULL, NULL))
            throw "bidClient main: Cant negotiate channel\n";
        m_protocolNegoTimer.Stop();

#ifdef TEST
        m_oKeys.printMe();
        fflush(g_logFile);
#endif
    }
    catch(const char* szError) {
        fprintf(g_logFile, "Error: %s\n", szError);
        fflush(g_logFile);
        return false;
    }

  return true;
}

void bidClient::closeConnection(safeChannel& fc) {
        if(fc.fd>0) {
                fc.safesendPacket((byte*) g_szTerm, strlen(g_szTerm)+1, CHANNEL_TERMINATE, 0, 1);
        }
}


// ------------------------------------------------------------------------

//
//  Application specific logic
// 

bool bidClient::readBid(safeChannel& fc, const string& auctionID, 
                               const string& user, const string& bid, 
                               const string& userCert)
{
    int     encType= NOENCRYPT;

    if(clientsendbidtoserver(fc, m_oKeys, auctionID.c_str(),  user.c_str(),
                              bid.c_str(), userCert.c_str(),
                              encType, m_bidKeys, m_encTimer)) {
        fprintf(g_logFile, "bidClient bidTest: read file successful\n");
        fflush(g_logFile);
    } 
    else {
        fprintf(g_logFile, "bidClient fileTest: read file unsuccessful\n");
        fflush(g_logFile);
        return false;
    }

    return true;
}


bool bidClient::compareFiles(const string& firstFile, const string& secondFile) {
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


// ------------------------------------------------------------------------


int main(int an, char** av)
{
    int             iRet= 0;
    int             i;
    bool            fInitProg= false;
    const char*     directory= NULL;
    string          testPath("bidClient/tests/");
    string          testFileName("tests.xml");
    bool            result;
    initLog(NULL);


#ifdef  TEST
    fprintf(g_logFile, "bidClient test\n");
    fflush(g_logFile);
#endif

    UNUSEDVAR(result);
    if(an>1) {
        for(i=0;i<an;i++) {
            if(strcmp(av[i],"-initProg")==0) {
                fInitProg= true;
            }
            if (strcmp(av[i],"-directory")==0) {
                directory= strdup(av[++i]);
            }
        }
    }
    UNUSEDVAR(directory);

    initLog("bidClient.log");
#ifdef  TEST
    fprintf(g_logFile, "bidClient main in measured loop\n");
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
            fprintf(g_logFile, "Got entry with name %s \n", entry->d_name);
            fflush(g_logFile);
#endif
            if (DT_DIR == entry->d_type) {
                string path = testPath + string(entry->d_name) + string("/");

                bidTester bt(path, testFileName);
                bt.Run(directory);
            }
        }

#ifdef TEST
        if (0 != errno) {
            fprintf(g_logFile, "Got error %d\n", errno);
        } 
        else {
            fprintf(g_logFile, "Finished reading test directory without error\n");
        }
        
        fprintf(g_logFile, "bidClient main: At close client\n");
#endif
        closeLog();

    } 
    catch (const char* err) {
        fprintf(g_logFile, "execution failed with error %s\n", err);
        fflush(g_logFile);
        iRet= 1;
    }

    return iRet;
}
#endif


void bidClient::printTimers(FILE* log) {
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

void bidClient::resetTimers() {
    m_sealTimer.Clear();
    m_unsealTimer.Clear();
    m_taoEnvInitializationTimer.Clear();
    m_taoHostInitializationTimer.Clear();
    m_protocolNegoTimer.Clear();
    m_encTimer.Clear();
    m_decTimer.Clear();
}

void bidClient::getKeyFiles(const string& directory, const string& testFile,
                            string& userCertFile, string& userKeyFile)
{
    string path = directory + testFile;
#ifdef TEST
    fprintf(g_logFile, "getKeyFiles Path: %s\n", path.c_str());
    fflush(g_logFile);
#endif

    TiXmlDocument doc(path.c_str());
    doc.LoadFile();

    const TiXmlElement* curElt = doc.RootElement();
    const TiXmlNode* child = NULL;
    while((child = curElt->IterateChildren(child))) {
        const string& name = child->ValueStr();
        const TiXmlElement* childElt = child->ToElement();
        const string& text(childElt->GetText());
        if (name.compare("UserCert") == 0) {
            userCertFile = directory + text;
        } else if (name.compare("UserKey") == 0) {
            userKeyFile = directory + text;
        } else {
            throw "Unknown child node of Test\n";
        }
    }

    return;
}

string bidClient::getFileContents(const string& filename) {
    // read the file and output the text
    ifstream file(filename.c_str());
    string fileContents((istreambuf_iterator<char>(file)),
                        (istreambuf_iterator<char>()));
    return fileContents;
}

// ------------------------------------------------------------------------



