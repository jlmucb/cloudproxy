//
//  File: sellerClient.h
//      John Manferdelli
//
//  Description: Symbol and class definitions for sellerClient
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


#ifndef _SELLERCLIENT__H
#define _SELLERCLIENT__H


#include "channel.h"
#include "safeChannel.h"
#include "session.h"
#include "objectManager.h"
#include "cert.h"
#include "tao.h"
#include "timer.h"

#include <string>
using std::string;


class sellerClient {
public:
    int                 m_clientState;
    bool                m_fChannelAuthenticated;

    taoHostServices     m_host;
    taoEnvironment      m_tcHome;

    bool                m_fpolicyCertValid;
    PrincipalCert       m_opolicyCert;

    bool                m_fEncryptFiles;
    char*               m_szSealedKeyFile;
    bool                m_fKeysValid;
    u32                 m_uAlg;
    u32                 m_uMode;
    u32                 m_uPad;
    u32                 m_uHmac;
    int                 m_sizeKey;
    byte                m_sellerKeys[GLOBALMAXSYMKEYSIZE];

    int	                m_fd;
    safeChannel         m_fc;
    session             m_clientSession;
    char*               m_szPort;
    char*               m_szAddress;

    char*               m_szAuctionID;
    bool                m_fWinningBidValid;
    int                 m_WinningBidAmount;
    char*               m_szSignedWinner;

    timer               m_sealTimer;
    timer               m_unsealTimer;
    timer               m_taoEnvInitializationTimer;
    timer               m_taoHostInitializationTimer;
    timer               m_protocolNegoTimer;
    timer               m_encTimer;
    timer               m_decTimer;

    sellerClient();
    ~sellerClient();

    bool    initClient(const char* configDirectory, const char* serverAddress, 
                       u_short serverPort, bool fInitChannel);
    bool    initPolicy();
    bool    closeClient();
    bool    establishConnection(safeChannel& fc, const char* keyFile, const char* certFile, 
                        const char* directory, const char* serverAddress, u_short serverPort);
    void    closeConnection(safeChannel& fc);
    bool    resolveAuction(int nbids, const char** bids);
    char*   signWinner(RSAKey* key, const char* auctionID, const char* now,
                       int winningBidAmount, const char* szWinnerCert);

    bool    readBidResolution(safeChannel& fc, const string& subject,
                                const string& identityCert,
                                const string& proposedKey,
                                const string& localOutput);

    bool    compareFiles(const string& firstFile, const string& secondFile);

    void    printTimers(FILE* log);
    void    resetTimers();

    // read the results from the directory
    void getResults();

    // return the URI of the winning client
    string getWinner();

    static string  getFileContents(const string& filename);
    static void getKeyFiles(const string& directory,
                     const string& testFile,
                     string& identityCertFile,
                     string& userCertFile,
                     string& userKeyFile,
                     string& keyFile);
};



#endif


//-------------------------------------------------------------------------------


