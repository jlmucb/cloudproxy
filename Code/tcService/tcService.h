//
//  File: tcService.h
//  Description: tcService defines
//
//  Copyright (c) 2012, John Manferdelli.  All rights reserved.
//     Some contributions Copyright (c) 2012, Intel Corporation. 
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


// ------------------------------------------------------------------------------


#ifndef __TCSERVICE_H__
#define __TCSERVICE_H__


#include "jlmTypes.h"
#include "sha256.h"
#include "tao.h"
#include "tcIO.h"
#include "timer.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

#include "domain.h"


typedef u64 TCSERVICE_RESULT;


#define MAXREQRESSIZE                         512


#define TCSERVICE_RESULT_SUCCESS                0
#define TCSERVICE_RESULT_UNKNOWNREQ             1
#define TCSERVICE_RESULT_NOREQUESTS             2
#define TCSERVICE_RESULT_CANTOPENOSSERVICE      3
#define TCSERVICE_RESULT_CANTREADOSSERVICE      4
#define TCSERVICE_RESULT_CANTWRITEOSSERVICE     5
#define TCSERVICE_RESULT_CANTALLOCBUFFER        6
#define TCSERVICE_RESULT_DATANOTVALID           7
#define TCSERVICE_RESULT_BUFFERTOOSMALL         8
#define TCSERVICE_RESULT_REQTOOLARGE            9
#define TCSERVICE_RESULT_FAILED                10

#include "tcServiceCodes.h"
#include "jlmUtility.h"


class serviceprocEnt {
public:
    int                 m_procid;
    int                 m_sizeHash;
    byte                m_rgHash[32];
    char*               m_szexeFile;
    int                 m_nArgs;
    char**              m_Args;

    void                print();
};


typedef aNode<serviceprocEnt>  serviceprocMap;


class serviceprocTable {
public:
    int                 m_numFree;
    int                 m_numFilled;
    serviceprocMap*     m_pFree;
    serviceprocMap*     m_pMap;
    serviceprocEnt*     m_rgProcEnts;
    serviceprocMap*     m_rgProcMap;

    serviceprocTable();
    ~serviceprocTable();

    bool                initprocTable(int size);
    bool                addprocEntry(int procid, const char* file, int an, char** av,
                                     int sizeHash, byte* hash);
    void                removeprocEntry(int procid);
    serviceprocEnt*     getEntfromprocId(int procid);
    bool                gethashfromprocId(int procid, int* psizeHash, byte* hash);

    void                print();
};


class tcServiceInterface {
public:
    taoHostServices     m_host;
    taoEnvironment      m_trustedHome;
    serviceprocTable    m_procTable;

    timer               m_taoEnvInitializationTimer;
    timer               m_taoHostInitializationTimer;

    tcServiceInterface();
    ~tcServiceInterface();

    TCSERVICE_RESULT    initService(const char* execfile, int an, char** av);

    TCSERVICE_RESULT    GetOsPolicyKey(u32* pType, int* psize, byte* rgBuf);
    TCSERVICE_RESULT    GetOsCert(u32* credType, int* psizeOut, byte* rgOut);
    TCSERVICE_RESULT    GetOsEvidence(int* psizeOut, byte* rgOut);
    TCSERVICE_RESULT    GetOsHash(u32* phashType,int* psizeOut, byte* rgOut);
    TCSERVICE_RESULT    GetServiceHash(u32* phashType, int* psize, byte* rgBuf);
    TCSERVICE_RESULT    GetHostedMeasurement(int pid, u32* phashType, int* psize, byte* rgBuf);
    TCSERVICE_RESULT    GetEntropy(int size, byte* buf);
    
    TCSERVICE_RESULT    StartApp(tcChannel& oAppChannel, int procid, 
                            const char* file, int an, char** av,
                            int* poutsize, byte* out);

    TCSERVICE_RESULT    SealFor(int procid, int sizeIn, byte* rgIn, 
                            int* psizeOut, byte* rgOut);
    TCSERVICE_RESULT    UnsealFor(int procid, int sizeIn, byte* rgIn, 
                            int* psizeOut, byte* rgOut);
    TCSERVICE_RESULT    AttestFor(int procid, int sizeIn, byte* rgIn, 
                            int* psizeOut, byte* rgOut);
};


#endif


// ------------------------------------------------------------------------------


