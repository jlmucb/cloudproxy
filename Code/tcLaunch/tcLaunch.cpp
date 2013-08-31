//  File: tcLaunch.cpp
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
#include "logging.h"
#include "tcIO.h"
#include "tcServiceCodes.h"
#include "buffercoding.h"
#include "tinyxml.h"
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
const char* szServerHostAddr= "127.0.0.1";

#ifdef KVMTCSERVICE
const char* g_tcioDDName= "kvmtciodd0";
#endif
#ifdef KVMGUESTOSTCSERVICE 
const char* g_tcioDDName= "ktciodd0";
#endif
#ifdef LINUXTCSERVICE 
const char* g_tcioDDName= "tcioDD0";
#endif

int         g_myPid;


// ------------------------------------------------------------------------


void tcBufferprint(tcBuffer* p)
{
    fprintf(g_logFile, 
           "Buffer: procid: %ld, req: %ld, size: %ld, status: %ld, orig proc: %ld\n",
           (long int)p->m_procid, (long int)p->m_reqID, (long int)p->m_reqSize,
           (long int)p->m_ustatus, (long int)p->m_origprocid);
}
 

bool gettcBuf(int fd, int* procid, u32* puReq, u32* pstatus, int* porigprocid,
                         int* paramsize, byte* params)
{
    byte            rgBuf[PADDEDREQ];
    tcBuffer*       pReq= (tcBuffer*) rgBuf;
    int             i;
    int             n;

#ifdef TEST
    fprintf(g_logFile, "gettcBuf outstanding %d\n", fd);
#endif
    n= *paramsize+sizeof(tcBuffer);
    if(n>PADDEDREQ) {
        fprintf(g_logFile, "Buffer too small\n");
        return false;
    }
    i= read(fd, rgBuf, n);
    if(i<0) {
        fprintf(g_logFile, "ReadBufRequest failed in gettcBuf %d %d\n", i, n);
        return false;
    }

#ifdef TEST
    fprintf(g_logFile, "gettcBuf succeeds %d\n", i);
    tcBufferprint((tcBuffer*) rgBuf);
    PrintBytes("Buffer: ", rgBuf, i);
#endif

#ifdef HEADERTEST
    fprintf(g_logFile, "gettcBuf: "); pReq->print();
#endif
    *procid= pReq->m_procid;
    *puReq= pReq->m_reqID;
    *pstatus= pReq->m_ustatus;
    *porigprocid= pReq->m_origprocid;
    i-= sizeof(tcBuffer);
    if(*paramsize<i)
        return false;
    *paramsize= i;
    memcpy(params, &rgBuf[sizeof(tcBuffer)], i);

    return true;
}


bool sendtcBuf(int fd, int procid, u32 uReq, u32 status, int origproc,
                          int paramsize, byte* params)
{
#if 1
    byte            rgBuf[PADDEDREQ];
    tcBuffer*       pReq= (tcBuffer*) rgBuf;
    int             i;
    int             n;

    if(paramsize>(PARAMSIZE)) {
        fprintf(g_logFile, "sendtcBuf buffer too small %d\n", paramsize);
        return false;
    }
    pReq->m_procid= procid;
    pReq->m_reqID= uReq;
    pReq->m_ustatus= status;
    pReq->m_origprocid= origproc;
    pReq->m_reqSize= paramsize;
#ifdef HEADERTEST
    fprintf(g_logFile, "sendtcBuf: "); pReq->print();
#endif
    n= paramsize+sizeof(tcBuffer);
    memcpy(&rgBuf[sizeof(tcBuffer)], params, paramsize);
    i= write(fd, rgBuf, n);
    if(i<0) {
        fprintf(g_logFile, "tcChannel::sendtcBuf: WriteBufRequest failed %d\n", i);
        return false;
    }
#endif
    return true;
}


bool startAppfromDeviceDriver(int fd, const char* szexecFile, int* ppid,
    int argc, char **argv)
{
#if 1
    u32         ustatus;
    u32         ureq;
    int         procid;
    int         origprocid;
    int         size= PARAMSIZE;
    byte        rgBuf[PARAMSIZE];

    size= encodeTCSERVICESTARTAPPFROMAPP(szexecFile, argc, argv, PARAMSIZE, rgBuf);
    if(size<0) {
        fprintf(g_logFile, "startAppfromDeviceDriver: encodeTCSERVICESTARTAPPFROMAPP failed\n");
        return false;
    }
    if(!sendtcBuf(fd, g_myPid, TCSERVICESTARTAPPFROMAPP, 0, g_myPid, size, rgBuf)) {
        fprintf(g_logFile, "startAppfromDeviceDriver: sendtcBuf for TCSERVICESTARTAPPFROMAPP failed\n");
        return false;
    }
    size= PARAMSIZE;
    if(!gettcBuf(fd, &procid, &ureq, &ustatus, &origprocid, &size, rgBuf)) {
        fprintf(g_logFile, "startAppfromDeviceDriver: gettcBuf for TCSERVICESTARTAPPFROMAPP failed\n");
        return false;
    }
    if(!decodeTCSERVICESTARTAPPFROMTCSERVICE(ppid, rgBuf)) {
        fprintf(g_logFile, "startAppfromDeviceDriver: cant decode childproc\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "Program created: %d by servicepid %d\n", 
          *ppid, g_myPid);
#endif
#endif
    return true;
}


int initLinuxService()
{
#ifdef TEST
        fprintf(g_logFile, "initLinuxService device %s\n", g_tcioDDName);
#endif

    int fd= open(g_tcioDDName, O_RDWR);
        if(fd<0) {
            fprintf(g_logFile, "Can't open device driver %s\n", g_tcioDDName);
            return -1;
        }

#ifdef TEST
    fprintf(g_logFile, "initLinuxService returns %d\n", fd);
#endif
    return fd;
}


// -------------------------------------------------------------------------


int main(int an, char** av)
{
    char*           program= (char*)"";

#ifdef  TEST
    initLog(NULL);
    fprintf(g_logFile, "tcLaunch test\n");
    fflush(g_logFile);
#endif
#if 0
    int             i;
    const char*     directory= NULL;
    if(an>1) {
        for(i=0;i<an;i++) {
            if (strcmp(av[i],"-directory")==0) {
                directory= strdup(av[++i]);
            }
        }
    }
#endif

    initLog("tcLaunch.log");
    g_myPid= getpid();

#ifdef  TEST
    fprintf(g_logFile, "tcLaunch main starting measured %s\n", av[0]);
#endif

    int fd= initLinuxService();
    if(fd<0) {
        return 1;
    }
    int   handle= 0;
    startAppfromDeviceDriver(fd, program, &handle, an, av);

#ifdef TEST
    fprintf(g_logFile, "main: measured program started, exiting\n");
    fflush(g_logFile);
#endif
    close(fd);
    closeLog();
    return 0;
}


// ------------------------------------------------------------------------


