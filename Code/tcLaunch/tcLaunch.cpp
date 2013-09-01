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

const char* g_tcioDDName;
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
#ifdef TEST
    fprintf(g_logFile, "sendtcBuf: "); tcBufferprint(pReq);
#endif
    n= paramsize+sizeof(tcBuffer);
    memcpy(&rgBuf[sizeof(tcBuffer)], params, paramsize);
    i= write(fd, rgBuf, n);
    if(i<0) {
        fprintf(g_logFile, "tcChannel::sendtcBuf: Write failed %d\n", i);
        return false;
    }
#endif
    return true;
}


bool startAppfromDeviceDriver(int fd, int* ppid, int argc, char **argv)
{
#if 1
    u32         ustatus;
    u32         ureq;
    int         procid= g_myPid;
    int         origprocid= g_myPid;
    int         size= PARAMSIZE;
    byte        rgBuf[PARAMSIZE];

    if(argc<1) {
        fprintf(g_logFile, "startAppfromDeviceDriver: no argument\n");
        return false;
    }

    size= encodeTCSERVICESTARTAPPFROMAPP(argv[0], argc-1, argv+1, PARAMSIZE, rgBuf);
    if(size<0) {
        fprintf(g_logFile, "startAppfromDeviceDriver: encodeTCSERVICESTARTAPPFROMAPP failed\n");
        return false;
    }
    if(!sendtcBuf(fd, g_myPid, TCSERVICESTARTAPPFROMAPP, 0, g_myPid, size, rgBuf)) {
        fprintf(g_logFile, "startAppfromDeviceDriver: sendtcBuf for TCSERVICESTARTAPPFROMAPP failed\n");
        return false;
    }
#ifdef TEST
    fprintf(g_logFile, "Sending request %s\n", rgBuf);
#endif
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


#define MAXPROGNAME 512


char* programNamefromFileName(const char* fileName)
{
    char*   p= (char*) fileName;
    char*   q;
    char*   r;
    char    progNameBuf[MAXPROGNAME];

    if(fileName==NULL)
        return NULL;
#ifdef TEST
    fprintf(g_logFile, "fileName: %s\n", fileName);
#endif
    while(*p!='\0')
        p++;
    q= p-1;
    while((--p)!=fileName) {
        if(*p=='/') {
            break;
        }
        if(*p=='.') {
            break;
        }
    }

    if(*p=='/') {
        r= p+1;
    }
    else if(*p=='.') {
        q= p-1;
        r= q;
        while(r>=fileName) {
            if(*r=='/')
                break;
            r--;
        }
    }
    else {
        r= (char*)fileName-1;
    }
    if((q-r)>=(MAXPROGNAME-1))
        return NULL;
    r++;
    p= progNameBuf;
    while(r<=q)
        *(p++)= *(r++);
    *p= '\0';
    q= strdup(progNameBuf);
#ifdef TEST
    fprintf(g_logFile, "fileName: %s, progname: %s\n", fileName, q);
#endif
    return q;
}


int main(int an, char** av)
{
    int         i;
    int         newan= an;
    char**      newav= av;

    for(i=0;i<an;i++) {
      if(strcmp(av[i],"-help")==0) {
        fprintf(g_logFile, 
         "tcLaunch.exe [-KVMHost |-KVMGuest | -LinuxHost]  KVNImage/ProcessImage remainingargs\n");
        return 0;
      }
      if(strcmp(av[i],"-KVMHost")==0) {
        g_tcioDDName= "/dev/kvmtciodd0";
        newan--;
        newav++;
      }
      else if(strcmp(av[i],"-KVMGuest")==0) {
        g_tcioDDName= "/dev/ktciodd0";
        newan--;
        newav++;
      }
      else if(strcmp(av[i],"-LinuxHost")==0) {
        g_tcioDDName= "/dev/tcioDD0";
        newan--;
        newav++;
      }
      else {
        g_tcioDDName= "/dev/tcioDD0";
      }
    }

    g_myPid= getpid();

#ifdef  TEST
    initLog(NULL);
    fprintf(g_logFile, "tcLaunch test %s, %d\n", g_tcioDDName, g_myPid);
    fflush(g_logFile);
#endif

    int fd= initLinuxService();
    if(fd<0) {
        fprintf(g_logFile, "tcLaunch: can't open tcio device driver\n");
        return 1;
    }

    if(newan<1) {
        fprintf(g_logFile, "tcLaunch: too few arguments\n");
        return 1;
    }
    newav[0]= newav[1];
    newav[1]= programNamefromFileName(newav[0]);
    newan= 2;

    int   handle= 0;
    if(startAppfromDeviceDriver(fd, &handle, newan, newav))
        fprintf(g_logFile, "tcLaunch: measured program started, id: %d, exiting\n",
                        handle);
    else
        fprintf(g_logFile, "tcLaunch: program not started due to error\n");
    fflush(g_logFile);
    close(fd);
    closeLog();
    return 0;
}


// ------------------------------------------------------------------------


