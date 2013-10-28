//  File: tcLaunch.cpp
//      John Manferdelli
//
//  Description: Stand alone launch of measured programs
//               and partitions.
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

const char*     g_tcioDDName= NULL;
int             g_myPid= 0;
const char*     g_progDirectory= "/home/jlm/jlmcrypt";


// ------------------------------------------------------------------------


#define BUFSIZE 2048
#define NAMESIZE 256

char *nextline(char* start, char* end)
{
    while(start<end) {
        if(*start=='\n') {
            start++;
            if(start<end && *start!='\0')
                return start;
            else
                return NULL;
        } 
        start++;
    }
    return NULL;
}


int  getmysyspid(const char* name)
{
    char    buf[BUFSIZE];
    char    fileName[256];
    char    line[BUFSIZE];
    int     mypid= getpid();
    int     newpid= -1;
    int     size= -1;
    char*   beginline= line;

    sprintf(fileName, "%s/KvmHost/tmpLaunch%d.tmp", g_progDirectory, mypid);
    sprintf(buf, "ps ax | grep \"%s\"|awk '{print $1}'>%s", name, fileName);
#ifdef TEST
    fprintf(g_logFile, "getmysyspid command: %s\n", buf);
    fflush(g_logFile);
#endif
    if(system(buf)<0) {
        fprintf(g_logFile, "getmysyspid: system command failed\n");
        return -1;
    }
    // open the logfile and get the pid
    int fd= open(fileName, O_RDONLY);
    if(fd<0) {
        fprintf(g_logFile, "getmysyspid: cant open file\n");
        return -1;
    }
    if((size=read(fd, line, BUFSIZE))<0) {
        fprintf(g_logFile, "getmysyspid: read failed\n");
        return -1;
    }
    while(beginline!=NULL) {
        sscanf(beginline, "%d", &newpid);
        if(newpid!=mypid)
            break;
        newpid= -1;
        beginline= nextline(beginline, &line[size-1]);
    }
    close(fd);
#ifndef TEST1
    unlink(fileName);
#endif
    // TODO:  Another hack, the one we want is the kvm-pit one
    return newpid+2;
}


// ------------------------------------------------------------------------


void tcBufferprint(tcBuffer* p)
{
    fprintf(g_logFile, 
           "Buffer: procid: %ld, req: %ld, size: %ld, status: %ld, orig proc: %ld\n",
           (long int)p->m_procid, (long int)p->m_reqID, (long int)p->m_reqSize,
           (long int)p->m_ustatus, (long int)p->m_origprocid);
}
 

bool newgettcBuf(int fd, int* procid, u32* puReq, u32* pstatus, int* porigprocid,
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


bool newsendtcBuf(int fd, int procid, u32 uReq, u32 status, int origproc,
                          int paramsize, byte* params)
{
    byte            rgBuf[PADDEDREQ];
    tcBuffer*       pReq= (tcBuffer*) rgBuf;
    int             i;
    int             n;

    if(paramsize>(PARAMSIZE)) {
        fprintf(g_logFile, "newsendtcBuf buffer too small %d\n", paramsize);
        return false;
    }
    pReq->m_procid= procid;
    pReq->m_reqID= uReq;
    pReq->m_ustatus= status;
    pReq->m_origprocid= origproc;
    pReq->m_reqSize= paramsize;

#ifdef TEST
    fprintf(g_logFile, "newsendtcBuf: "); tcBufferprint(pReq);
#endif
    n= paramsize+sizeof(tcBuffer);
    memcpy(&rgBuf[sizeof(tcBuffer)], params, paramsize);
    i= write(fd, rgBuf, n);
    if(i<0) {
        fprintf(g_logFile, "newsendtcBuf: Write failed %d\n", i);
        return false;
    }
    return true;
}


bool startAppfromDeviceDriver(int fd, int* ppid, int argc, char **argv)
{
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
#ifdef TEST
    int i;
    fprintf(g_logFile, "startAppfromDeviceDriver, %d args\n", argc);
    for(i=0; i<argc;i++) {
        fprintf(g_logFile, "\t%s\n", argv[i]);
    }
    fprintf(g_logFile, "\n");
    fflush(g_logFile);
#endif

    size= encodeTCSERVICESTARTAPPFROMAPP(argc, argv, PARAMSIZE, rgBuf);
    if(size<0) {
        fprintf(g_logFile, "startAppfromDeviceDriver: encodeTCSERVICESTARTAPPFROMAPP failed\n");
        return false;
    }
#ifdef TEST1
    int     nc= 30;
    char*   nav[32];    // FIX
    if(!decodeTCSERVICESTARTAPPFROMAPP(&nc, nav, rgBuf)) {
        fprintf(g_logFile, "startAppfromDeviceDriver: cant decodebuf\n");
        return false;
    }
    fprintf(g_logFile, "Decoded args: %d\n", nc);
    for(i=0; i<nc;i++) {
        fprintf(g_logFile, "\t%s\n", nav[i]);
    }
    fprintf(g_logFile, "Sending request %s\n", rgBuf);
    return true;
#endif
    if(!newsendtcBuf(fd, g_myPid, TCSERVICESTARTAPPFROMAPP, 0, g_myPid, size, rgBuf)) {
        fprintf(g_logFile, "startAppfromDeviceDriver: newsendtcBuf for TCSERVICESTARTAPPFROMAPP failed\n");
        return false;
    }
    size= PARAMSIZE;
    if(!newgettcBuf(fd, &procid, &ureq, &ustatus, &origprocid, &size, rgBuf)) {
        fprintf(g_logFile, "startAppfromDeviceDriver: newgettcBuf for TCSERVICESTARTAPPFROMAPP failed\n");
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


// ------------------------------------------------------------------------


bool startApplication(int an, char** av, bool fKvmCall)
{
#ifdef  TEST
    fprintf(g_logFile, "startApplication\n");
    fflush(g_logFile);
#endif

    if(fKvmCall) {
        int    size= 0;
        char   buf[BUFSIZE];    // FIX

        // replace xml file name with xml
        int fd= open(av[1], O_RDONLY);
        if(fd<0) {
            fprintf(g_logFile, "startApplication cant open xml-file\n");
            return false;
        }
        if((size=read(fd, buf, BUFSIZE))<0) {
            fprintf(g_logFile, "startApplication: xml read failed\n");
            return false;
        }
        buf[size]= '\0';
        av[1]= strdup(buf);
#ifdef  TEST
    	fprintf(g_logFile, "startApplication, template:\n%s\n", av[1]);
    	fflush(g_logFile);
#endif
        close(fd);
    }

    int fd= initLinuxService();
    if(fd<0) {
        fprintf(g_logFile, "tcLaunch: can't open tcio device driver\n");
        return 1;
    }

    int   handle= 0;
    if(startAppfromDeviceDriver(fd, &handle, an, av))
        fprintf(g_logFile, "tcLaunch: measured program started, id: %d, exiting\n",
                        handle);
    else
        fprintf(g_logFile, "tcLaunch: program not started due to error\n");

    if(fKvmCall) {
        int pid= getmysyspid(av[0]);
        printf("PID of started process (%s child): %d\n", av[0], pid);
    }

    close(fd);
    fflush(g_logFile);
    return true;
}


bool GetPolicyKey()
{
    u32         ustatus;
    u32         ureq;
    u32         type= 0;
    int         procid= g_myPid;
    int         origprocid= g_myPid;
    int         size= PARAMSIZE;
    byte        rgBuf[PARAMSIZE];
    byte        pKey[PARAMSIZE];

#ifdef  TEST
    fprintf(g_logFile, "GetPolicyKey\n");
    fflush(g_logFile);
#endif

    int fd= initLinuxService();
    if(fd<0) {
        fprintf(g_logFile, "tcLaunch: can't open tcio device driver\n");
        return 1;
    }

    if(!newsendtcBuf(fd, g_myPid, TCSERVICEGETPOLICYKEYFROMAPP, 0, g_myPid, size, rgBuf)) {
        fprintf(g_logFile, "GetPolicyKey: newsendtcBuf for TCSERVICESTARTAPPFROMAPP failed\n");
        return false;
    }
    size= PARAMSIZE;
    if(!newgettcBuf(fd, &procid, &ureq, &ustatus, &origprocid, &size, rgBuf)) {
        fprintf(g_logFile, "GetPolicyKey: newgettcBuf for TCSERVICESTARTAPPFROMAPP failed\n");
        return false;
    }
    if(!decodeTCSERVICEGETPOLICYKEYFROMOS(&type, &size, pKey, rgBuf)) {
        fprintf(g_logFile, "GetPolicyKey: cant decode childproc\n");
        return false;
    }

    close(fd);
    fflush(g_logFile);
    return true;
}


// ------------------------------------------------------------------------


int main(int an, char** av)
{
    int         i;

    const char*     definedprogDirectory= getenv("CPProgramDirectory");
    if(definedprogDirectory!=NULL) {
        g_progDirectory= definedprogDirectory;
    }

    initLog(NULL);
    fprintf(g_logFile, "tcLaunch.exe, %d args\n", an);
    for(i=0; i<an; i++) {
        fprintf(g_logFile, "\t%s\n", av[i]);
    }
    fflush(g_logFile);

    if(an<2 ||an>30 || strcmp(av[1],"-help")==0) {
        fprintf(g_logFile, "\ttcLaunch.exe -KVMImage programname xml-file image-file \n");
        fprintf(g_logFile, "\ttcLaunch.exe -KVMLinux programname xml-file kernel-file initram-file image-file\n");
        fprintf(g_logFile, "\ttcLaunch.exe -KVMGuest program-file remaining arguments\n");
        fprintf(g_logFile, "\ttcLaunch.exe -LinuxGuest program-file remaining-args\n");
        fprintf(g_logFile, "\ttcLaunch.exe -LinuxHost program-file remaining-args\n");
        fprintf(g_logFile, "\ttcLaunch.exe -GetPolicyKey\n");
        return 1;
    }

    g_myPid= getpid();
    fprintf(g_logFile, "tcLaunch pid: %d\n", g_myPid);
    fflush(g_logFile);

    if(strcmp(av[1],"-KVMImage")==0) {
        g_tcioDDName= "/dev/kvmtciodd0";
        startApplication(an-2, av+2, true);
    }
    else if(strcmp(av[1],"-KVMLinux")==0) {
        g_tcioDDName= "/dev/kvmtciodd0";
        startApplication(an-2, av+2, true);
    }
    else if(strcmp(av[1],"-KVMGuest")==0) {
        g_tcioDDName= "/dev/ktciodd0";
        startApplication(an-2, av+2, true);
    }
    else if(strcmp(av[1],"-LinuxGuest")==0) {
        g_tcioDDName= "/dev/tcioDD0";
        startApplication(an-2, av+2, false);
    }
    else if(strcmp(av[1],"-LinuxHost")==0) {
        g_tcioDDName= "/dev/tcioDD0";
        startApplication(an-2, av+2, false);
    }
    else if(strcmp(av[1],"-GetPolicyKey")==0) {
        g_tcioDDName= "/dev/tcioDD0";
        GetPolicyKey();
    }
    else {
        fprintf(g_logFile, "tcLaunch: unknown option\n");
        return 1;
    }

    closeLog();
    return 0;
}


// ------------------------------------------------------------------------


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


// -------------------------------------------------------------------------


