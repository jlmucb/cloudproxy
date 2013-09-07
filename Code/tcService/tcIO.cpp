//
//  File: tcIO.cpp
//  Description: tcIO implementation
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

// -------------------------------------------------------------------


#include "jlmTypes.h"
#include "logging.h"
#include "tcIO.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <signal.h>
#include <errno.h>

#ifdef LINUX
#include <wait.h>
#else
#include <sys/wait.h>
#endif

extern const char* g_tcioDDName;


// -------------------------------------------------------------------


void tcBufferprint(tcBuffer* p)
{
    fprintf(g_logFile, "Buffer: procid: %ld, req: %ld, size: %ld, status: %ld, orig proc: %ld\n",
           (long int)p->m_procid, (long int)p->m_reqID, (long int)p->m_reqSize, 
           (long int)p->m_ustatus, (long int)p->m_origprocid); 
}


// -------------------------------------------------------------------


bool g_fterminateLoop= false;

#ifndef TCIODEVICEDRIVERPRESENT
bool openserver(int* pfd, const char* szunixPath, struct sockaddr* psrv)
{
    int                 fd;
    int                 slen= 0;
    int                 iQsize= 5;
    int                 iError= 0;
    int                 l;

    fprintf(g_logFile, "open server FILE: %s\n", szunixPath);
    unlink(szunixPath);
    if((fd=socket(AF_UNIX, SOCK_STREAM, 0))==(-1))
        return false;

    slen= strlen(szunixPath)+sizeof(psrv->sa_family)+1;
    memset((void*) psrv, 0, slen);
    psrv->sa_family= AF_UNIX;
    strcpy(psrv->sa_data, szunixPath);

    iError= bind(fd, psrv, slen);
    if(iError<0) {
        fprintf(g_logFile, "openserver:bind error %s\n", strerror(errno));
        return false;
    }
    if(listen(fd, iQsize)==(-1)) {
        fprintf(g_logFile, "listen error in server init");
        return false;
    }

    *pfd= fd;
    return true;
}


bool openclient(int* pfd, const char* szunixPath, struct sockaddr* psrv)
{
    int     fd;
    int     newfd;
    int     slen= strlen(szunixPath)+sizeof(psrv->sa_family)+1;
    int     iError= 0;

    fprintf(g_logFile, "open client FILE: %s\n", szunixPath);
    if((fd=socket(AF_UNIX, SOCK_STREAM, 0))==(-1))
        return false;

    memset((void*) psrv, 0, slen);
    psrv->sa_family= AF_UNIX;
    strcpy(psrv->sa_data, szunixPath);

    iError= connect(fd, psrv, slen);
    if(iError<0) {
        fprintf(g_logFile, "openclient: Cant connect client, %s\n", strerror(errno));
        close(fd);
        return false;
    }

    *pfd= fd;
    return true;
}
#endif


bool tcChannel::OpenBuf(u32 type, int fd, const char* file, u32 flags)
{
    m_uType= type;
    m_fd= -1;

    switch(type) {
#ifdef TCIODEVICEDRIVERPRESENT
      case TCDEVICEDRIVER:
        m_fd= open(g_tcioDDName, O_RDWR);
        if(m_fd<0) {
            fprintf(g_logFile, "Can't open device driver %s\n", g_tcioDDName);
            fprintf(g_logFile, "Reason: %s\n", strerror(errno));
            return false;
        }
        return true;
#else
      case SERVERSIDEUNIXSTREAMMASTER:
        if(file==NULL)
            return false;
#ifdef TEST
        fprintf(g_logFile, "OpenBuf %s, master server\n", file);
#endif
        if(!openserver(&m_fd, file, (struct sockaddr*)&m_serveraddr)) {
            fprintf(g_logFile, "Can't open server\n");
            return false;
        }
        return true;
      case SERVERSIDEUNIXSTREAMSLAVE:
#ifdef TEST
        fprintf(g_logFile, "OpenBuf slave server\n");
#endif
        m_fd= fd;
        return true;
      case CLIENTSIDEUNIXSTREAM:
        if(file==NULL)
            return false;
#ifdef TEST
        fprintf(g_logFile, "OpenBuf %s, client\n", file);
#endif
        if(!openclient(&m_fd, file, (struct sockaddr*)&m_serveraddr)) {
            fprintf(g_logFile, "Can't open client\n");
            return false;
        }
        return true;
      case SERVERSIDEDEVICEDRIVER:
      case CLIENTSIDEDEVICEDRIVER:
#endif
      default:
        return false;
    }
}


int tcChannel::WriteBuf(byte* buf, int size)
{
#ifdef TCIODEVICEDRIVERPRESENT
    return write(m_fd, buf, size);
#else
    return send(m_fd, buf, size, 0);
#endif
}


int tcChannel::ReadBuf(byte* buf, int size)
{
#ifdef TCIODEVICEDRIVERPRESENT
    return read(m_fd, buf, size);
#else
    return recv(m_fd, buf, size, 0);
#endif
}


void tcChannel::CloseBuf()
{
    close(m_fd);
}


// -------------------------------------------------------------------


bool tcChannel::gettcBuf(int* procid, u32* puReq, u32* pstatus, int* porigprocid, 
                         int* paramsize, byte* params)
{
    byte            rgBuf[PADDEDREQ];
    tcBuffer*       pReq= (tcBuffer*) rgBuf;
    int             i;
    int             n;

#ifdef TEST
    fprintf(g_logFile, "gettcBuf outstanding %d\n", m_fd);
#endif
    n= *paramsize+sizeof(tcBuffer);
    if(n>PADDEDREQ) {
        fprintf(g_logFile, "Buffer too small\n");
        return false;
    }
    i= ReadBuf(rgBuf, n);
    if(i<0) {
        fprintf(g_logFile, "ReadBufRequest failed in gettcBuf %d %d\n", i, n);
        return false;
    }

    // only for socket
    if(i==0) {
        fprintf(g_logFile, "Client closed connection? %d\n", m_fd);
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


bool tcChannel::sendtcBuf(int procid, u32 uReq, u32 status, int origproc, 
                          int paramsize, byte* params)
{
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
    i= WriteBuf(rgBuf, n);
    if(i<0) {
        fprintf(g_logFile, "tcChannel::sendtcBuf: WriteBufRequest failed %d\n", i);
        return false;
    }
    return true;
}


// ------------------------------------------------------------------------------


