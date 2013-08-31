//
//  File: tcIO.h
//  Description: tcIO defines
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


#ifndef __TCIO_H__
#define __TCIO_H__

#include "jlmTypes.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#ifdef LINUX
#include <linux/un.h>
#else
#include <sys/un.h>
#endif
#include "tciohdr.h"


#define TCIODEVICEDRIVERPRESENT

#define TCDEVICEDRIVER                        0
#define SERVERSIDEUNIXSTREAMMASTER            1
#define SERVERSIDEUNIXSTREAMSLAVE             2
#define CLIENTSIDEUNIXSTREAM                  3
#define SERVERSIDEDEVICEDRIVER                4
#define CLIENTSIDEDEVICEDRIVER                5


// #define TCIODDNAME  "/dev/tcioDD0"


#define PADDEDREQ 8192
#define PARAMSIZE static_cast<int>(8192-sizeof(tcBuffer))


//
//  open bidirectional channel
//
class tcChannel {
public:
#ifndef TCIODEVICEDRIVERPRESENT
    struct sockaddr_un      m_serveraddr;
    struct sockaddr_un      m_clientaddr;
#endif
    u32                     m_uType;
    int                     m_fd;

    bool OpenBuf(u32 type, int fd, const char* file, u32 flags);
    int  WriteBuf(byte* buf, int size);
    int  ReadBuf(byte* buf, int size);
    void CloseBuf();
    bool gettcBuf(int* procid, u32* puReq, u32* pstatus, 
                  int* porigprocid, int* paramsize, byte* params);
    bool sendtcBuf(int procid, u32 uReq, u32 status, 
                   int origproc, int paramsize, byte* params);
};


bool openclient(int* pfd, const char* szunixPath, struct sockaddr* psrv);
bool openserver(int* pfd, const char* szunixPath, struct sockaddr* psrv);



#define TERMINATE  102


#endif


// ------------------------------------------------------------------------------


