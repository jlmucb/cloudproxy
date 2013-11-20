//
//  File: channel.cpp
//  Description: common channel implementation
//
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


#include "jlmTypes.h"
#include "logging.h"
#include "channel.h"

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
#include <errno.h>


//----------------------------------------------------------------------


int sendPacket(int fd, byte* buf, int len, int type, byte multi, byte final)
{
    packetHdr       oHdr;

#ifdef IOTEST
    fprintf(g_logFile, "sendPacket %d len %d type %d\n", fd, len, type);
    fflush(g_logFile);
#endif
    oHdr.packetType= type;
    oHdr.len= len;
    oHdr.multipart= multi;
    oHdr.finalpart= final;
    oHdr.error= 0;

    ssize_t bytesWritten = write(fd, &oHdr, sizeof(packetHdr));

    // make sure we can write the header in one write
    if (sizeof(packetHdr) != bytesWritten) {
      fprintf(g_logFile, "Tried to write the packet header (%d bytes), but only wrote %d bytes\n", sizeof(packetHdr), bytesWritten);
      return 0;
    }
    
    // send the message in chunks as allowed by the underlying protocol
    bytesWritten = 0;
    do {
      ssize_t ret = write(fd, buf + bytesWritten, len - bytesWritten);
      if (ret < 0) {
        fprintf(g_logFile, "Could not write the full buffer of length %d to the network after %d bytes were written\n", len, bytesWritten);
        return 0;
      }

      bytesWritten += ret;
    } while (bytesWritten < len);

    return len;
}


int getPacket(int fd, byte* buf, int maxSize, int* ptype, byte* pmulti, byte* pfinal)
{
    packetHdr       oHdr;

#ifdef IOTEST
    fprintf(g_logFile, "getPacket %d len %d type %d\n", fd, maxSize, *ptype);
    fflush(g_logFile);
#endif
    oHdr.error= 0;
    if(read(fd, &oHdr, sizeof(packetHdr)) < (ssize_t)sizeof(packetHdr)) {
        return 0;
    }

    // clear input?
    if((int)oHdr.len > maxSize)
        return BUFFERTOOSMALL;
    *ptype= oHdr.packetType;
    *pmulti= oHdr.multipart;
    *pfinal= oHdr.finalpart;
    if(oHdr.error!=0)
        return -((int) oHdr.error);

    ssize_t bytesRead = 0;
    do {
      ssize_t ret = read(fd, buf + bytesRead, oHdr.len - bytesRead);
      if (ret < 0) {
        fprintf(g_logFile, "Could not read a buffer of length %d from the network after %d bytes were read\n", oHdr.len, bytesRead);
        return 0;
      }

      bytesRead += ret;
    } while (bytesRead < oHdr.len);

    return oHdr.len;
}


//----------------------------------------------------------------------------------


