//
//  File: channel.h
//  Description: common channel definitions
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



//-------------------------------------------------------------------------


#ifndef _CHANNEL__H
#define _CHANNEL__H


#include "jlmTypes.h"

#define CHANNEL_REQUEST    1
#define CHANNEL_RESPONSE   2
#define CHANNEL_NEGO       3
#define CHANNEL_NEGO_IV    4
#define CHANNEL_TRANSFER   5
#define CHANNEL_TERMINATE  6

#define MAXREQUESTSIZE     16384

// getPacket/sendPacket Errors
#define UNKNOWNERROR     (-1)
#define GETTOOBIGERROR   (-2)
#define PUTTOOBIGERROR   (-3)
#define HMACFAILED       (-4)
#define BUFFERTOOSMALL   (-5)
#define HMACCOMPERROR    (-6)
#define HMACMATCHERROR   (-7)
#define BADPADDERROR     (-8)
#define UNINITIALIZEDIV  (-9)


class packetHdr {
public:
    byte   packetType;
    byte   error;
    byte   multipart;
    byte   finalpart;
    u32    len;
};


int sendPacket(int fd, byte* buf, int len, int type, byte multipart, byte finalpart);
int getPacket(int fd, byte* buf, int maxSize, int* ptype, 
              byte* pmultipart, byte* pfinalpart);

#endif


//----------------------------------------------------------------------------


