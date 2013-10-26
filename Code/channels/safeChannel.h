//
//  File: safeChannel.h
//      John Manferdelli
//
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


#ifndef _SAFECHANNEL__H
#define _SAFECHANNEL__H


#include "jlmTypes.h"
#include "keys.h"
#include "aesni.h"
#include "channel.h"


#define CHANNEL_REQUEST    1
#define CHANNEL_RESPONSE   2
#define CHANNEL_NEGO       3
#define CHANNEL_NEGO_IV    4
#define CHANNEL_TRANSFER   5
#define CHANNEL_TERMINATE  6

#define MAXADDEDSIZE		256
#define MAXREQUESTSIZEWITHPAD   (MAXREQUESTSIZE+MAXADDEDSIZE)


class safeChannel {
public:
    int     fd;

    bool    fKeysValid;
    int     iAlg;
    int     iMode;
    int     iHMAC;
    int     sizeofEncKey;
    int     sizeofIntKey;
    byte    sendEncKey[BIGSYMKEYSIZE];      // FIX
    byte    sendIntKey[BIGSYMKEYSIZE];      // FIX
    byte    getEncKey[BIGSYMKEYSIZE];       // FIX
    byte    getIntKey[BIGSYMKEYSIZE];       // FIX

    bool    fsendIVValid;
    bool    fgetIVReceived;
    bool    fsendIVSent;
    byte    lastgetBlock[BIGSYMKEYSIZE];    // last decrypted cipher block received // FIX
    byte    lastsendBlock[BIGSYMKEYSIZE];   // last cipher block sent // FIX

    byte    plainMessageBlock[MAXREQUESTSIZEWITHPAD];
    byte    encryptedMessageBlock[MAXREQUESTSIZEWITHPAD];

    int     sizeprereadencrypted;
    byte    prereadencryptedMessageBlock[MAXREQUESTSIZEWITHPAD];

    aesni     sendAES;
    aesni     getAES;

    int     nAuthenticatingPrincipals;
    int     nAuthenticatedPrincipals;
    // put principals here


            safeChannel();
            ~safeChannel();

    bool    initChannel(int fdIn, int alg, int mode, int hmac,
                        int sizeofEncKeys, int sizeofIntKeys,
                        byte* sendEncKeyIn, byte* sendIntKeyIn,
                        byte* getEncKeyIn, byte* getIntKeyIn);
    int     getFullPacket(byte* buf, int maxSize, int* ptype, 
                          byte* pmultipart, byte* pfinalpart);
    int     safesendPacket(byte* buf, int len, int type, byte multipart, byte finalpart);
    int     safegetPacket(byte* buf, int maxSize, int* ptype, 
                          byte* pmultipart, byte* pfinalpart);
};


#endif


//----------------------------------------------------------------------------


