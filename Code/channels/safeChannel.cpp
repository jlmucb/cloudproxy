//
//  File: safeChannel.cpp
//      John Manferdelli
//
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
#include "jlmcrypto.h"
#include "keys.h"
#include "tinyxml.h"
#include "channel.h"
#include "safeChannel.h"

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


safeChannel::safeChannel()
{
    fKeysValid= false;
    fsendIVValid= false;
    iAlg= NOALG;
    iMode= NOMODE;
    iHMAC= NOHMAC;
    fd= -1;
    sizeofEncKey= -1;
    sizeofIntKey= -1;
    fgetIVReceived= false;
    fsendIVSent= false;
    nAuthenticatingPrincipals= 0;
    nAuthenticatedPrincipals= 0;
    iUnGetSize= 0;
}


safeChannel::~safeChannel()
{

    if(sendEncKey!=NULL && sizeofEncKey>0)
        memset(sendEncKey, 0, sizeofEncKey);
    if(getEncKey!=NULL && sizeofEncKey>0)
        memset(getEncKey, 0, sizeofEncKey);
    if(sendIntKey!=NULL && sizeofIntKey>0)
        memset(sendIntKey, 0, sizeofIntKey);
    if(getIntKey!=NULL && sizeofIntKey>0)
        memset(getIntKey, 0, sizeofIntKey);

    sendAES.CleanKeys();
    getAES.CleanKeys();
}


bool safeChannel::initChannel(int fdIn, int alg, int mode, int hmac,
                              int sizeofEncKeys, int sizeofIntKeys,
                              byte* sendEncKeyIn, byte* sendIntKeyIn,
                              byte* getEncKeyIn, byte* getIntKeyIn)
{
    fd= fdIn;

#ifdef IOTEST
    fprintf(g_logFile, "initChannel. alg: %d, mode: %d, hmac: %d, sizeofIntKeys: %d, sizeofEncKeys: %d\n",
            alg, mode, hmac, sizeofIntKeys, sizeofEncKeys);
#endif

    if(alg!=AES128 || mode!=CBCMODE || hmac!=HMACSHA256) {
        fprintf(g_logFile, "Unsupported algorithm\n");
        return false;
    }
    if(sizeofEncKeys>BIGSYMKEYSIZE || sizeofIntKeys>BIGSYMKEYSIZE) {
        fprintf(g_logFile, "Unsupported key lengths\n");
        return false;
    }

    iAlg= alg;
    iMode= mode;
    iHMAC= hmac;
    sizeofEncKey= sizeofEncKeys;
    sizeofIntKey= sizeofIntKeys;

    memset(sendEncKey, 0, BIGSYMKEYSIZE);
    memset(sendIntKey, 0, BIGSYMKEYSIZE);
    memset(getEncKey, 0, BIGSYMKEYSIZE);
    memset(getIntKey, 0, BIGSYMKEYSIZE);
    memset(lastgetBlock, 0, BIGSYMKEYSIZE);
    memset(lastsendBlock, 0, BIGSYMKEYSIZE);

    memcpy(sendEncKey, sendEncKeyIn, sizeofEncKeys);
    memcpy(getEncKey, getEncKeyIn, sizeofEncKeys);
    memcpy(sendIntKey, sendIntKeyIn, sizeofIntKeys);
    memcpy(getIntKey, getIntKeyIn, sizeofIntKeys);

    sendAES.KeySetupEnc(sendEncKey, sizeofEncKey*NBITSINBYTE);
    getAES.KeySetupDec(getEncKey, sizeofEncKey*NBITSINBYTE);

#ifdef IOTEST
    fprintf(g_logFile, "\nSize of keys: %d\n", sizeofEncKeys);
    PrintBytes("Send Enc Key", sendEncKey, sizeofEncKey);
    PrintBytes("Get Enc  Key", getEncKey, sizeofEncKey);
    PrintBytes("Send Int Key", sendIntKey, sizeofIntKey);
    PrintBytes("Get Int  Key", getIntKey, sizeofIntKey);
    fprintf(g_logFile, "\n");
#endif

    nAuthenticatingPrincipals= 0;
    nAuthenticatedPrincipals= 0;

    fKeysValid= true;

    if(mode==CBCMODE) {
        if(!getCryptoRandom(sizeofEncKeys*NBITSINBYTE, lastsendBlock)) {
            fprintf(g_logFile, "Cant generate IV\n");
            return false;
        }
        fsendIVValid= true;
    }

    return true;
}


#define BLKSIZE 16


int  safeChannel::safesendPacket(byte* buf, int len, int type, byte multipart, byte finalpart)
{
#ifdef IOTEST1
    fprintf(g_logFile, "safesendPacket(%d, %d, %d, %d)\n", len, type, multipart, finalpart);
#endif
    packetHdr   oHdr;
    int         totalSize;
    int         newMsgSize= len+sizeof(packetHdr);
    int         hmacSize= SHA256_DIGESTSIZE_BYTES;
    int         remaining= newMsgSize%BLKSIZE;
    int         residue= BLKSIZE-remaining;
    byte*       pLastCipher= lastsendBlock;
    byte*       pNextCipher= encryptedMessageBlock;
    byte*       pNextPlain= plainMessageBlock;
    int         i;
    int         iLeft;
    byte        rguCBCMixer[BLKSIZE];

    // buffer too big?
    if(len>MAXREQUESTSIZE) {
        fprintf(g_logFile, "Message too big\n");
        return PUTTOOBIGERROR;
    }

    // IV?
    if(!fsendIVSent) {
        fprintf(g_logFile, "IV uninitialized\n");
        return UNINITIALIZEDIV;
    }

    // compute size
    if(remaining==0) {
        newMsgSize+= BLKSIZE;
    }
    else {
        newMsgSize+= residue;
    }
    totalSize= newMsgSize+hmacSize;

    // message header
    oHdr.packetType= type;
    oHdr.len= totalSize;
    oHdr.multipart= multipart;
    oHdr.finalpart= finalpart;
    oHdr.error= 0;
    memcpy(plainMessageBlock, (byte*)&oHdr, sizeof(packetHdr));
    memcpy(&plainMessageBlock[sizeof(packetHdr)], buf, len);

    byte* pNext= &plainMessageBlock[newMsgSize-BLKSIZE];

    // pad
    if(remaining==0) {
        pNext[0]= 0x80;
        for(i=1; i<BLKSIZE;i++) 
            pNext[i]= 0x00;
    }
    else {
        pNext[remaining]= 0x80;
        for(i=1; i<residue;i++) 
            pNext[remaining+i]= 0x00;
    }

    // hmac
    if(!hmac_sha256(plainMessageBlock, newMsgSize, sendIntKey, 
                    sizeofIntKey, &plainMessageBlock[newMsgSize])) {
        fprintf(g_logFile, "bad compute mac error\n");
        return HMACCOMPERROR;
    }
#ifdef IOTEST1
    fprintf(g_logFile, "safesendPacket HMAC, %d bytes\n",newMsgSize);
    PrintBytes("Int key:", sendIntKey, sizeofIntKey);
    PrintBytes("Message:", plainMessageBlock, newMsgSize);
    PrintBytes("Mac:", &plainMessageBlock[newMsgSize], SHA256_DIGESTSIZE_BYTES);
    fprintf(g_logFile, "totalSize: %d\n", totalSize);
#endif

    // encrypt
    iLeft= totalSize;
    while(iLeft>0) {
        memcpy(rguCBCMixer, pNextPlain, BLKSIZE);
        inlineXorto(rguCBCMixer, pLastCipher, BLKSIZE);
        sendAES.Encrypt(rguCBCMixer, pNextCipher);
        iLeft-= BLKSIZE;
        pLastCipher= pNextCipher;
        pNextPlain+= BLKSIZE;
        pNextCipher+= BLKSIZE;
    }
    memcpy(lastsendBlock, pLastCipher, BLKSIZE);

    int n= write(fd, encryptedMessageBlock, totalSize);
    if(n<0) {
        fprintf(g_logFile, "safesendPacket failure\n");
        return n;
    }
    return len;
}

int  safeChannel::safegetPacket(byte* buf, int maxSize, int* ptype, 
                                byte* pmultipart, byte* pfinalpart)
{
    int     n;
    int     padLen, residue;
    byte*   pLastCipher= lastgetBlock;
    byte*   pNextCipher= encryptedMessageBlock;
    byte*   pNextPlain= plainMessageBlock;
    int     iLeft;
    int     iMsgLen;

#ifdef IOTEST1
    fprintf(g_logFile, "safegetPacket(%d, %d, %d, %d)\n", maxSize, *ptype, *pmultipart, *pfinalpart);
#endif

    // limit on request size
    if(maxSize>MAXREQUESTSIZE) {
        fprintf(g_logFile, "safegetPacket request too large, %d byte limit\n", MAXREQUESTSIZE);
        return GETTOOBIGERROR;
    }

    // IV set yet?
    if(!fgetIVReceived)
        return UNINITIALIZEDIV;

    // get 
    if(iUnGetSize>0) {
#ifdef IOTEST1
        fprintf(g_logFile, "retrieving %d bytes from unget buffer\n", iUnGetSize);
#endif
        memcpy(plainMessageBlock, ungetBuf, iUnGetSize);
        n= iUnGetSize;
        iUnGetSize= 0;
    }
    else {
        n= recv(fd, encryptedMessageBlock, maxSize+MAXADDEDSIZE, 0);
        if(n==0) {
            fprintf(g_logFile, "Got 0 return on socket\n");
        }
        if(n<0) {
            fprintf(g_logFile, "Cant do initial get\n");
            return n;
        }

        // Decrypt
        iLeft= n;
        while(iLeft>0) {
            getAES.Decrypt(pNextCipher, pNextPlain);
            inlineXorto(pNextPlain, pLastCipher, BLKSIZE);
            iLeft-= BLKSIZE;
            pLastCipher= pNextCipher;
            pNextPlain+= BLKSIZE;
            pNextCipher+= BLKSIZE;
        }
        memcpy(lastgetBlock, pLastCipher, BLKSIZE);
    }

    *ptype= ((packetHdr*) plainMessageBlock)->packetType;
    *pmultipart= ((packetHdr*) plainMessageBlock)->multipart;
    *pfinalpart= ((packetHdr*) plainMessageBlock)->finalpart;
    // oHdr.error= 0;?

#ifdef IOTEST1
    fprintf(g_logFile, "safeget receive is %d, header is %d\n", n, ((packetHdr*) plainMessageBlock)->len);
#endif

    // Two messages were merged?
    if(n>(int)((packetHdr*) plainMessageBlock)->len) {
        iUnGetSize= n-((packetHdr*) plainMessageBlock)->len;
#ifdef IOTEST1
        fprintf(g_logFile, "ungetting %d bytes\n", iUnGetSize);
#endif
        memcpy(ungetBuf, &plainMessageBlock[((packetHdr*) plainMessageBlock)->len], iUnGetSize);
        n= ((packetHdr*) plainMessageBlock)->len;
    }

    byte*   rguPad= &plainMessageBlock[n]-BLKSIZE-SHA256_DIGESTSIZE_BYTES;
    byte*   rguHmac= &plainMessageBlock[n]-SHA256_DIGESTSIZE_BYTES;
    byte    rguHmacComputed[SHA256_DIGESTSIZE_BYTES];

    n-= SHA256_DIGESTSIZE_BYTES;   // remove HMAC at the end
    // hmac check
    if(!hmac_sha256(plainMessageBlock, n, getIntKey, sizeofIntKey, rguHmacComputed)) {
        fprintf(g_logFile, "HMAC Compute error 1\n");
        return HMACCOMPERROR;
    }
#ifdef IOTEST
    fprintf(g_logFile, "safegetPacket HMAC, %d bytes\n",n);
    PrintBytes("Int key:", getIntKey, sizeofIntKey);
    PrintBytes("Message:", plainMessageBlock, n);
    PrintBytes("Computed Mac:", rguHmacComputed, SHA256_DIGESTSIZE_BYTES);
    PrintBytes("Mac:", rguHmac, SHA256_DIGESTSIZE_BYTES);
    fprintf(g_logFile, "Header size: %d\n", ((packetHdr*) plainMessageBlock)->len);
#endif
    if(!isEqual(rguHmac, rguHmacComputed, SHA256_DIGESTSIZE_BYTES)) {
        fprintf(g_logFile, "HMAC comparison error 2\n");
        return HMACMATCHERROR;
    }

    // depad
    for(residue=(BLKSIZE-1); residue>=0; residue--) {
        if(rguPad[residue]!=0) {
            if(rguPad[residue]!=0x80) {
                fprintf(g_logFile, "bad pad error 1, %02x\n", rguPad[residue]);
                return BADPADDERROR;
            }
            break;
        }
    }
    if(residue<0) {
        fprintf(g_logFile, "bad pad error\n");
        return BADPADDERROR;
    }
    padLen= BLKSIZE-residue;
    iMsgLen= ((packetHdr*) plainMessageBlock)->len;
    iMsgLen-= padLen+SHA256_DIGESTSIZE_BYTES+sizeof(packetHdr);

    memcpy(buf, &plainMessageBlock[sizeof(packetHdr)], iMsgLen);
#ifdef IOTEST
    fprintf(g_logFile, "safegetPacket(%d, %d, %d) --- returning %d bytes\n", 
            *ptype, *pmultipart, *pfinalpart, iMsgLen);
#endif
    return iMsgLen;
}


//----------------------------------------------------------------------------------


