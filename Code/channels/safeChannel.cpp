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
    sizeprereadencrypted= 0;
    nAuthenticatingPrincipals= 0;
    nAuthenticatedPrincipals= 0;
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


// -------------------------------------------------------------------------------


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


// -------------------------------------------------------------------------------


int safeChannel::getFullPacket(byte* buf, int maxSize, int* ptype, 
                      byte* pmultipart, byte* pfinalpart)
//
//  collects a full message
//      only decrypt to message boundary
//      put excess preread cipher in prereadencryptedMessageBlock
//      authenticate message, etc done here
{
    int     padLen, residue;
    byte*   pLastCipher= lastgetBlock;
    byte*   pNextCipher= encryptedMessageBlock;
    byte*   pNextPlain= plainMessageBlock;
    int     fullMsgSize= 0;
    int     sizeEncryptedBuf= 0;
    int     sizedecryptedMsg= 0;
    int     iLeft= 0;
    int     m= 0;
    int     n= 0;

#ifdef IOTEST
    fprintf(g_logFile, "getFullPacket(%d, %d, %d, %d)\n", maxSize, 
            *ptype, *pmultipart, *pfinalpart);
    fprintf(g_logFile, "\tpre-fetched encrypted: %d\n", sizeprereadencrypted);
    fflush(g_logFile);
#endif

    // any preread available?
    sizeEncryptedBuf= 0;
    if(sizeprereadencrypted>0) {
        memcpy(encryptedMessageBlock, prereadencryptedMessageBlock, 
               sizeprereadencrypted);
        sizeEncryptedBuf= sizeprereadencrypted;
        sizeprereadencrypted= 0;
    }

    if(sizeEncryptedBuf==0) {
        sizeEncryptedBuf= recv(fd, encryptedMessageBlock, MAXREQUESTSIZE, 0);
        if(sizeEncryptedBuf==0) {
            fprintf(g_logFile, "Got 0 return on socket\n");
            return 0;
        }
        if(sizeEncryptedBuf<0) {
            fprintf(g_logFile, "Cant do initial get\n");
            return sizeEncryptedBuf;
        }
#ifdef IOTEST
        fprintf(g_logFile, "getFullPacket: just read, sizeEncrypted: %d\n", sizeEncryptedBuf);
        fflush(g_logFile);
#endif
    }

    // Decrypt first block to get message size
    getAES.Decrypt(pNextCipher, pNextPlain);
    inlineXorto(pNextPlain, pLastCipher, BLKSIZE);
    pLastCipher= pNextCipher;
    pNextPlain+= BLKSIZE;
    pNextCipher+= BLKSIZE;
    fullMsgSize= ((packetHdr*) plainMessageBlock)->len;

#ifdef IOTEST
    fprintf(g_logFile, "getFullPacket: message size %d, sizeEncryptedBuf: %d\n", 
            fullMsgSize, sizeEncryptedBuf);
    fflush(g_logFile);
#endif
    if(fullMsgSize<0 || fullMsgSize>MAXREQUESTSIZEWITHPAD) {
        fprintf(g_logFile, "getFullPacket: bad message size %d\n", fullMsgSize);
#ifdef IOTEST
        PrintBytes((char*)"Last decrypted: ", plainMessageBlock, BLKSIZE);
        fflush(g_logFile);
#endif
        return -1;
    }

    // big enough?
    if(fullMsgSize>sizeEncryptedBuf) {
#ifdef IOTEST
        fprintf(g_logFile, "getFullPacket: sizeEncryptedBuf smaller than message\n");
        fflush(g_logFile);
#endif
        m= fullMsgSize-sizeEncryptedBuf;
        while(m>0) {
            n= recv(fd, &encryptedMessageBlock[sizeEncryptedBuf], m, 0);
#ifdef IOTEST
            fprintf(g_logFile, "getFullPacket: received %d in loop\n",n);
            fflush(g_logFile);
#endif
            if(n<0)
                return n;
            sizeEncryptedBuf+= n;
            m-= n;
        }
    }

    // too big?
    if(fullMsgSize<sizeEncryptedBuf) {
        n=  sizeEncryptedBuf-fullMsgSize;
#ifdef IOTEST
        fprintf(g_logFile, "getFullPacket: sizeEncryptedBuf bigger than message\n");
        fprintf(g_logFile, "fullMsgSize: %d, sizeEncryptedBuf: %d, storing: %d\n", 
                fullMsgSize, sizeEncryptedBuf, n);
        fflush(g_logFile);
#endif
        if(n>MAXREQUESTSIZEWITHPAD) {
            fprintf(g_logFile, "getFullPacket: violate buffer size %d\n", n);
            return -1;
        }
        memcpy(prereadencryptedMessageBlock, &encryptedMessageBlock[fullMsgSize],n);
        sizeEncryptedBuf-= n;
        sizeprereadencrypted= n;
    }

    // should be just right now
    if(fullMsgSize!=sizeEncryptedBuf) {
        fprintf(g_logFile, "getFullPacket: fullMsgsize should match buffersize %d %d\n", 
                fullMsgSize, sizeEncryptedBuf);
        return -1;
    }

#ifdef IOTEST
    fprintf(g_logFile, "getFullPacket: sizeEncryptedBuf just right %d\n",
            sizeEncryptedBuf);
    fflush(g_logFile);
#endif
    // Decrypt remaining
    iLeft= sizeEncryptedBuf-BLKSIZE;
    while(iLeft>0) {
        getAES.Decrypt(pNextCipher, pNextPlain);
        inlineXorto(pNextPlain, pLastCipher, BLKSIZE);
        iLeft-= BLKSIZE;
        pLastCipher= pNextCipher;
        pNextPlain+= BLKSIZE;
        pNextCipher+= BLKSIZE;
    }

    // copy last cipher back for next round
    memcpy(lastgetBlock, pLastCipher, BLKSIZE);

#ifdef IOTEST
    fprintf(g_logFile, "getFullPacket: got last block, checking MAC\n");
    fflush(g_logFile);
#endif
    // check MAC
    byte*   rguPad= &plainMessageBlock[fullMsgSize-BLKSIZE-SHA256_DIGESTSIZE_BYTES];
    byte*   rguHmac= &plainMessageBlock[fullMsgSize-SHA256_DIGESTSIZE_BYTES];
    byte    rguHmacComputed[SHA256_DIGESTSIZE_BYTES];

    n= fullMsgSize-SHA256_DIGESTSIZE_BYTES;   // remove HMAC at the end

    // hmac check
    if(!hmac_sha256(plainMessageBlock, n, getIntKey, sizeofIntKey, rguHmacComputed)) {
        fprintf(g_logFile, "getFullPacket: HMAC Compute error 1\n");
        return HMACCOMPERROR;
    }
    if(!isEqual(rguHmac, rguHmacComputed, SHA256_DIGESTSIZE_BYTES)) {
        fprintf(g_logFile, "getFullPacket: HMAC comparison error 2\n");
#ifdef IOTEST
        PrintBytes((char*) "original buffer\n", encryptedMessageBlock, n);
        PrintBytes((char*) "decrypted buffer\n", plainMessageBlock, n);
        PrintBytes((char*) "send Hmac\n", rguHmac, SHA256_DIGESTSIZE_BYTES);
        PrintBytes((char*) "computed Hmac\n", rguHmacComputed, SHA256_DIGESTSIZE_BYTES);
#endif
        return HMACMATCHERROR;
    }

    // depad
    for(residue=(BLKSIZE-1); residue>=0; residue--) {
        if(rguPad[residue]!=0) {
            if(rguPad[residue]!=0x80) {
                fprintf(g_logFile, "getFullPacket: bad pad error 1, %02x\n", rguPad[residue]);
                return BADPADDERROR;
            }
            break;
        }
    }
    if(residue<0) {
        fprintf(g_logFile, "getFullPacket: bad pad error\n");
        return BADPADDERROR;
    }
    padLen= BLKSIZE-residue;

    // compute message length and copy
    sizedecryptedMsg= n-padLen-sizeof(packetHdr);
    if(maxSize<sizedecryptedMsg)
        return -1;

#ifdef IOTEST
    fprintf(g_logFile, "getFullPacket: copying message %d\n", sizedecryptedMsg);
    fflush(g_logFile);
#endif

    memcpy(buf, &plainMessageBlock[sizeof(packetHdr)], sizedecryptedMsg);
    *ptype= ((packetHdr*) plainMessageBlock)->packetType;
    *pmultipart= ((packetHdr*) plainMessageBlock)->multipart;
    *pfinalpart= ((packetHdr*) plainMessageBlock)->finalpart;
    return sizedecryptedMsg;
}


int  safeChannel::safegetPacket(byte* buf, int maxSize, int* ptype, 
                                byte* pmultipart, byte* pfinalpart)
{
#ifdef IOTEST
    fprintf(g_logFile, "safegetPacket(%d, %d, %d, %d)\n", maxSize, *ptype, 
            *pmultipart, *pfinalpart);
#endif

    // limit on request size
    if(maxSize>MAXREQUESTSIZE) {
        fprintf(g_logFile, "safegetPacket request too large, %d byte limit\n", MAXREQUESTSIZE);
        return GETTOOBIGERROR;
    }

    // IV set yet?
    if(!fgetIVReceived)
        return UNINITIALIZEDIV;

    return getFullPacket(buf, maxSize, ptype, pmultipart, pfinalpart);
}


//----------------------------------------------------------------------------------


