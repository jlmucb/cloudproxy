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

    memset(sendEncKey, 0, BIGSYMKEYSIZE);
    memset(sendIntKey, 0, BIGSYMKEYSIZE);
    memset(getEncKey, 0, BIGSYMKEYSIZE);
    memset(getIntKey, 0, BIGSYMKEYSIZE);
    memset(lastgetBlock, 0, BIGSYMKEYSIZE);
    memset(lastsendBlock, 0, BIGSYMKEYSIZE);

    sizeofEncKey= sizeofEncKeys;
    sizeofIntKey= sizeofIntKeys;

    memcpy(sendEncKey, sendEncKeyIn, sizeofEncKeys);
    memcpy(getEncKey, getEncKeyIn, sizeofEncKeys);
    memcpy(sendIntKey, sendIntKeyIn, sizeofIntKeys);
    memcpy(getIntKey, getIntKeyIn, sizeofIntKeys);

    sendAES.KeySetupEnc(sendEncKey, sizeofEncKey*NBITSINBYTE);
    getAES.KeySetupDec(getEncKey, sizeofEncKey*NBITSINBYTE);

#ifdef IOTEST
    fprintf(g_logFile, "\nSize of keys: %d\n", sizeofEncKeys);
    PrintBytes("Send Enc Key: ", sendEncKey, sizeofEncKey);
    PrintBytes("Get Enc  Key: ", getEncKey, sizeofEncKey);
    PrintBytes("Send Int Key: ", sendIntKey, sizeofIntKey);
    PrintBytes("Get Int  Key: ", getIntKey, sizeofIntKey);
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
    byte        rguCBCMixer[BLKSIZE];       // FIX
    byte*       pNext= NULL;

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
    // Note: neither totalSize nor newMsg size include IV which is
    // sent once when the channel is opened by initChannel.
    // However, both include the size of the transmission header,
    // sizeof(packetHdr).
    totalSize= newMsgSize+hmacSize;
#ifdef TEST
    if(totalSize>MAXREQUESTSIZEWITHPAD) {
        fprintf(g_logFile, "Message too big\n");
        return PUTTOOBIGERROR;
    }
#endif

    // message header
    oHdr.packetType= type;
    oHdr.len= totalSize;
    oHdr.multipart= multipart;
    oHdr.finalpart= finalpart;
    oHdr.error= 0;
    memcpy(plainMessageBlock, (byte*)&oHdr, sizeof(packetHdr));
    memcpy(&plainMessageBlock[sizeof(packetHdr)], buf, len);

    pNext= &plainMessageBlock[newMsgSize-BLKSIZE];

    // pad final message block
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

    // If this is MACTHENENCRYPT.  The hmac is
    // computed over plaintext and is placed at end of message in 
    // plainMessageBlock[newMsgSize], increasing message
    // size by the size of the HMAC .
    // otherwise, we need to calculate it after encryption.
#ifdef MACTHENENCRYPT  // dont do this
    if(!hmac_sha256(plainMessageBlock, newMsgSize, sendIntKey, 
                    sizeofIntKey, &plainMessageBlock[newMsgSize])) {
        fprintf(g_logFile, "safesendPacket: bad compute mac error\n");
        return HMACCOMPERROR;
    }
#ifdef IOTEST
    fprintf(g_logFile, "MACTHENENCRYPT: %d bytes\n", newMsgSize);
    PrintBytes("Mac:", &plainMessageBlock[newMsgSize], SHA256_DIGESTSIZE_BYTES);
#endif
#endif

    // encrypt
    //      pLastCipher points to last encrypted block
    //      originally set to the IV in initChannel.
    //      pNextPlain points to next block to encrypt
    //      pNextCipher points to where we should copy
    //      the next cipher block.
    //      iLeft is the total size the portion of the
    //      message to be encrypted.  It included the
    //      HMAC if we ENCRYPTTHENMAC but does not
    //      otherwise.
#ifdef MACTHENENCRYPT
    iLeft= totalSize;
#else
    iLeft=  newMsgSize;
#endif
    while(iLeft>0) {
        memcpy(rguCBCMixer, pNextPlain, BLKSIZE);
        inlineXorto(rguCBCMixer, pLastCipher, BLKSIZE);
        sendAES.Encrypt(rguCBCMixer, pNextCipher);
        iLeft-= BLKSIZE;
        pLastCipher= pNextCipher;
        pNextPlain+= BLKSIZE;
        pNextCipher+= BLKSIZE;
    }
    // save last cipher block for next message
    memcpy(lastsendBlock, pLastCipher, BLKSIZE);

#ifndef MACTHENENCRYPT
    if(!hmac_sha256(encryptedMessageBlock, newMsgSize, sendIntKey, 
                    sizeofIntKey, &encryptedMessageBlock[newMsgSize])) {
        fprintf(g_logFile, "safesendPacket: bad compute mac error\n");
        return HMACCOMPERROR;
    }
#ifdef IOTEST
    fprintf(g_logFile, "ENCRYPTTHENMAC: %d bytes\n", newMsgSize);
    PrintBytes("Mac:", &plainMessageBlock[newMsgSize], SHA256_DIGESTSIZE_BYTES);
#endif
#endif

    int n= write(fd, encryptedMessageBlock, totalSize);
    if(n<0) {
        fprintf(g_logFile, "safesendPacket failure\n");
        return n;
    }
#ifdef IOTEST
    fprintf(g_logFile, "safesendPacket: bytes gotten %d, bytes sent %d \n", len, totalSize);
    PrintBytes((char*)"input: ", buf, len);
#ifndef MACTHENENCRYPT
    PrintBytes((char*)"ENCRYPTTHENMAC formatted: ", plainMessageBlock, newMsgSize);
    PrintBytes((char*)"ENCRYPTTHENMAC sent: ", encryptedMessageBlock, totalSize);
#else
    PrintBytes((char*)"MACTHENENCRYPT formatted: ", plainMessageBlock, totalSize);
    PrintBytes((char*)"MACTHENENCRYPT sent: ", encryptedMessageBlock, totalSize);
#endif
#endif
    return len;
}


// -------------------------------------------------------------------------------


int safeChannel::getFullPacket(byte* buf, int maxSize, int* ptype, 
                      byte* pmultipart, byte* pfinalpart)
//
//  Get a full message from channel
//      We only decrypt to message boundary.
//      Put excess preread cipher in prereadencryptedMessageBlock.
//      This routine does message authentication and returns only the
//      original sent message without header, padding or HMAC.
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

    packetHdr*  plainMessageBlockHeader = NULL;
    byte*       rguHmac= NULL;
    byte        rguHmacComputed[SHA256_DIGESTSIZE_BYTES];
    byte*       rguPad= NULL;

#ifdef IOTEST
    fprintf(g_logFile, "getFullPacket(%d, %d, %d, %d)\n", maxSize, 
            *ptype, *pmultipart, *pfinalpart);
    fprintf(g_logFile, "\tpre-fetched encrypted: %d\n", sizeprereadencrypted);
    PrintBytes((char*)"Encrypted: ", pNextCipher, sizeprereadencrypted);
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
            fprintf(g_logFile, "getFullPacket: channel empty\n");
            return 0;
        }
        if(sizeEncryptedBuf<0) {
            fprintf(g_logFile, "getFullPacket: channel read error\n");
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
#ifdef IOTEST
    PrintBytes((char*)"Last Encrypted: ", pLastCipher, BLKSIZE);
    PrintBytes((char*)"Cipher read: ", pNextCipher, BLKSIZE);
    PrintBytes((char*)"Plain read: ", pNextPlain, BLKSIZE);
    fflush(g_logFile);
#endif
    pLastCipher= pNextCipher;
    pNextPlain+= BLKSIZE;
    pNextCipher+= BLKSIZE;

    // Fix: If we get an error after this we're in trouble because
    // lastgetblock in no longer properly set.  We should copy the
    // last cipherblock in this message to lastgetBlock and clear the
    // buffer

    plainMessageBlockHeader = reinterpret_cast<packetHdr*>(plainMessageBlock);
    fullMsgSize= plainMessageBlockHeader->len;

#ifdef TEST
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

    // Does input buffer have less than an entire encrypted message in the buffer?
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

    // Does input buffer have more than an entire encrypted message?
    if(fullMsgSize<sizeEncryptedBuf) {
        n=  sizeEncryptedBuf-fullMsgSize;
#ifdef IOTEST
        fprintf(g_logFile, "getFullPacket: sizeEncryptedBuf bigger than message\n");
        fprintf(g_logFile, "fullMsgSize: %d, sizeEncryptedBuf: %d, storing: %d\n", 
                fullMsgSize, sizeEncryptedBuf, n);
        fflush(g_logFile);
#endif
        if(n>MAXREQUESTSIZEWITHPAD) {
            fprintf(g_logFile, "getFullPacket: message violates buffer size %d\n", n);
            return -1;
        }
        memcpy(prereadencryptedMessageBlock, &encryptedMessageBlock[fullMsgSize],n);
        sizeEncryptedBuf-= n;
        sizeprereadencrypted= n;
    }

    // Input buffer should contain a single encrypted message
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
    // Decrypt remaining message blocks
    //      pLastCipher points to last encrypted block
    //      originally set to the IV in initChannel.
    //      pNextPlain points to where to put next plain block
    //      pNextCipher points to where to get next cipher block
    //      iLeft is total number of message bytes remaining 
    //      to be decrypted.
#ifndef MACTHENENCRYPT
    iLeft= sizeEncryptedBuf-BLKSIZE-SHA256_DIGESTSIZE_BYTES;
#else
    iLeft= sizeEncryptedBuf-BLKSIZE;
#endif
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

#ifdef TEST
    fprintf(g_logFile, "getFullPacket: got last block, checking MAC\n");
    fflush(g_logFile);
#endif

    // compute HMAC
#ifndef MACTHENENCRYPT
    if(!hmac_sha256(encryptedMessageBlock, fullMsgSize-SHA256_DIGESTSIZE_BYTES, 
                    getIntKey, sizeofIntKey, rguHmacComputed)) {
        fprintf(g_logFile, "getFullPacket: HMAC Compute error 1\n");
        return HMACCOMPERROR;
    }
    rguHmac= &encryptedMessageBlock[fullMsgSize-SHA256_DIGESTSIZE_BYTES];
#else
    if(!hmac_sha256(plainMessageBlock, fullMsgSize-SHA256_DIGESTSIZE_BYTES, getIntKey, 
                    sizeofIntKey, rguHmacComputed)) {
        fprintf(g_logFile, "getFullPacket: HMAC Compute error 1\n");
        return HMACCOMPERROR;
    }
    rguHmac= &plainMessageBlock[fullMsgSize-SHA256_DIGESTSIZE_BYTES];
#endif

    // check MAC
    if(!isEqual(rguHmac, rguHmacComputed, SHA256_DIGESTSIZE_BYTES)) {
        fprintf(g_logFile, "getFullPacket: HMAC comparison error 2\n");
#ifdef TEST
        PrintBytes("sent Hmac\n", rguHmac, SHA256_DIGESTSIZE_BYTES);
        PrintBytes("computed Hmac\n", rguHmacComputed, SHA256_DIGESTSIZE_BYTES);
#endif
        return HMACMATCHERROR;
    }

    // depad
    rguPad= &plainMessageBlock[fullMsgSize-BLKSIZE-SHA256_DIGESTSIZE_BYTES];
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
    sizedecryptedMsg= fullMsgSize-SHA256_DIGESTSIZE_BYTES-padLen-sizeof(packetHdr);
    if(maxSize<sizedecryptedMsg)
        return -1;

#ifdef TEST
    fprintf(g_logFile, "getFullPacket: returned message has %d bytes\n", sizedecryptedMsg);
    //PrintBytes((char*)"plain: ", buf, sizedecryptedMsg);
    fflush(g_logFile);
#endif

    packetHdr* plainMessageBlockHdr = reinterpret_cast<packetHdr*>(plainMessageBlock);
    memcpy(buf, &plainMessageBlock[sizeof(packetHdr)], sizedecryptedMsg);
    *ptype= plainMessageBlockHdr->packetType;
    *pmultipart= plainMessageBlockHdr->multipart;
    *pfinalpart= plainMessageBlockHdr->finalpart;
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


