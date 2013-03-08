//
//  File: encryptedblockIO.cpp, encrypted IO
//
//  Copyright (c) 2012, John Manferdelli.  All rights reserved.
//      Some contributions (c) Intel Corporation
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


#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include "jlmTypes.h"
#include "logging.h"
#include "jlmcrypto.h"
#include "sha256.h"
#include "algs.h"
#include "encryptedblockIO.h"


// ------------------------------------------------------------------------------------


encryptedFileread::encryptedFileread()
{
    m_fFirstBlockRead= false;
    m_fInitialized= false;
    m_iBlockSize= 0;
    m_iBufIn= 0;
    m_iBufOut= 0;
    m_fileLeft= 0;
    m_fileSize= 0;
    m_dataSize= 0;
}

encryptedFileread::~encryptedFileread()
{
}


encryptedFilewrite::encryptedFilewrite() 
{
    m_fFirstBlockWritten= false;
    m_fInitialized= false;
    m_iBlockSize= 0;
    m_iBufIn= 0;
    m_iBufOut= 0;
    m_fileLeft= 0;
    m_fileSize= 0;
    m_dataSize= 0;
}


encryptedFilewrite::~encryptedFilewrite()
{
}


bool encryptedFileread::initDec(int filesize, int datasize, byte* key, int keyBitSize, 
                                u32 alg, u32 pad, u32 mode, u32 hmac)
{

#ifdef IOTEST
    fprintf(g_logFile, "initDec filesize: %d, datasize: %d\n", filesize, datasize);
#endif
    m_uAlg= alg;
    m_uMode= mode;
    m_uPad= pad;
    m_uHmac= hmac;
    if(alg==NOALG) {
        m_fInitialized= true;
        return true;
    }

    m_iBlockSize= AES128BYTEBLOCKSIZE;
    m_iBufIn= 0;
    m_iBufOut= 0;
    m_uCombinedAlgId= alg | (mode<<8) | (pad<<16) | (hmac<<24);

    m_fileLeft= filesize;
    m_fileSize= filesize;
    m_dataSize= datasize;
    m_fFinalProcessed= false;

    switch(m_uCombinedAlgId) {
      case AES128CBCSYMPADHMACSHA256:
        if(!m_oCBC.initDec(AES128, SYMPAD, HMACSHA256, AES128BYTEKEYSIZE,
                           key, AES128BYTEKEYSIZE, &key[AES128BYTEKEYSIZE], filesize))
            return false;
        break;
      case AES128GCM:
        if(!m_oGCM.initDec(AES128, AES128BYTEKEYSIZE,
                           key, filesize, 0, AES128BYTEKEYSIZE))
            return false;
        break;
      default:
        return -1;
    }

    m_fInitialized= true;
    return true;
}


// ---------------------------------------------------------------------------------


bool encryptedFileread::AES128CBCDecryptBlocks(int iRead) 
{
    int     k, m, n;

#ifdef IOTEST
    fprintf(g_logFile, "AES128CBCDecryptBlocks, fileLeft: %d, m_iBufOut: %d\n",
            m_fileLeft, m_iBufOut);
#endif
    if(m_iBufOut!=0)
        return false;
    if(m_fileLeft==0) {
        m_fFinalProcessed= true;
        return true;
    }

    m_iBufIn= read(iRead, m_rguBufIn, BLOCKBUFSIZE);
    if(m_iBufIn<0)
        return false;

    m_fileLeft-= m_iBufIn;
    if(m_fileLeft<=(3*m_iBlockSize)) {
        m_fFinalProcessed= true;
        if(m_fileLeft>0)
            n= read(iRead, &m_rguBufIn[m_iBufIn], m_fileLeft);
        else
            n= 0;

        if(n<0)
            return false;
        m_fileLeft= 0;
        m_iBufIn+= n;
    }

    byte*   puIn= m_rguBufIn;
    byte*   puOut= m_rguBufOut;

    m= m_iBufIn;
    if(m_fFinalProcessed)
        k= m_iBlockSize+SHA256DIGESTBYTESIZE;
    else
        k= 0;
    m_iBufOut= 0;
    m_iOutStart= 0;

    // decrypt, and copy bytes
    while(m>k) {
        m_oCBC.nextCipherBlockIn(puIn, puOut);
        m-= m_iBlockSize;
        puIn+= m_iBlockSize;
        puOut+= m_iBlockSize;
        m_iBufOut+= m_iBlockSize;
    }
    if(!m_fFinalProcessed)
        return true;

    // process final blocks
    n= m_oCBC.lastCipherBlockIn(m, puIn, puOut);
    if(n>0)
        m_iBufOut+= n;

    return true;
}


int encryptedFileread::AES128CBCDecrypt(int iRead, int bufsize, byte* buf)
{
    int     m= 0;       // bytes read from file
    int     k= 0;       

#ifdef IOTEST
    fprintf(g_logFile, "AES128CBCDecrypt, bufsize: %d, m_fileLeft: %d\n", 
            bufsize, m_fileLeft);
#endif
    // get IV block
    if(!m_fFirstBlockRead) {
        m= read(iRead, m_rguBufIn, m_iBlockSize);
        if(m<m_iBlockSize)
            return -1;
        m_oCBC.firstCipherBlockIn(m_rguBufIn);
        m_fileLeft-= m_iBlockSize;
        m_fFirstBlockRead= true;
    }

    if(m_iBufOut==0) {
        if(m_fileLeft>0) {
            if(!AES128CBCDecryptBlocks(iRead))
                return -1;
        }
        if(m_iBufOut==0) 
            return 0;
    }
   
    if(m_iBufOut<bufsize) {
        m= m_iBufOut;
        memcpy(buf, &m_rguBufOut[m_iOutStart], m);
        m_iBufOut= 0;
        m_iOutStart= 0;
        bufsize-= m;
        buf+= m;
        k= AES128CBCDecrypt(iRead, bufsize, buf);
        if(k<0) {
            fprintf(g_logFile, "Second AES128CBCDecrypt failed\n");
            return k;
        }
        return m+k;
    }
    m= bufsize;
    memcpy(buf, &m_rguBufOut[m_iOutStart], m);
    m_iBufOut-= m;
    m_iOutStart+= m;
    return m;
}


bool  encryptedFilewrite::AES128CBCEncryptBlocks(int iWrite)
{
    byte*   puIn= m_rguBufIn;
    byte*   puOut= m_rguBufOut;
    int     k= m_iBufIn;
    int     n= 0;

#ifdef IOTEST
    fprintf(g_logFile, "AES128CBCEncryptBlocks, bufin: %d, fileLeft: %d\n", k, m_fileLeft);
    fflush(g_logFile);
#endif
    // get, encrypt, and write bytes
    while(k>m_iBlockSize) {
        m_oCBC.nextPlainBlockIn(puIn, puOut);
        puIn+= m_iBlockSize;
        puOut+= m_iBlockSize;
        k-= m_iBlockSize;
    }

    // last block?
    ssize_t result;
    if((m_fileLeft-m_iBufIn)==0) {
        n= m_oCBC.lastPlainBlockIn(k, puIn, puOut);
        result = write(iWrite, m_rguBufOut, m_iBufIn-k+n);
	UNUSEDVAR(result);
        m_fileLeft-= m_iBufIn;
        m_iBufIn= 0;
        m_fFinalProcessed= true;
        return true;
    }

    if(k==m_iBlockSize) {
        m_oCBC.nextPlainBlockIn(puIn, puOut);
        result = write(iWrite, m_rguBufOut, m_iBufIn);
	UNUSEDVAR(result);
        m_fileLeft-= m_iBufIn;
        m_iBufIn= 0;
        return true;
    }
    return false;
}


int encryptedFilewrite::AES128CBCEncrypt(int iWrite, int bufsize, byte* buf)
{
    int     t= 0;       // total (unencrypted) bytes written
    int     k;

#ifdef IOTEST
    fprintf(g_logFile, "AES128CBCEncrypt, bufsize: %d, fileLeft: %d\n", 
            bufsize, m_fileLeft);
    fflush(g_logFile);
#endif
    // first block?
    if(!m_fFirstBlockWritten) {
        m_oCBC.firstCipherBlockOut(m_rguBufOut);
        ssize_t result = write(iWrite, m_rguBufOut, m_iBlockSize);
	UNUSEDVAR(result);
        m_fFirstBlockWritten= true;
    }

    // call AES128CBCEncryptBlocks
    while(bufsize>0) {
        k= BLOCKBUFSIZE-m_iBufIn;
        if(k>bufsize)
            k= bufsize;
        memcpy(&m_rguBufIn[m_iBufIn], buf, k);
        m_iBufIn+= k;
        if(m_iBufIn==BLOCKBUFSIZE || m_fileLeft<=m_iBufIn) {
            if(!AES128CBCEncryptBlocks(iWrite))
                return -1;
        }
        t+= k;
        bufsize-= k;
        buf+= k;
    }

    return t;
}


//----------------------------------------------------------------------------------


// untested


bool encryptedFilewrite::AES128GCMEncryptBlocks(int iWrite)
{
    byte*   puIn= m_rguBufIn;
    byte*   puOut= m_rguBufOut;
    int     k= m_iBufIn;

    // get, encrypt, and write bytes
    while(k>m_iBlockSize) {
        m_oGCM.nextPlainBlockIn(puIn, puOut);
        puIn+= m_iBlockSize;
        puOut+= m_iBlockSize;
        k-= m_iBlockSize;
    }

#ifdef IOTEST1
    fprintf(g_logFile, "AES128GCMEncryptBlocks, fileLeft: %d\n", m_fileLeft);
#endif
    ssize_t result;
    if(m_fileLeft>0) {
        m_oGCM.nextPlainBlockIn(puIn, puOut);
        result = write(iWrite, m_rguBufOut, m_iBufIn);
	UNUSEDVAR(result);
        m_iBufIn= 0;
        return true;
    }

    int n= m_oGCM.lastPlainBlockIn(k, puIn, puOut);
    result = write(iWrite, m_rguBufOut, m_iBufIn-k+n);
    UNUSEDVAR(result);
    m_iBufIn= 0;
    m_fFinalProcessed= true;

    return true;
}


bool encryptedFileread::AES128GCMDecryptBlocks(int iRead)
{
    int     n= 0;
    int     m= 0;
    int     k= 0;

#ifdef IOTEST1
    fprintf(g_logFile, "AES128GCMDecryptBlocks, fileLeft: %d\n", m_fileLeft);
#endif
    if(m_iBufOut!=0)
        return false;
    if(m_fileLeft==0) {
        m_fFinalProcessed= true;
        return true;
    }

    int m_iBufIn= read(iRead, m_rguBufIn, BLOCKBUFSIZE);
    if(m_iBufIn<0)
        return false;

    m_fileLeft-= m_iBufIn;
    if(m_fileLeft<=(2*m_iBlockSize)) {
        m_fFinalProcessed= true;
        if(m_fileLeft>0)
            n= read(iRead, &m_rguBufIn[m_iBufIn], m_fileLeft);
        else
            n= 0;
        if(n<0)
            return false;
        m_fileLeft= 0;
        m_iBufIn+= n;
    }

    byte*   puIn= m_rguBufIn;
    byte*   puOut= m_rguBufOut;

    m= m_iBufIn;
    if(m_fFinalProcessed)
        k= 2*m_iBlockSize;
    else
        k= 0;
    m_iBufOut= 0;
    m_iOutStart= 0;

    // decrypt, and copy bytes
    while(m>k) {
        m_oGCM.nextCipherBlockIn(puIn, puOut);
        m-= m_iBlockSize;
        puIn+= m_iBlockSize;
        puOut+= m_iBlockSize;
        m_iBufOut+= m_iBlockSize;
    }

    // Not at end
    if(!m_fFinalProcessed)
        return true;

    // process final blocks
    n= m_oGCM.lastCipherBlockIn(m, puIn, puOut);
    m_iBufOut+= n;

    return true;
}


int encryptedFilewrite::AES128GCMEncrypt(int iWrite, int bufsize, byte* buf)
{
    int     k= 0;

    // first block?
    if(!m_fFirstBlockWritten) {
        // get and send first cipher block
        m_oGCM.firstCipherBlockOut(m_rguBufOut);
        ssize_t result = write(iWrite, m_rguBufOut, m_iBlockSize);
	UNUSEDVAR(result);
        m_fFirstBlockWritten= true;
    }

   if(m_iBufIn>BLOCKBUFSIZE) {
        if(!AES128GCMEncryptBlocks(iWrite))
            return -1;
    }
    if(m_iBufIn>=BLOCKBUFSIZE)
        return -1;

    if((m_iBufIn+bufsize)<BLOCKBUFSIZE) {
        memcpy(&m_rguBufIn[m_iBufIn], buf, bufsize);
        m_iBufIn+= bufsize;
        m_fileLeft-= bufsize;
        if(m_fileLeft==0) {
            AES128GCMEncryptBlocks(iWrite);
        }
        return bufsize;
    }

    k= BLOCKBUFSIZE-m_iBufIn;
    memcpy(m_rguBufIn, buf, k);
    m_iBufIn+= k;
    buf+= k;
    bufsize-= k;
    m_fileLeft-= k;
    return k+AES128GCMEncrypt(iWrite, bufsize, buf);

    // write tag
    m_oGCM.getTag(m_iBlockSize, m_rguBufOut);
    ssize_t result = write(iWrite, m_rguBufOut, m_iBlockSize);
    UNUSEDVAR(result);

    return bufsize;
}


int encryptedFileread::AES128GCMDecrypt(int iRead, int bufsize, byte* buf)
{
    int     m= 0;       // bytes read from file

#ifdef IOTEST1
    fprintf(g_logFile, "AES128GCMDecrypt(%d)\n", bufsize);
#endif
    // get and send first cipher block
    if(!m_fFirstBlockRead) {
        ssize_t result = read(iRead, m_rguBufIn, m_iBlockSize);
	UNUSEDVAR(result);
        m_oGCM.firstCipherBlockIn(m_rguBufIn);
        m_fileLeft-= m_iBlockSize;
        m_fFirstBlockRead= true;
    }

    if(m_iBufOut==0) {
        if(!AES128GCMDecryptBlocks(iRead) )
            return -1;
        if(m_iBufOut==0)
            return 0;
    }

    if(m_iBufOut<bufsize) {
        m= m_iBufOut;
        memcpy(buf, &m_rguBufOut[m_iOutStart], m);
        m_iBufOut= 0;
        bufsize-= m;
        buf+= m;
        return m+AES128GCMDecrypt(iRead, bufsize, buf);
    }
    m= bufsize;
    memcpy(buf, &m_rguBufOut[m_iOutStart], m);
    m_iBufOut-= m;
    m_iOutStart+= m;
    return m;
}


// ------------------------------------------------------------------------


int  encryptedFileread::EncRead(int iRead, byte* buf, int size)
{
#ifdef TEST1
    fprintf(g_logFile, "EncRead size: %d\n", size);
#endif
    if(!m_fInitialized)
        return -1;

    if(m_uAlg==NOALG)
        return read(iRead, buf, size);

    switch(m_uCombinedAlgId) {
      case AES128CBCSYMPADHMACSHA256:
        return AES128CBCDecrypt(iRead, size, buf);
      case AES128GCM:
        return AES128GCMDecrypt(iRead, size, buf);
      default:
        return -1;
    }
}


int  encryptedFilewrite::EncWrite(int iWrite, byte* buf, int size)
{
#ifdef IOTEST
    fprintf(g_logFile, "EncWrite size: %d\n", size);
    fflush(g_logFile);
#endif
    if(!m_fInitialized)
        return -1;

    if(m_uAlg==NOALG)
        return write(iWrite, buf, size);

    switch(m_uCombinedAlgId) {
      case AES128CBCSYMPADHMACSHA256:
        return AES128CBCEncrypt(iWrite, size, buf);
      case AES128GCM:
        return AES128GCMEncrypt(iWrite, size, buf);
      default:
        return -1;
    }
}


bool encryptedFilewrite::initEnc(int filesize, int datasize, byte* key, int keyBitSize, 
                                 u32 alg, u32 pad, u32 mode, u32 hmac)
{
#ifdef TEST1
    fprintf(g_logFile, "initEnc filesize: %d, datasize: %d\n", filesize, datasize);
    fflush(g_logFile);
#endif
    m_uAlg= alg;
    m_uMode= mode;
    m_uPad= pad;
    m_uHmac= hmac;
    if(alg==NOALG) {
        m_fInitialized= true;
        return true;
    }

    m_iBlockSize= AES128BYTEBLOCKSIZE;
    m_iBufIn= 0;
    m_iBufOut= 0;
    m_uCombinedAlgId= alg | (mode<<8) | (pad<<16) | (hmac<<24);

    m_fileLeft= filesize;
    m_fileSize= filesize;
    m_dataSize= datasize;

    byte    iv[AES128BYTEBLOCKSIZE];

    switch(m_uCombinedAlgId) {

      case AES128CBCSYMPADHMACSHA256:

        // init iv
        if(!getCryptoRandom(AES128BYTEBLOCKSIZE*NBITSINBYTE, iv)) {
            fprintf(g_logFile, "Cant generate iv\n");
            return false;
        }

        // init 
        if(!m_oCBC.initEnc(AES128, SYMPAD, HMACSHA256, AES128BYTEKEYSIZE, 
                           key, AES128BYTEKEYSIZE, 
                           &key[AES128BYTEKEYSIZE], filesize, AES128BYTEBLOCKSIZE, iv))
            return false;
        break;

      case AES128GCM:

        // init iv
        if(!getCryptoRandom(AES128BYTEBLOCKSIZE*NBITSINBYTE, iv)) {
            fprintf(g_logFile, "Cant generate iv\n");
            return false;
        }

        // init 
        if(!m_oGCM.initEnc(AES128, AES128BYTEKEYSIZE-sizeof(u32), iv, AES128BYTEKEYSIZE,
                            key, datasize, 0, AES128BYTEBLOCKSIZE))
            return false;
        break;

      default:
        return -1;
    }

    m_fInitialized= true;

    return true;
}


// ------------------------------------------------------------------------------------

