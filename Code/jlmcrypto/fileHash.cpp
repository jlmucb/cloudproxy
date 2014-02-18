//
//  File: fileHash.cpp
//  Description: getfilehash implementation
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


#include "common.h"
#include "logging.h"
#include "algs.h"
#include "sha256.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>


// ------------------------------------------------------------------------------


#define HASHINBUFSIZE 1024


bool hashfilefromdescriptor(int fd, Sha256& oHash)
{
    int     n;
    byte    rgBuf[HASHINBUFSIZE];

    for(;;) {
        n= read(fd, rgBuf, HASHINBUFSIZE);
        if(n<=0)
            break;
        oHash.Update(rgBuf, n);
        if(n<HASHINBUFSIZE)
            break;
    }
    return true;
}


bool getcombinedfileHash(int numfiles, const char** fileNames, u32* phashType, 
                         int* psize, byte* rgHash)
{
    int     i;
    Sha256  oHash;
    int     fd;

    if(*psize<SHA256DIGESTBYTESIZE) {
        fprintf(g_logFile, "getcombinedfileHash: hash buffer too small %d\n", *psize);
        return false;
    }
    oHash.Init();

    for(i=0; i<numfiles;i++) {
        if(fileNames[i]==NULL)
            return false;
        fd= open(fileNames[i], O_RDONLY);
        if(fd<0) {
            fprintf(g_logFile, "getcombinedfileHash: cant open %s\n", fileNames[i]);
            return false;
        }
        hashfilefromdescriptor(fd, oHash);
        close(fd);
    }

    oHash.Final();
    oHash.GetDigest(rgHash);
    *phashType= SHA256HASH;
    *psize= SHA256DIGESTBYTESIZE;

    return true;
}


bool getfileHash(const char* szFile, u32* phashType, int* psize, byte* rgHash)
{
    Sha256  oHash;
    int     iFile= -1;

    if(szFile==NULL)
        return false;
    iFile= open(szFile, O_RDONLY);
    if(iFile<0) {
        fprintf(g_logFile, "getfileHash: cant open %s\n", szFile);
        return false;
    }

    if(*psize<SHA256DIGESTBYTESIZE) {
        fprintf(g_logFile, "getfileHash: hash buffer too small %d\n", *psize);
        return false;
    }

    oHash.Init();
    hashfilefromdescriptor(iFile, oHash);
    oHash.Final();

    oHash.GetDigest(rgHash);
    *phashType= SHA256HASH;
    *psize= SHA256DIGESTBYTESIZE;
    close(iFile);
    return true;
}


// ------------------------------------------------------------------------------


