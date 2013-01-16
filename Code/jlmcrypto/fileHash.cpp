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


#include "jlmTypes.h"
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


bool getfileHash(char* szFile, u32* phashType, int* psize, byte* rgHash)
{
    Sha256  oHash;
    byte    rgBuf[HASHINBUFSIZE];
    int     iFile= -1;
    int     n;

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
    for(;;) {
        n= read(iFile, rgBuf, HASHINBUFSIZE);
        if(n<=0)
            break;
        oHash.Update(rgBuf, n);
        if(n<HASHINBUFSIZE)
            break;
    }
    oHash.Final();

    oHash.GetDigest(rgHash);
    *phashType= SHA256HASH;
    *psize= SHA256DIGESTBYTESIZE;
    close(iFile);
    return true;
}


// ------------------------------------------------------------------------------


