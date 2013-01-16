//
//  logging.cpp
//      John Manferdelli
//
//  Description: PrintBytes
//
//  Copyright (c) 2011, Intel Corporation. All rights reserved.
//  Some contributions (c) John Manferdelli.  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without 
//  modification, are permitted provided that the following conditions 
//  are met:
//    Redistributions of source code must retain the above copyright notice,
//      this list of conditions and the disclaimer below.
//    Redistributions in binary form must reproduce the above copyright
//      notice, this list of conditions and the disclaimer below in the 
//      documentation and/or other materials provided with the distribution.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
//  "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
//  TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
//  PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
//  HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
//  SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
//  TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
//  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
//  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
//  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
//  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
//


#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <pthread.h>
#include <errno.h>

#include "jlmTypes.h"


// ------------------------------------------------------------------------------


FILE*   g_logFile= stdout;


#ifdef __FLUSHIO__

int         g_ithread= -1;
pthread_t   g_flushIOthread;


void*  flushIO(void* ptr)
{
    fprintf(g_logFile, "flush thread running\n");
    for(;;) {
        sleep(5);
        fflush(g_logFile);
    }
}
#endif


bool initLog(char* szLogFile)
{

    if(szLogFile==NULL) {
        g_logFile= stdout;
        return true;
    }

    g_logFile= fopen(szLogFile, "w+");
    if(g_logFile==NULL)
        return false;

#ifdef __FLUSHIO__
    memset(&g_flushIOthread, 0, sizeof(pthread_t));
    g_ithread= pthread_create(&g_flushIOthread, NULL, flushIO, NULL);
    if(g_ithread!=0) {
        fprintf(g_logFile, "initLog: Cant create flush thread\n");
        fprintf(g_logFile, "errno: %d\n", errno);
    }
#endif
    return true;
}


void closeLog()
{
    if(g_logFile!=stdout) {
        fclose(g_logFile);
        g_logFile= NULL;
    }
}


void PrintBytes(char* szMsg, byte* pbData, int iSize, int col)
{
    int i;

    fprintf(g_logFile, "%s", szMsg);
    for (i= 0; i<iSize; i++) {
        fprintf(g_logFile, "%02x", pbData[i]);
        if((i%col)==(col-1))
            fprintf(g_logFile, "\n");
        }
    fprintf(g_logFile, "\n");
}


// ------------------------------------------------------------------------------------


