//
//  File: logging.cpp
//  Description: PrintBytes, initLog, closeLog, flushIO
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
#include "common.h"
#include "logging.h"

// ------------------------------------------------------------------------------

extern FILE* g_logFile;

#ifndef GLOGENABLED
std::ostream *logFile= NULL;
#endif


// ------------------------------------------------------------------------------

FILE* g_logFile = stdout;

#ifdef __FLUSHIO__

int g_ithread = -1;
pthread_t g_flushIOthread;

void* flushIO(void* ptr) {
  for (;;) {
    sleep(5);
    fflush(g_logFile);
  }

  // unreachable, but eliminates a useless warning
  return NULL;
}
#endif

bool initLog(const char* szLogFile) {

#ifndef GLOGENABLED
  logFile= new std::ofstream((char*)"/tmp/logfile");
#endif

  if (szLogFile == NULL) {
    g_logFile = stdout;
    return true;
  }

  g_logFile = fopen(szLogFile, "w+");
  if (g_logFile == NULL) return false;

#ifdef __FLUSHIO__
  memset(&g_flushIOthread, 0, sizeof(pthread_t));
  g_ithread = pthread_create(&g_flushIOthread, NULL, flushIO, NULL);
  if (g_ithread != 0) {
    LOG(ERROR)<<"initLog: Cant create flush thread\n";
    LOG(ERROR)<<"errno: "<< errno <<"\n";
  }
#endif
  return true;
}

void closeLog() {
  if (g_logFile != stdout) {
    fclose(g_logFile);
    g_logFile = NULL;
  }
}

#define MAXBYTESTRING 2048
void PrintBytes(const char* message, byte* pbData, int iSize, int col) {
  int i;
  int n;
  char byte_string[MAXBYTESTRING];

  LOG(INFO)<<message<<"\n";
  byte_string[0]= 0;
  for (i = 0; i < iSize; i++) {
    n= strlen(byte_string);
    sprintf(&byte_string[n], "%02x", pbData[i]);
    if ((i % col) == (col - 1)) {
      n= strlen(byte_string);
      sprintf(&byte_string[n], "\n");
    }
  }
  n= strlen(byte_string);
  sprintf(&byte_string[n], "\n");
  LOG(INFO)<<byte_string;
}

// ------------------------------------------------------------------------------------
