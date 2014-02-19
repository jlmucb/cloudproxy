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
#include <ostream>
#include <iostream>
#include "common.h"
#include "logging.h"
using namespace std;

// ------------------------------------------------------------------------------


#ifndef GLOGENABLED
std::ostream *logFile= NULL;
#endif

bool initLog(const char* logfilename) {

#ifndef GLOGENABLED
  if (logfilename== NULL) {
    logFile= &cout;
    return true;
  }
  else
    logFile= new std::ofstream((char*)logfilename);
#endif
  return true;
}

void closeLog() {
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

void PrintBytesToConsole(const char* message, byte* pbData, int iSize, int col) {
  int i;
  printf("%s\n", message);
  for (i = 0; i < iSize; i++) {
    printf("%02x", pbData[i]);
    if ((i % col) == (col - 1)) {
      printf("\n");
    }
  }
  printf("\n");
}

// ------------------------------------------------------------------------------------
