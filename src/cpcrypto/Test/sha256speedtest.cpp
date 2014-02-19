//
//  File: sha256speedtest.cpp
//  Description: sha256speedtest
//
//  Copyright (c) John Manferdelli.  All rights reserved.
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
#include "sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <time.h>

#define BLOCKSIZE 1024

// ---------------------------------------------------------------------

bool sha256speed(int numBlocks, int blockSize) {
  byte buf[BLOCKSIZE];
  time_t start, finish;
  double bytespersecond = 0.0;
  double elapsedseconds;
  int totalbytes = numBlocks * blockSize;
  int i;
  Sha256 oHash;

  for (i = 0; i < blockSize; i++) buf[i] = (byte)i;

  oHash.Init();
  time(&start);
  for (i = 0; i < numBlocks; i++) {
    oHash.Update((const byte*)buf, blockSize);
  }
  oHash.Final();
  time(&finish);
  elapsedseconds = difftime(finish, start);
  bytespersecond = ((double)totalbytes) / elapsedseconds;
  printf(
      "%10.4lf seconds, %8d bytes, blocksize: %d, %10.4lf bytes per second\n",
      elapsedseconds, totalbytes, blockSize, bytespersecond);
  return true;
}

// ---------------------------------------------------------------------

int main(int an, char** av) {
  int numBlocks = 1024;

  for (int i = 0; i < an; i++) {
    if (strcmp(av[i], "-help") == 0) {
      printf("\nUsage: sha256speedtest -Blocks blocks\n");
      return 0;
    }
    if (strcmp(av[i], "-Blocks") == 0) {
      if (an > (i + 1)) {
        numBlocks = atoi(av[++i]);
      }
    }
  }

  if (sha256speed(numBlocks, BLOCKSIZE))
    printf("\nTest completed susessfully\n");
  else
    printf("\nTest did NOT completed susessfully\n");

  return 0;
}

// -------------------------------------------------------------------------
