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

#include <stdio.h>
#include <time.h>
#include "string.h"
#include "sha1.h"
#include "logging.h"

byte b;
#define BUF_SIZE 1024

// ---------------------------------------------------------------------------------------


void bigEndian(u8* buf, int size) {
  u8* pU = buf;
  u8 t;

  while (size >= (int)sizeof(u32)) {
    t = pU[0];
    pU[0] = pU[3];
    pU[3] = t;
    t = pU[1];
    pU[1] = pU[2];
    pU[2] = t;
    size -= sizeof(u32);
    pU += sizeof(u32);
  }
}

void testvector(int sizetoHash, byte* toHash, int sizeAns, byte* answer) {
  Sha1 oSha;
  byte rgbDigest[64];

  printf("SHA1 Test, %d bytes\n", sizetoHash);
  PrintBytes("In     ", toHash, sizetoHash);
  PrintBytes("Answer ", answer, sizeAns);

  oSha.Init();
  oSha.Update(toHash, sizetoHash);
  oSha.Final();
  oSha.getDigest(rgbDigest);

  PrintBytes("Out    ", rgbDigest, sizeAns);
  if (memcmp(rgbDigest, answer, sizeAns) == 0) {
    printf("Test Passed\n\n");
  } else {
    printf("Test Failed\n\n");
  }
}

int main(int argc, char** argv) {
  // Test1
  const byte* toHash1 = (const byte*)"abc";
  int sizetoHash1 = strlen((const char*)toHash1);
  u32 answer1[5] = {0xA9993E36, 0x4706816A, 0xBA3E2571, 0x7850C26C, 0x9CD0D89D};
  initLog("shatest.log");
  bigEndian((byte*)answer1, 20);
  testvector(sizetoHash1, (byte*)toHash1, 20, (byte*)answer1);

  const byte* toHash2 =
      (const byte*)"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
  u32 answer2[5] = {0x84983E44, 0x1C3BD26E, 0xBAAE4AA1, 0xF95129E5, 0xE54670F1};
  bigEndian((byte*)answer2, 20);
  int sizetoHash2 = strlen((const char*)toHash2);
  testvector(sizetoHash2, (byte*)toHash2, 20, (byte*)answer2);

  return 0;
}

// ---------------------------------------------------------------------------------------
