//
//  File: aestest.cpp
//
//  Description: aes sanity check
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
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "jlmTypes.h"
#include "aes.h"
#include "algs.h"
#include "logging.h"
#include "modesandpadding.h"


// ----------------------------------------------------------------------------


// ECB
byte aes128EncTestKey1[16]= {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};
byte aes128EncTestPlain1[16]=  {
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 
    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF
};
byte aes128EncTestCipher1[16]=  {
    0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30, 
    0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A
};


byte aes128EncTestKey2[16]= {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
byte aes128EncTestPlain2a[16]=  {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};
byte aes128EncTestCipher2a[16]=  {
    0x3a, 0xd7, 0x7b, 0xb4, 0x0d, 0x7a, 0x36, 0x60, 
    0xa8, 0x9e, 0xca, 0xf3, 0x24, 0x66, 0xef, 0x97
};
byte aes128EncTestPlain2b[16]=  {
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
};
byte aes128EncTestCipher2b[16]=  {
    0xf5, 0xd3, 0xd5, 0x85, 0x03, 0xb9, 0x69, 0x9d, 
    0xe7, 0x85, 0x89, 0x5a, 0x96, 0xfd, 0xba, 0xaf
};
byte aes128EncTestPlain2c[16]=  {
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef
};
byte aes128EncTestCipher2c[16]=  {
    0x43, 0xb1, 0xcd, 0x7f, 0x59, 0x8e, 0xce, 0x23, 
    0x88, 0x1b, 0x00, 0xe3, 0xed, 0x03, 0x06, 0x88
};
byte aes128EncTestPlain2d[16]=  {
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};
byte aes128EncTestCipher2d[16]=  {
    0x7b, 0x0c, 0x78, 0x5e, 0x27, 0xe8, 0xad, 0x3f, 
    0x82, 0x23, 0x20, 0x71, 0x04, 0x72, 0x5d, 0xd4
};


byte aes256EncTestKey1[32]= {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};
byte aes256EncTestPlain1a[16]=  {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};
byte aes256EncTestCipher1a[16]=  {
    0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c, 
    0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8
};
byte aes256EncTestPlain1b[16]=  {
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
};
byte aes256EncTestCipher1b[16]=  {
    0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26, 
    0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70
};
byte aes256EncTestPlain1c[16]=  {
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef
};
byte aes256EncTestCipher1c[16]=  {
    0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9, 
    0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d
};
byte aes256EncTestPlain1d[16]=  {
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};
byte aes256EncTestCipher1d[16]=  {
    0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff, 
    0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7
};


// CBC
byte aes128CBCTestKey1[16]= {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};
byte aes128CBCTestIV1[16]= {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
byte aes128CBCTestPlain1a[16]=  {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};
byte aes128CBCTestCipher1a[16]=  {
    0x76, 0x49, 0xab, 0xac, 0x81, 0x19, 0xb2, 0x46, 
    0xce, 0xe9, 0x8e, 0x9b, 0x12, 0xe9, 0x19, 0x7d
};
byte aes128CBCTestPlain1b[16]=  {
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
};
byte aes128CBCTestCipher1b[16]=  {
    0x50, 0x86, 0xcb, 0x9b, 0x50, 0x72, 0x19, 0xee, 
    0x95, 0xdb, 0x11, 0x3a, 0x91, 0x76, 0x78, 0xb2
};
byte aes128CBCTestPlain1c[16]=  {
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef
};
byte aes128CBCTestCipher1c[16]=  {
    0x73, 0xbe, 0xd6, 0xb8, 0xe3, 0xc1, 0x74, 0x3b, 
    0x71, 0x16, 0xe6, 0x9e, 0x22, 0x22, 0x95, 0x16
};
byte aes128CBCTestPlain1d[16]=  {
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};
byte aes128CBCTestCipher1d[16]=  {
    0x3f, 0xf1, 0xca, 0xa1, 0x68, 0x1f, 0xac, 0x09, 
    0x12, 0x0e, 0xca, 0x30, 0x75, 0x86, 0xe1, 0xa7
};


byte aes256CBCTestKey1[32]= {
    0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe, 
    0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
    0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7, 
    0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4
};
byte aes256CBCTestIV1[16]= {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};
byte aes256CBCTestPlain1a[16]=  {
    0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 
    0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
};
byte aes256CBCTestCipher1a[16]=  {
    0xf5, 0x8c, 0x4c, 0x04, 0xd6, 0xe5, 0xf1, 0xba, 
    0x77, 0x9e, 0xab, 0xfb, 0x5f, 0x7b, 0xfb, 0xd6
};
byte aes256CBCTestPlain1b[16]=  {
    0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 
    0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51
};
byte aes256CBCTestCipher1b[16]=  {
    0x9c, 0xfc, 0x4e, 0x96, 0x7e, 0xdb, 0x80, 0x8d, 
    0x67, 0x9f, 0x77, 0x7b, 0xc6, 0x70, 0x2c, 0x7d
};
byte aes256CBCTestPlain1c[16]=  {
    0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 
    0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef
};
byte aes256CBCTestCipher1c[16]=  {
    0x39, 0xf2, 0x33, 0x69, 0xa9, 0xd9, 0xba, 0xcf, 
    0xa5, 0x30, 0xe2, 0x63, 0x04, 0x23, 0x14, 0x61
};
byte aes256CBCTestPlain1d[16]=  {
    0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 
    0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10
};
byte aes256CBCTestCipher1d[16]=  {
    0xb2, 0xeb, 0x05, 0xe2, 0xc3, 0x9b, 0xe9, 0xfc, 
    0xda, 0x6c, 0x19, 0x07, 0x8c, 0x6a, 0x9d, 0x1b
};


byte aes128SanityPlain[64] ={
   0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
   0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
   0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
   0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00,
   0xff, 0xfe, 0xfd, 0xfc, 0xfb, 0xfa, 0xf9, 0xf8,
   0xf7, 0xf6, 0xf5, 0xf4, 0xf3, 0xf2, 0xf1, 0xf0,
   0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08,
   0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
};


// ----------------------------------------------------------------------------



int main(int an, char** av) 
{
    aes     oAesEnc;
    aes     oAesDec;
    byte    pt[16], ct[16], npt[16];
    bool    fAllTest= true;

    // init logging
    initLog(NULL);

    // Test 1
    PrintBytes("aes128 key: ", (byte*)aes128EncTestKey1, 16);
    oAesEnc.KeySetupEnc((byte*)aes128EncTestKey1, 128);
    oAesDec.KeySetupDec((byte*)aes128EncTestKey1, 128);
    memcpy(pt, aes128EncTestPlain1, 16);
    oAesEnc.Encrypt(pt, ct);
    oAesDec.Decrypt(ct, npt);

    PrintBytes("aes128 PT : ", (byte*)pt, 16);
    PrintBytes("aes128 CT : ", (byte*)ct, 16);
    PrintBytes("aes128 PT : ", (byte*)npt, 16);

    if(memcmp(ct, aes128EncTestCipher1, 16)==0 && memcmp(npt, aes128EncTestPlain1, 16)==0) {
        fprintf(g_logFile, "Test 1 Passed\n");
    }
    else {
        fprintf(g_logFile, "Test 1 Failed\n");
        fAllTest= false;
    }
    fprintf(g_logFile, "\n");

    
    // Test 2
    PrintBytes("aes128 key: ", (byte*)aes128EncTestKey2, 16);
    oAesEnc.KeySetupEnc((byte*)aes128EncTestKey2, 128);
    oAesDec.KeySetupDec((byte*)aes128EncTestKey2, 128);

    memcpy(pt, aes128EncTestPlain2a, 16);
    oAesEnc.Encrypt(pt, ct);
    oAesDec.Decrypt(ct, npt);
    PrintBytes("aes128 PT : ", (byte*)pt, 16);
    PrintBytes("aes128 CT : ", (byte*)ct, 16);
    PrintBytes("aes128 PT : ", (byte*)npt, 16);
    if(memcmp(ct, aes128EncTestCipher2a, 16)==0 && 
       memcmp(npt, aes128EncTestPlain2a, 16)==0) {
        fprintf(g_logFile, "Test 2a Passed\n");
    }
    else {
        fprintf(g_logFile, "Test 2a Failed\n");
        fAllTest= false;
    }
    fprintf(g_logFile, "\n");

    memcpy(pt, aes128EncTestPlain2b, 16);
    oAesEnc.Encrypt(pt, ct);
    oAesDec.Decrypt(ct, npt);
    PrintBytes("aes128 PT : ", (byte*)pt, 16);
    PrintBytes("aes128 CT : ", (byte*)ct, 16);
    PrintBytes("aes128 PT : ", (byte*)npt, 16);
    if(memcmp(ct, aes128EncTestCipher2b, 16)==0 && 
       memcmp(npt, aes128EncTestPlain2b, 16)==0) {
        fprintf(g_logFile, "Test 2b Passed\n");
    }
    else {
        fprintf(g_logFile, "Test 2b Failed\n");
        fAllTest= false;
    }
    fprintf(g_logFile, "\n");

    memcpy(pt, aes128EncTestPlain2c, 16);
    oAesEnc.Encrypt(pt, ct);
    oAesDec.Decrypt(ct, npt);
    PrintBytes("aes128 PT : ", (byte*)pt, 16);
    PrintBytes("aes128 CT : ", (byte*)ct, 16);
    PrintBytes("aes128 PT : ", (byte*)npt, 16);
    if(memcmp(ct, aes128EncTestCipher2c, 16)==0 && 
       memcmp(npt, aes128EncTestPlain2c, 16)==0) {
        fprintf(g_logFile, "Test 2c Passed\n");
    }
    else {
        fprintf(g_logFile, "Test 2c Failed\n");
        fAllTest= false;
    }
    fprintf(g_logFile, "\n");

    memcpy(pt, aes128EncTestPlain2d, 16);
    oAesEnc.Encrypt(pt, ct);
    oAesDec.Decrypt(ct, npt);
    PrintBytes("aes128 PT : ", (byte*)pt, 16);
    PrintBytes("aes128 CT : ", (byte*)ct, 16);
    PrintBytes("aes128 PT : ", (byte*)npt, 16);
    if(memcmp(ct, aes128EncTestCipher2d, 16)==0 && 
       memcmp(npt, aes128EncTestPlain2d, 16)==0) {
        fprintf(g_logFile, "Test 2d Passed\n");
    }
    else {
        fprintf(g_logFile, "Test 2d Failed\n");
        fAllTest= false;
    }
    fprintf(g_logFile, "\n");
   
 
    // Test 3 (AES256)
    PrintBytes("aes256 key: ", (byte*)aes256EncTestKey1, 32);
    oAesEnc.KeySetupEnc((byte*)aes256EncTestKey1, 256);
    oAesDec.KeySetupDec((byte*)aes256EncTestKey1, 256);

    memcpy(pt, aes256EncTestPlain1a, 16);
    oAesEnc.Encrypt(pt, ct);
    oAesDec.Decrypt(ct, npt);
    PrintBytes("aes256 PT : ", (byte*)pt, 16);
    PrintBytes("aes256 CT : ", (byte*)ct, 16);
    PrintBytes("aes256 PT : ", (byte*)npt, 16);
    if(memcmp(ct, aes256EncTestCipher1a, 16)==0 && 
       memcmp(npt, aes256EncTestPlain1a, 16)==0) {
        fprintf(g_logFile, "Test 1a Passed\n");
    }
    else {
        fprintf(g_logFile, "Test 1a Failed\n");
        fAllTest= false;
    }
    fprintf(g_logFile, "\n");

    memcpy(pt, aes256EncTestPlain1b, 16);
    oAesEnc.Encrypt(pt, ct);
    oAesDec.Decrypt(ct, npt);
    PrintBytes("aes256 PT : ", (byte*)pt, 16);
    PrintBytes("aes256 CT : ", (byte*)ct, 16);
    PrintBytes("aes256 PT : ", (byte*)npt, 16);
    if(memcmp(ct, aes256EncTestCipher1b, 16)==0 && 
       memcmp(npt, aes256EncTestPlain1b, 16)==0) {
        fprintf(g_logFile, "Test 1b Passed\n");
    }
    else {
        fprintf(g_logFile, "Test 1b Failed\n");
        fAllTest= false;
    }
    fprintf(g_logFile, "\n");

    memcpy(pt, aes256EncTestPlain1c, 16);
    oAesEnc.Encrypt(pt, ct);
    oAesDec.Decrypt(ct, npt);
    PrintBytes("aes256 PT : ", (byte*)pt, 16);
    PrintBytes("aes256 CT : ", (byte*)ct, 16);
    PrintBytes("aes256 PT : ", (byte*)npt, 16);
    if(memcmp(ct, aes256EncTestCipher1c, 16)==0 && 
       memcmp(npt, aes256EncTestPlain1c, 16)==0) {
        fprintf(g_logFile, "Test 1c Passed\n");
    }
    else {
        fprintf(g_logFile, "Test 1c Failed\n");
        fAllTest= false;
    }
    fprintf(g_logFile, "\n");

    memcpy(pt, aes256EncTestPlain1d, 16);
    oAesEnc.Encrypt(pt, ct);
    oAesDec.Decrypt(ct, npt);
    PrintBytes("aes256 PT : ", (byte*)pt, 16);
    PrintBytes("aes256 CT : ", (byte*)ct, 16);
    PrintBytes("aes256 PT : ", (byte*)npt, 16);
    if(memcmp(ct, aes256EncTestCipher1d, 16)==0 && 
       memcmp(npt, aes256EncTestPlain1d, 16)==0) {
        fprintf(g_logFile, "Test 1d Passed\n");
    }
    else {
        fprintf(g_logFile, "Test 1d Failed\n");
        fAllTest= false;
    }
    fprintf(g_logFile, "\n");

    cbc     oCBCEnc;
    cbc     oCBCDec;
    byte    intKey[16];
    int     size= 0;
    int     insize= 0;
    int     psize= 0;
    int     csize= 0;
    byte    out[256];
    byte    check[256];
    byte*   pin;
    byte*   pout;

    for(psize=1; psize<=64;psize++) {
        memset(intKey, 0, 16);
        PrintBytes("CBC128 enc key : ", aes128CBCTestKey1, 16);
        PrintBytes("CBC128 int key : ", intKey, 16);
        PrintBytes("CBC128 IV      : ", aes128CBCTestIV1, 16);
        PrintBytes("CBC128 Plain   : ",  aes128SanityPlain, psize);
        if(!oCBCEnc.initEnc(AES128, SYMPAD, HMACSHA256, 16, aes128CBCTestKey1,
			        16, intKey, psize, 16, aes128CBCTestIV1)) {
            fprintf(g_logFile, "CBC encrypt init %d bytes failed\n", psize);
            fAllTest= false;
            continue;
        }

        pin= aes128SanityPlain;
        pout= out;
        insize= psize;
        memcpy(pout, aes128CBCTestIV1, oCBCEnc.m_iBlockSize);
        pout+= oCBCEnc.m_iBlockSize;

        while(insize>oCBCEnc.m_iBlockSize) {
            oCBCEnc.nextPlainBlockIn(pin, pout);
            pin+= oCBCEnc.m_iBlockSize;
            pout+= oCBCEnc.m_iBlockSize;
            insize-= oCBCEnc.m_iBlockSize;
        }
        size= oCBCEnc.lastPlainBlockIn(insize, pin, pout);
        if(size<0) {
            fprintf(g_logFile, "CBC encrypt %d bytes failed\n", psize);
            fAllTest= false;
            continue;
        } 

        csize= oCBCEnc.m_iNumCipherBytes;
        fprintf(g_logFile, 
                "CBC encrypted %d plain bytes produced %d cipherbytes\n",
                oCBCEnc.m_iNumPlainBytes, oCBCEnc.m_iNumCipherBytes);

        PrintBytes("CBC128 Plain:   ", aes128SanityPlain, psize);
        PrintBytes("CBC128 Cipher:  ", out, csize);

        if(!oCBCDec.initDec(AES128, SYMPAD, HMACSHA256, 16, aes128CBCTestKey1,
                16, intKey, csize)) {
            fprintf(g_logFile, "CBC decrypt init %d bytes failed\n", psize);
            fAllTest= false;
            continue;
        }

        insize= csize;
        pin= out;
        pout= check;
        oCBCDec.firstCipherBlockIn(pin);
        insize-= oCBCDec.m_iBlockSize;
        pin+= oCBCDec.m_iBlockSize;
        while(insize>4*oCBCDec.m_iBlockSize) {
            oCBCDec.nextCipherBlockIn(pin, pout);
            pin+= oCBCDec.m_iBlockSize;
            pout+= oCBCDec.m_iBlockSize;
            insize-= oCBCDec.m_iBlockSize;
        }
        size= oCBCDec.lastCipherBlockIn(insize, pin, pout);
        if(size<0) {
            fprintf(g_logFile, "CBC decrypt %d bytes failed\n", psize);
            fAllTest= false;
            continue;
        } 
        fprintf(g_logFile, 
                "CBC decrypt %d cipherbytes produced %d plainbytes\n",
                oCBCDec.m_iNumCipherBytes, oCBCDec.m_iNumPlainBytes);
        PrintBytes("CBC128 Decrypt: ", check, oCBCDec.m_iNumPlainBytes);
        if(psize==oCBCDec.m_iNumPlainBytes && 
	   memcmp(check, aes128SanityPlain, psize)==0) {
            fprintf(g_logFile, "CBC %d bytes sanity PASSED\n", psize);
        }
        else {
            fprintf(g_logFile, "CBC %d bytes sanity FAILED\n", psize);
            fAllTest= false;
        }
        fprintf(g_logFile, "\n");
    }

    if(fAllTest)
        fprintf(g_logFile, "All tests PASSED\n");
    else
        fprintf(g_logFile, "Some test FAILED\n");

    return 0;
}


// ---------------------------------------------------------------------------


