//
//  Copyright (c) 2011, (c) John Manferdelli.  All rights reserved.
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
#include "sha256.h"



byte b;
#define BUF_SIZE 1024


// --------------------------------------------------------------------------------


void bigEndian(u8* buf, int size)
{
    u8* pU= buf;
    u8  t;

    while(size>=(int)sizeof(u32)) {
        t= pU[0]; pU[0]= pU[3]; pU[3]= t;
        t= pU[1]; pU[1]= pU[2]; pU[2]= t;
        size-= sizeof(u32);
        pU+= sizeof(u32);
    }
}


void PrintBytes(char* szMsg, byte* pbData, int iSize)
{
        int i;

        printf("\t%s: ", szMsg);
        for (i= 0; i<iSize; i++) {
        printf("%02x", pbData[i]);
                }
        printf("\n");
        }


void testvector(int sizetoHash, byte* toHash, int sizeAns, byte* answer)
{
    Sha256      oSha;
    byte        rgbDigest[64];

    printf("SHA-256 Test, %d bytes\n", sizetoHash);
    PrintBytes((char*)"In     ", toHash, sizetoHash);
    PrintBytes((char*)"Answer ", answer, sizeAns);

    oSha.Init();
    oSha.Update(toHash, sizetoHash);
    oSha.Final();
    oSha.GetDigest(rgbDigest);

    PrintBytes((char*)"Out    ", rgbDigest, sizeAns);
    if(memcmp(rgbDigest, answer, sizeAns) == 0) {
        printf("Test Passed\n\n");
    }
    else {
        printf("Test Failed\n\n");
    }
}


int main(int argc, char** argv)
{
    // Test1
    const byte* toHash1= (const byte*)"abc";
    int sizetoHash1= strlen((const char *)toHash1);
    // ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad
    u32 answer1[8]= {
        0xba7816bf, 0x8f01cfea, 0x414140de, 0x5dae2223,
        0xb00361a3, 0x96177a9c, 0xb410ff61, 0xf20015ad
    };
    bigEndian((byte*) answer1, 20);
    testvector(sizetoHash1, (byte*) toHash1, 20, (byte*) answer1);

    const byte* toHash2= (const byte*) 
            "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    u32 answer2[8]= {
        0x248d6a61, 0xd20638b8, 0xe5c02693, 0x0c3e6039,
        0xa33ce459, 0x64ff2167, 0xf6ecedd4, 0x19db06c1
    };
    int sizetoHash2= strlen((const char *)toHash2);
    bigEndian((byte*) answer2, 20);
    testvector(sizetoHash2, (byte*) toHash2, 20, (byte*) answer2);
    
    return 0;
}


// ---------------------------------------------------------------------------------------


