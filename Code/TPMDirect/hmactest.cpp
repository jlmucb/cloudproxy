//
//      File: hmactest.cpp 
//      Description: hmacsha1 test
//      TPM interface.
//
//  Copyright (c) 2012 John Manferdelli.  All rights reserved.
//    Some contributions (c) 2012, Intel Corporation
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


#include "algs.h"
#include "sha1.h"
#include "logging.h"
#include "hmacsha1.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

class hmactest {
public:
    int     keylen;
    byte    key[40];
    int     messagelen;
    byte    message[40];
    byte    testdigest[20];
};


inline byte val(char a)
{
    if(a>='0'&a<='9')
        return a-'0';
    if(a>='a'&a<='f')
        return a-'a'+10;
    return 16;
}


bool fromhex(char* szH, byte* buf, int sizemax, int* psizeout)
{
    int     i;
    byte*   p= buf;
    byte    a, b, c;

    for(i=0; i<sizemax; i++) {
        if(*szH==0 || *(szH+1)==0)
            break;
        a= val(*szH);
        b= val(*(szH+1));
        szH+= 2;
        c= a*16+b;
        *(p++)= c;
    }
    *psizeout= i;
    return true;
}


hmactest tests[3];

void inittests()
{
    char*   sz;
    int     n;

    fromhex((char*) "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
             tests[0].key, 40, &tests[0].keylen);
    sz= (char*) "Hi There";
    memcpy(tests[0].message, (byte*)sz, strlen(sz));
    tests[0].messagelen= strlen(sz);
    fromhex((char*) "b617318655057264e28bc0b6fb378c8ef146be00",
            tests[0].testdigest, 20, &n);
}




// --------------------------------------------------------------------------


#define BUFSIZE  128


int main(int an, char** av)
{
    u8          key[BUFSIZE];
    int         klen;
    u8          message[BUFSIZE];
    int         mlen;
    byte        digest[BUFSIZE];
    int         i, n;
    int         ntests= 1;
    int         size;

    printf("hmac-sha1 test\n\n");
    memset(key, 0, BUFSIZE);
    memset(message, 0, BUFSIZE);
    memset(digest, 0, BUFSIZE);

    inittests();
    for(i=0; i<ntests;i++) {
        memset(key, 0, BUFSIZE);
        memset(message, 0, BUFSIZE);
        memset(digest, 0, BUFSIZE);
        klen= tests[i].keylen;
        memcpy(key,tests[i].key, klen);
        mlen= tests[i].messagelen;
        memcpy(message, tests[i].message, mlen);
        if(!hmac_sha1(message, mlen, key, klen, digest)) {
            printf("hmac calculation  failes test %d\n", i);
            continue;
        }
        printf("Test %d, key length= %d, message length= %d\n", i, klen, mlen);
        PrintBytes((char*)"key: ", key, klen);
        PrintBytes((char*)"msg: ", message, mlen);
        PrintBytes((char*)"Computed hmac: ", digest, 20);
        PrintBytes((char*)"Actual hmac:   ", tests[i].testdigest, 20);
        if(memcmp(digest, tests[i].testdigest,20)==0)
            printf("test succeeds\n\n");
        else
            printf("test fails\n\n");
    }

    return 0;
}


// --------------------------------------------------------------------------


