#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

char* szH= (char*)"66e94bd4ef8a2c3b884cfa59ca342b2e";
char* szX= (char*)"0388dace60b6a392f328c2b971b2fe78";

typedef unsigned char u8;

//  File: gcmtest.cpp
//      John Manferdelli
//
//  Description: gcmtest code
//
//  Copyright (c) 2011, Intel Corporation. Some contributions
//    (c) John Manferdelli.  All rights reserved.
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


// ---------------------------------------------------------------------------



void printBits(char* sz,u8* rgA, int n)
{
    int i;

    if(sz!=NULL)
        printf("%s\n",sz);
    for(i=0; i<n; i++) {
        if(i!=0 && (i%32)==0)
            printf("\n");
        else if(i!=0 && (i%8)==0)
            printf(" ");
        printf("%1d", rgA[i]);
    }
    printf("\n\n");
}

void  toBits(char a, u8* pb)
{
    u8  x;

    if(a>='0' && a<='9')
        x= a-'0';
    else if(a>='a' && a<='f')
        x= a-'a'+10;
    else
        return;
    *pb= (x>>3)&0x1;
    *(pb+1)= (x>>2)&0x1;
    *(pb+2)= (x>>1)&0x1;
    *(pb+3)= (x)&0x1;
    return;
}

void tobitArray(char* p, u8* rgA, int n)
{
    int i;

    for(i=0; i<n; i+=4) {
        toBits(*p, &rgA[i]);
        p++;
    }
}


void shiftandXor(u8* in, u8* out, int shift, int n)
{
    int i;

    for(i=0;i<n;i++)
        out[i+shift]^= in[i];
}


// ---------------------------------------------------------------------------


main(int an, char** av)
{
    int i,j,k,m;
    char    *p, a, b;
    u8      rgH[128];
    u8      rgX[128];
    u8      rgOut[256];
    u8      rgF[8]= {1,1,1,0,0,0,0,1};
 
    memset(rgOut, 0, 256);
    tobitArray(szH, rgH, 128);
    tobitArray(szX, rgX, 128);
    printBits((char*)"H", rgH, 128);
    printBits((char*)"X", rgX, 128);

    for(i=0; i<128; i++) {
        if(rgX[i]!=0)
            shiftandXor(rgH, rgOut, i, 128);
    }
    printBits((char*)"out", rgOut, 256);

    return 0;
}


// ---------------------------------------------------------------------------


