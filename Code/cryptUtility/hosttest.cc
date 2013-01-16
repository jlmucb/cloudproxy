//  File: hosttest.cpp
//      John Manferdelli
//
//  Description: hosttest
//
//  Copyright (c) 2011, Intel Corporation. Some contributions 
//    (c) John Manferdelli.  All rights reserved.
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


// ------------------------------------------------------------------------


#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>


// ------------------------------------------------------------------------


int main(int an, char** av)
{
    unsigned        v;
    struct in_addr  haddr;
    char unsigned*  pa;

    if(an<2) {
        printf("No hostname\n");
        return 1;
    }

    struct hostent* pHostent;
    pHostent= gethostbyname((const char *) av[1]);
    pa= (char unsigned*) (pHostent->h_addr);
    printf("%s: %d.%d.%d.%d\n", pHostent->h_name, 
           *pa, *(pa+1), *(pa+2), *(pa+3));
    struct in_addr  ad= *(struct in_addr*)(pHostent->h_addr);
    char* p= inet_ntoa(ad);
    printf("Sys name: %s\n", p);
    unsigned u= inet_addr(p);
    pa= (unsigned char*) &u;
    printf("%s: %d.%d.%d.%d\n", pHostent->h_name, 
           *pa, *(pa+1), *(pa+2), *(pa+3));

    return 0;
}


// ------------------------------------------------------------------------



