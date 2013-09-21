//
//  File: buffercoding.cpp
//  Description: encode/decode buffers between app/OS and tcService/OS
//
//  Copyright (c) 2012, John Manferdelli.  All rights reserved.
//     Some contributions Copyright (c) 2012, Intel Corporation. 
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


#include "jlmTypes.h"
#include "logging.h"
#include "tcService.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>


// ------------------------------------------------------------------------------


int encodeTCSERVICEGETPOLICYKEYFROMOS(u32 keyType, int size, const byte* key, 
                                      int bufsize, byte* buf)
{
    int n= 0;

    if(bufsize<(int)(sizeof(u32)+sizeof(int)+size))
        return -1;
    memcpy(&buf[n], (byte*)&keyType, sizeof(u32));
    n+= sizeof(u32);
    memcpy(&buf[n], &size, sizeof(int));
    n+= sizeof(int);
    memcpy(&buf[n], key, size);
    n+= size;
    return n;
}


bool  decodeTCSERVICEGETPOLICYKEYFROMOS(u32* pkeyType, int* psize, 
                                            byte* key, const byte* buf)
{
    int n= 0;
    memcpy(pkeyType, buf, sizeof(u32));
    n+= sizeof(u32);
    memcpy(psize, &buf[n], sizeof(int));
    n+= sizeof(int);
    memcpy(key, &buf[n], *psize);
    return true;
}


int encodeTCSERVICEGETOSHASHFROMTCSERVICE(u32 hashType, int size, const byte* hash, 
                                          int bufsize, byte* buf)
{
    int n= 0;

    if(bufsize<(int)(sizeof(u32)+sizeof(int)+size))
        return -1;
    memcpy(&buf[n], (byte*)&hashType, sizeof(u32));
    n+= sizeof(u32);
    memcpy(&buf[n], &size, sizeof(int));
    n+= sizeof(int);
    memcpy(&buf[n], hash, size);
    n+= size;
    return n;
}


bool  decodeTCSERVICEGETOSHASHFROMTCSERVICE(u32* phashType, int* psize, byte* hash, 
                                            const byte* buf)
{
    int n= 0;

    memcpy(phashType, buf, sizeof(u32));
    n+= sizeof(u32);
    memcpy(psize, &buf[n], sizeof(int));
    n+= sizeof(int);
    memcpy(hash, &buf[n], *psize);
    return true;
}


bool  encodeTCSERVICEGETOSCREDSFROMAPP(u32 credType, int size, const byte* cred, 
                                       byte* buf)
{
    int n= 0;

    memcpy(&buf[n], (byte*)&credType, sizeof(u32));
    n+= sizeof(u32);
    memcpy(&buf[n], &size, sizeof(int));
    n+= sizeof(int);
    memcpy(&buf[n], cred, size);
    return true;
}


bool  decodeTCSERVICEGETOSCREDSFROMAPP(u32* pcredType, int* psize, byte* cred, 
                                       const byte* buf)
{
    int n= 0;

    memcpy(pcredType, buf, sizeof(u32));
    n+= sizeof(u32);
    memcpy(psize, &buf[n], sizeof(int));
    n+= sizeof(int);
    memcpy(cred, &buf[n], *psize);
    return true;
}


int encodeTCSERVICEGETOSCREDSFROMTCSERVICE(u32 credType, int size, const byte* cred, 
                                      int bufsize, byte* buf)
{
    int n= 0;

    if(bufsize<(int)(sizeof(u32)+sizeof(int)+size))
        return -1;
    memcpy(&buf[n], (byte*)&credType, sizeof(u32));
    n+= sizeof(u32);
    memcpy(&buf[n], &size, sizeof(int));
    n+= sizeof(int);
    memcpy(&buf[n], cred, size);
    n+= size;
    return n;
}


bool  decodeTCSERVICEGETOSCREDSFROMTCSERVICE(u32* pcredType, int* psize, 
                                             byte* cred, const byte* buf)
{
    int n= 0;

    memcpy(pcredType, buf, sizeof(u32));
    n+= sizeof(u32);
    memcpy(psize, &buf[n], sizeof(int));
    n+= sizeof(int);
    memcpy(cred, &buf[n], *psize);
    return true;
}


int encodeTCSERVICESEALFORFROMAPP(int sealsize, const byte* seal, int bufsize, 
                                  byte* buf)
{
    int n= 0;

    if(bufsize<(int)(sizeof(int)+sealsize))
        return -1;
    memcpy(&buf[n], &sealsize, sizeof(int));
    n+= sizeof(int);
    memcpy(&buf[n], seal, sealsize);
    n+= sealsize;
    return n;
}


bool  decodeTCSERVICESEALFORFROMAPP(int* psealsize, byte* seal, const byte* buf)
{
    int n= 0;

    memcpy(psealsize, &buf[n], sizeof(int));
    n+= sizeof(int);
    memcpy(seal, &buf[n], *psealsize);
    return true;
}


int encodeTCSERVICESEALFORFROMTCSERVICE(int sealedsize, const byte* sealed, int bufsize, byte* buf)
{
    int n= 0;

    if(bufsize<(int)(sealedsize+sizeof(int)))
        return -1;
    memcpy(&buf[n], (byte*)&sealedsize, sizeof(int));
    n+= sizeof(int);
    memcpy(&buf[n], sealed, sealedsize);
    n+= sealedsize;
    return n;
}


bool  decodeTCSERVICESEALFORFROMTCSERVICE(int* psealedsize, byte* sealed, const byte* buf)
{
    int n= 0;

    memcpy(psealedsize, &buf[n], sizeof(int));
    n+= sizeof(int);
    memcpy(sealed, &buf[n], *psealedsize);
    return true;
}


int encodeTCSERVICEUNSEALFORFROMAPP(int sealedsize, const byte* sealed, int bufsize, byte* buf)
{
    int n= 0;

    if(bufsize<(int)(sealedsize+sizeof(int)))
        return -1;
    memcpy(&buf[n], (byte*)&sealedsize, sizeof(int));
    n+= sizeof(int);
    memcpy(&buf[n], sealed, sealedsize);
    n+= sealedsize;
    return n;
}


bool decodeTCSERVICEUNSEALFORFROMAPP(int* psealedsize, byte* sealed, const byte* buf)
{
    int n= 0;

    memcpy(psealedsize, &buf[n], sizeof(int));
    n+= sizeof(int);
    memcpy(sealed, &buf[n], *psealedsize);
    n+= *psealedsize;
    return true;
}


int encodeTCSERVICEUNSEALFORFROMTCSERVICE(u32 hashType, int hashsize, const byte* hash,
                                    int sealsize, const byte* seal, int bufsize, byte* buf)
{
    int n= 0;

    if(bufsize<(int)(hashsize+sealsize+sizeof(int)+sizeof(u32)))
        return -1;
    memcpy(&buf[n], (byte*)&hashType, sizeof(u32));
    n+= sizeof(u32);
    memcpy(&buf[n], &hashsize, sizeof(int));
    n+= sizeof(int);
    memcpy(&buf[n], hash, hashsize);
    n+= hashsize;
    memcpy(&buf[n], &sealsize, sizeof(int));
    n+= sizeof(int);
    memcpy(&buf[n], seal, sealsize);
    n+= sealsize;
    return n;
}


bool  decodeTCSERVICEUNSEALFORFROMTCSERVICE(int* punsealedsize, 
                                        byte* unsealed, const byte* buf)
{
    int n= 0;

    memcpy(punsealedsize, &buf[n], sizeof(int));
    n+= sizeof(int);
    memcpy(unsealed, &buf[n], *punsealedsize);
    return true;
}


int encodeTCSERVICEATTESTFORFROMAPP(int toattestsize, const byte* toattest, 
                                    int bufsize, byte* buf)
{
    int n= 0;

    if(bufsize<(int)(toattestsize+sizeof(int))) {
        return -1;
    }
    memcpy(&buf[n], (byte*)&toattestsize, sizeof(int));
    n+= sizeof(int);
    memcpy(&buf[n], toattest, toattestsize);
    n+= toattestsize;
    return n;
}


bool  decodeTCSERVICEATTESTFORFROMAPP(int* ptoattestsize, byte* toattest, 
                                      const byte* buf)
{
    int n= 0;

    memcpy(ptoattestsize, &buf[n], sizeof(int));
    n+= sizeof(int);
    memcpy(toattest, &buf[n], *ptoattestsize);
    return true;
}


bool  encodeTCSERVICEATTESTFORFROMTCSERVICE(int attestsize, const byte* attested, 
                                            byte* buf)
{
    return false;
}


bool  decodeTCSERVICEATTESTFORFROMTCSERVICE(int* pattestsize, byte* attested, 
                                            const byte* buf)
{
    int n= 0;

    memcpy(pattestsize, &buf[n], sizeof(int));
    n+= sizeof(int);
    memcpy(attested, &buf[n], *pattestsize);
    return true;
}


// Todo: security problem with overflow here
int encodeTCSERVICESTARTAPPFROMAPP(int nargs, char** args, 
                                   int bufsize, byte* buf)
{
    int n= 0;
    int m= 0;
    int k= 0;
    int i;

#ifdef TEST 
    fprintf(g_logFile, "encodeTCSERVICESTARTAPPFROMAPP, nargs: %d\n", nargs);
    for(i=0;i<nargs; i++)
        fprintf(g_logFile, "\targ[%d]: %s\n", i, args[i]);
#endif
    for(i=0;i<nargs;i++)
        k+= sizeof(int)+strlen(args[i])+1;
    if(bufsize<(int)(sizeof(int)+k)) {
        fprintf(g_logFile, "encodeTCSERVICESTARTAPPFROMAPP buffer too small\n");
        return -1;
    }
    memcpy(&buf[n], (byte*)&nargs, sizeof(int));
    n+= sizeof(int);
    for(i=0;i<nargs;i++) {
        m= strlen(args[i])+1;
        memcpy(&buf[n], &m, sizeof(int));
        n+= sizeof(int);
        memcpy(&buf[n], (byte*)args[i], m);
        n+= m;
    }

    return n;
}


bool  decodeTCSERVICESTARTAPPFROMAPP(int* pnargs, char** args, const byte* buf)
{
    int     n= 0;
    int     i, m, k;

#ifdef TEST
    fprintf(g_logFile, "decodeTCSERVICESTARTAPPFROMAPP: starting\n");
#endif 
    memcpy(&m, &buf[n], sizeof(int));
#ifdef TEST
    fprintf(g_logFile, "Got argc %d\n", m);
#endif 
    if(m>*pnargs) {
        fprintf(g_logFile, "decodeTCSERVICESTARTAPPFROMAPP too few args avail\n");
        return false;
    }
    n+= sizeof(int);
    *pnargs= m;

    for(i=0;i<m;i++) {
        memcpy(&k, &buf[n], sizeof(int));
        n+= sizeof(int);
        args[i]= strdup(reinterpret_cast<const char*>(&buf[n]));
        n+= k;
    }
   
#ifdef TEST
    fprintf(g_logFile, "decodeTCSERVICESTARTAPPFROMAPP %d args\n",  m);
    for(i=1; i<m;i++)
        fprintf(g_logFile, "\targ[%d]: %s\n", i, args[i]);
#endif 
    return true;
}


bool  encodeTCSERVICESTARTAPPFROMTCSERVICE(int procid, byte* buf)
{
    if(buf==NULL)
        return false;
    *((int*) buf)= procid;
    return true;
}


bool  decodeTCSERVICESTARTAPPFROMTCSERVICE(int* pprocid, const byte* buf)
{
    if(buf==NULL)
        return false;
    *pprocid= *((int*) buf);
    return true;
}


bool  encodeTCSERVICETERMINATEAPPFROMAPP()
{
    return false;
}


bool  decodeTCSERVICETERMINATEAPPFROMAPP()
{
    return false;
}


bool  encodeTCSERVICETERMINATEAPPFROMTCSERVICE()
{
    return false;
}


bool  decodeTCSERVICETERMINATEAPPFROMTCSERVICE()
{
    return false;
}


int encodeTCSERVICEGETPROGHASHFROMSERVICE (u32 uType, int size, const byte* hash,
                                           int bufsize, byte* buf)
{
    int n= 0;

#ifdef CODINGTEST
    fprintf(g_logFile, "encodeTCSERVICEGETPROGHASHFROMSERVICE, type: %d, size: %d\n", 
            uType, size);
#endif
    if(bufsize<(int)(sizeof(u32)+sizeof(int)+size))
        return -1;
    memcpy(&buf[n], (byte*)&uType, sizeof(u32));
    n+= sizeof(u32);
    memcpy(&buf[n], &size, sizeof(int));
    n+= sizeof(int);
    memcpy(&buf[n], hash, size);
    n+= size;
    return n;
}


bool  decodeTCSERVICEGETPROGHASHFROMSERVICE(u32* puType, int* psize, byte* hash,
                                      int bufsize, const byte* buf)
{
    int n= 0;

    memcpy(puType, buf, sizeof(u32));
    n+= sizeof(u32);
    memcpy(psize, &buf[n], sizeof(int));
    n+= sizeof(int);
    memcpy(hash, &buf[n], *psize);
    return true;
}

int encodeTCSERVICEGETPROGHASHFROMAPP(int pid, int bufsize, byte* buf)
{
    int n= 0;

    // note that this cast is safe, since sizeof(int) is always less than 2^(sizeof(int)-1)
    if(bufsize<static_cast<int>(sizeof(int)))
        return -1;
    memcpy(&buf[n], &pid, sizeof(int));
    n+= sizeof(int);
    return n;
}


bool  decodeTCSERVICEGETPROGHASHFROMAPP(int* ppid, const byte* buf)
{
    int n= 0;

    memcpy(ppid, &buf[n], sizeof(int));
    n+= sizeof(int);
    return true;
}




// ------------------------------------------------------------------------------


