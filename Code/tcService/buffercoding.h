//
//  File: buffercoding.h
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


// ------------------------------------------------------------------------------


#ifndef _BUFFERCODING_H__
#define _BUFFERCODING_H__


#include "jlmTypes.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>


int   encodeTCSERVICEGETPOLICYKEYFROMOS(u32 keyType, int size, 
                                    byte* key, int bufsize, byte* buf);
bool  decodeTCSERVICEGETPOLICYKEYFROMOS(u32* pkeyType, int* psize, 
                                    byte* key, byte* buf);

int   encodeTCSERVICEGETOSHASHFROMTCSERVICE(u32 hashType, int size, 
                                    byte* hash, int bufsize, byte* buf);
bool  decodeTCSERVICEGETOSHASHFROMTCSERVICE(u32* phashType, int* psize, 
                                    byte* hash, byte* buf);

bool  decodeTCSERVICEGETOSCREDSFROMAPP(u32* pcredType, int* psize, byte* cred, 
                                    byte* buf);

int   encodeTCSERVICEGETOSCREDSFROMTCSERVICE(u32 credType, int size, byte* cred, 
                                    int bufsize, byte* buf);
bool  decodeTCSERVICEGETOSCREDSFROMTCSERVICE(u32* pcredType, int* psize, 
                                    byte* cred, byte* buf);

int   encodeTCSERVICESEALFORFROMAPP(int sealsize, byte* seal, int bufsize, byte* buf);
bool  decodeTCSERVICESEALFORFROMAPP(int* psealedsize, byte* sealed, byte* buf);

int   encodeTCSERVICESEALFORFROMTCSERVICE(int sealedsize, byte* sealed, int bufsize, byte* buf);
bool  decodeTCSERVICESEALFORFROMTCSERVICE(int* psealedsize, byte* sealed, byte* buf);

int   encodeTCSERVICEUNSEALFORFROMAPP(int sealedsize, byte* sealed, int bufsize, byte* buf);
bool  decodeTCSERVICEUNSEALFORFROMAPP(int* psealsize, byte* seal, byte* buf);

int   encodeTCSERVICEUNSEALFORFROMTCSERVICE(u32 hashType, int hashsize, byte* hash,
                                    int sealsize, byte* seal, int bufsize, byte* buf);
bool  decodeTCSERVICEUNSEALFORFROMTCSERVICE(int* punsealsize, byte* unsealed, 
                                    byte* buf);

bool  encodeTCSERVICEATTESTFORFROMAPP(int toattestsize, byte* toattest, 
                                      int bufsize, byte* buf);
bool  decodeTCSERVICEATTESTFORFROMAPP(int* ptoattestsize, byte* toattest, 
                                      byte* buf);

bool  encodeTCSERVICEATTESTFORFROMTCSERVICE(int attestsize, byte* attested, 
                                            byte* buf);
bool  decodeTCSERVICEATTESTFORFROMTCSERVICE(int* pattestsize, byte* attested, 
                                            byte* buf);

int encodeTCSERVICESTARTAPPFROMAPP(char* file, int nargs, char** args,
                                   int bufsize, byte* buf);
bool decodeTCSERVICESTARTAPPFROMAPP(char** psz, int* pnargs, char**, byte* buf);

int   encodeTCSERVICESTARTAPPFROMTCSERVICE(int procid, int sizebuf, byte* buf);
bool  decodeTCSERVICESTARTAPPFROMTCSERVICE(int* pprocid, byte* buf);

bool  encodeTCSERVICETERMINATEAPPFROMAPP();
bool  decodeTCSERVICETERMINATEAPPFROMAPP();
bool  encodeTCSERVICETERMINATEAPPFROMTCSERVICE();
bool  decodeTCSERVICETERMINATEAPPFROMTCSERVICE();

bool  encodeTCSERVICEGETPOLICYKEYFROMOS(u32 keyType, int size, 
                                        byte* key, byte* buf);
bool  decodeTCSERVICEGETPOLICYKEYFROMOS(u32* pkeyType, int* psize,
                                        byte* key, byte* buf);
int encodeTCSERVICEGETPROGHASHFROMSERVICE (u32 uType, int size, byte* hash,
                                           int bufsize, byte* buf);
bool  decodeTCSERVICEGETPROGHASHFROMSERVICE(u32* puType, int* psize, byte* hash,
                                      int bufsize, byte* buf);
int encodeTCSERVICEGETPROGHASHFROMAPP(int pid, int bufsize, byte* buf);
bool  decodeTCSERVICEGETPROGHASHFROMAPP(int* ppid, byte* buf);


#endif


// ------------------------------------------------------------------------------


