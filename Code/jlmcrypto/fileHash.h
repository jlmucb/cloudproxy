//
//  File: fileHash.h
//  Description: getfilehashdefines 
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


#ifndef _FILEHASH__H_
#define _FILEHASH__H_

#include "jlmTypes.h"
#include "sha256.h"

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <string.h>
#include <unistd.h>

bool getfileHash(const char* szFile, u32* phashType, int* psize, byte* rgHash);
bool getcombinedfileHash(int numfiles, const char** fileNames, u32* phashType, 
                         int* psize, byte* rgHash);

#endif


// ------------------------------------------------------------------------------


