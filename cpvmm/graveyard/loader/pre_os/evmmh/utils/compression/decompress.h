/****************************************************************************
* Copyright (c) 2013 Intel Corporation
*
* Licensed under the Apache License, Version 2.0 (the "License");
* you may not use this file except in compliance with the License.
* You may obtain a copy of the License at
*
*     http://www.apache.org/licenses/LICENSE-2.0

* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific language governing permissions and
* limitations under the License.
****************************************************************************/

/****************************************************************************
* INTEL CONFIDENTIAL
* Copyright 2001-2013 Intel Corporation All Rights Reserved.
*
* The source code contained or described herein and all documents related to
* the source code ("Material") are owned by Intel Corporation or its
* suppliers or licensors.  Title to the Material remains with Intel
* Corporation or its suppliers and licensors.  The Material contains trade
* secrets and proprietary and confidential information of Intel or its
* suppliers and licensors.  The Material is protected by worldwide copyright
* and trade secret laws and treaty provisions.  No part of the Material may
* be used, copied, reproduced, modified, published, uploaded, posted,
* transmitted, distributed, or disclosed in any way without Intel's prior
* express written permission.
*
* No license under any patent, copyright, trade secret or other intellectual
* property right is granted to or conferred upon you by disclosure or
* delivery of the Materials, either expressly, by implication, inducement,
* estoppel or otherwise.  Any license under such intellectual property rights
* must be express and approved by Intel in writing.
****************************************************************************/

#ifndef _DECOMPRESS_H
#define _DECOMPRESS_H

// VT #include "Efi.h"

//
// Driver Produced Protocol Prototypes
//
// VT #include EFI_PROTOCOL_DEFINITION(Decompress)

//
// Decompression algorithm specific values and data structures
//
#define     BITBUFSIZ         16
#define     WNDBIT            13
#define     WNDSIZ            (1U << WNDBIT)
#define     MAXMATCH          256
#define     THRESHOLD         3
#define     CODE_BIT          16
#define     UINT8_MAX         0xff
#define     BAD_TABLE         -1

//
// C: Char&Len Set; P: Position Set; T: exTra Set
//

#define     NC                (0xff + MAXMATCH + 2 - THRESHOLD)
#define     CBIT              9
#define     NP                (WNDBIT + 1)
#define     NT                (CODE_BIT + 3)
#define     PBIT              4
#define     TBIT              5
#if NT > NP
  #define     NPT               NT
#else
  #define     NPT               NP
#endif

typedef struct {
  UINT8       *mSrcBase;      //Starting address of compressed data
  UINT8       *mDstBase;      //Starting address of decompressed data

  UINT16      mBytesRemain;
  UINT16      mBitCount;
  UINT16      mBitBuf;
  UINT16      mSubBitBuf;
  UINT16      mBufSiz;
  UINT16      mBlockSize;
  UINT32      mDataIdx;
  UINT32      mCompSize;
  UINT32      mOrigSize;
  UINT32      mOutBuf;
  UINT32      mInBuf;

  UINT16      mBadTableFlag;

  UINT8       mBuffer[WNDSIZ];
  UINT16      mLeft[2 * NC - 1];
  UINT16      mRight[2 * NC - 1];
  UINT32      mBuf;
  UINT8       mCLen[NC];
  UINT8       mPTLen[NPT];
  UINT16      mCTable[4096];
  UINT16      mPTTable[256];
} SCRATCH_DATA;


BOOLEAN
Decompress_GetInfo (
  IN      VOID    *Source,
  IN      UINT32  SrcSize,
  OUT     UINT32  *DstSize
  );

BOOLEAN
Decompress_Decompress (
  IN      VOID    *Source,
  IN      UINT32  SrcSize,
  IN OUT  VOID    *Destination,
  IN      UINT32  DstSize
  );


#endif
