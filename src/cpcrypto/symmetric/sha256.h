//
//  File: sha256.h
//  Description: sha256 implementation
//
//  Copyright (c) 2007,2011,  John Manferdelli
//  All rights reserved.
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

#ifndef _SHA256_H_
#define _SHA256_H_

#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN
#endif

#include "common.h"

//------------------------------------------------------------------------------

#define SHA256_DIGESTSIZE_BYTES 32
#define SHA256_BLOCKSIZE_BYTES 64

class Sha256 {
 public:
  enum {
    DIGESTSIZE = 32,
    BLOCKSIZE = 64
  };
  u64 total_processed_length_;
  const static u32 K[SHA256_BLOCKSIZE_BYTES];
  u32 state_[SHA256_DIGESTSIZE_BYTES / sizeof(u32)];
  byte final_hash_[SHA256_DIGESTSIZE_BYTES];
  int partial_block_length_;
  byte current_block_[SHA256_BLOCKSIZE_BYTES];

  void Init();
  void LittleEndian(byte* buf, int size);
  void Transform(u32* state, u32* data);
  void Update(const byte*, int);
  void Final();
  void GetDigest(byte*);
};

#endif

//------------------------------------------------------------------------------
