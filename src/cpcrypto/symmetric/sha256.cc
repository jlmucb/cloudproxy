//  File: sha256.cpp
//  Description: sha256 implementation
//
//  Derived from public domain version (sha.cpp) written by Wei Dai (see
//  notice below).  Downloaded from http://www.cryptopp.com/  1/23/2102
//
//  Modifications and work as a whole is
//  Copyright (c) 2011, John Manferdelli.  All rights reserved.
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

//  Original notice:
//      sha.cpp - modified by Wei Dai from Steve Reid's public domain sha1.c
//      Steve Reid implemented SHA-1. Wei Dai implemented SHA-2.
//      Both are in the public domain.

#include "sha256.h"
#include "common.h"
#include "logging.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

template <class T>
inline T rotrFixed(T x, unsigned int y) {
  return (x >> y) | (x << (sizeof(T) * 8 - y));
}

#ifdef CRYPTOTEST2
#include "stdio.h"
void printW(u32* pU, int count) {
  int i;

  for (i = 0; i < count; i++) {
    LOG(WARNING)<<pU[i];
  }
  LOG(WARNING)<<"\n";
}
#endif

// -----------------------------------------------------------------------------------

const u32 Sha256::K[SHA256_BLOCKSIZE_BYTES] = {
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
  0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
  0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
  0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
  0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
  0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void Sha256::LittleEndian(byte* buf, int size) {
  byte* current = buf;
  byte t;

  while (size >= (int)sizeof(u32)) {
    t = current[0];
    current[0] = current[3];
    current[3] = t;
    t = current[1];
    current[1] = current[2];
    current[2] = t;
    size -= sizeof(u32);
    current += sizeof(u32);
  }
}

void Sha256::Init() {
  state_[0] = 0x6a09e667;
  state_[1] = 0xbb67ae85;
  state_[2] = 0x3c6ef372;
  state_[3] = 0xa54ff53a;
  state_[4] = 0x510e527f;
  state_[5] = 0x9b05688c;
  state_[6] = 0x1f83d9ab;
  state_[7] = 0x5be0cd19;
  total_processed_length_ = 0ULL;
  partial_block_length_ = 0;
}

#define blk0(i) (W[i] = data[i])
#define blk2(i) \
  (W[i & 15] += s1(W[(i - 2) & 15]) + W[(i - 7) & 15] + s0(W[(i - 15) & 15]))
#define Ch(x, y, z) (z ^ (x&(y ^ z)))
#define Maj(x, y, z) ((x& y) | (z&(x | y)))

#define a(i) T[(0 - i) & 7]
#define b(i) T[(1 - i) & 7]
#define c(i) T[(2 - i) & 7]
#define d(i) T[(3 - i) & 7]
#define e(i) T[(4 - i) & 7]
#define f(i) T[(5 - i) & 7]
#define g(i) T[(6 - i) & 7]
#define h(i) T[(7 - i) & 7]

#define R(i) \
  h(i) += S1(e(i)) + Ch(e(i), f(i), g(i)) + K[i + j] + (j ? blk2(i) : blk0(i));\
d(i) += h(i);\
h(i) += S0(a(i)) + Maj(a(i), b(i), c(i))
#define S0(x) (rotrFixed(x, 2) ^ rotrFixed(x, 13) ^ rotrFixed(x, 22))
#define S1(x) (rotrFixed(x, 6) ^ rotrFixed(x, 11) ^ rotrFixed(x, 25))
#define s0(x) (rotrFixed(x, 7) ^ rotrFixed(x, 18) ^ (x >> 3))
#define s1(x) (rotrFixed(x, 17) ^ rotrFixed(x, 19) ^ (x >> 10))
        void Sha256::Transform(u32 * state, u32 * data) {
  u32 W[16];
  u32 T[8];
  u32 j;

#ifdef CRYPTOTEST2
  LOG(INFO)<<"\nState     in:  ";
  printW(state_, 8);
  LOG(INFO)<<"Data      in:  ";
  printW(data, 16);
#endif
  memcpy((byte*)W, (byte*)data, 64);
  memcpy(T, state, sizeof(T));
  for (j = 0; j < 64; j += 16) {
    R(0);
    R(1);
    R(2);
    R(3);
    R(4);
    R(5);
    R(6);
    R(7);
    R(8);
    R(9);
    R(10);
    R(11);
    R(12);
    R(13);
    R(14);
    R(15);
  }
#ifdef CRYPTOTEST2
  LOG(INFO)<<"W:  ";
  printW(W, 16);
#endif
  state_[0] += a(0);
  state_[1] += b(0);
  state_[2] += c(0);
  state_[3] += d(0);
  state_[4] += e(0);
  state_[5] += f(0);
  state_[6] += g(0);
  state_[7] += h(0);
#ifdef CRYPTOTEST2
  LOG(INFO)<<"Transform out: ";
  printW(state_, 8);
#endif
  memset(W, 0, sizeof(W));
  memset(T, 0, sizeof(T));
}

void Sha256::Update(const byte* data, int size)
    // size in bytes
    {
  const byte* next_block = data;
  int processed = 0;
  int left = size;
  int n;

  // partial block?
  if (partial_block_length_ > 0) {
    if (left < (SHA256_BLOCKSIZE_BYTES - partial_block_length_)) {
      memcpy(&current_block_[partial_block_length_], data, left);
      partial_block_length_ += left;
      return;
    }
    n = SHA256_BLOCKSIZE_BYTES - partial_block_length_;
    memcpy(&current_block_[partial_block_length_], next_block, n);
#ifdef LITTLE_ENDIAN
    LittleEndian(current_block_, SHA256_BLOCKSIZE_BYTES);
#endif
    Transform(state_, (u32*)current_block_);
    partial_block_length_ = 0;
    left -= n;
    next_block += n;
    processed += SHA256_BLOCKSIZE_BYTES;
  }

  while (left >= SHA256_BLOCKSIZE_BYTES) {
    memcpy(current_block_, next_block, SHA256_BLOCKSIZE_BYTES);
#ifdef LITTLE_ENDIAN
    LittleEndian(current_block_, SHA256_BLOCKSIZE_BYTES);
#endif
    // Transform each 512 bit block
    Transform(state_, (u32*)current_block_);
    left -= SHA256_BLOCKSIZE_BYTES;
    next_block += SHA256_BLOCKSIZE_BYTES;
    processed += SHA256_BLOCKSIZE_BYTES;
  }

  // save any partial 512 bit block
  if (left > 0) {
    memcpy(current_block_, next_block, left);
    partial_block_length_ = left;
  }
  total_processed_length_ += processed;
}

/*
 *  length is l bits.  Append the bit “1” followed by k zero bits, 
 *  where k is the smallest, non-negative solution to the 
 *  l + 1 + k ≡ 448 mod 512. Then append 64-bit value of l
 */
void Sha256::Final() {
  int n;

  if (partial_block_length_ > 0) total_processed_length_ += partial_block_length_;
  // append 1
  current_block_[partial_block_length_++] = 0x80;

  // zero fill if no room for size
  if ((SHA256_BLOCKSIZE_BYTES - partial_block_length_) < (int)sizeof(u64)) {
    memset(&current_block_[partial_block_length_], 0, SHA256_BLOCKSIZE_BYTES - partial_block_length_);
    partial_block_length_ = SHA256_BLOCKSIZE_BYTES;
#ifdef LITTLE_ENDIAN
    LittleEndian(current_block_, SHA256_BLOCKSIZE_BYTES);
#endif
    Transform(state_, (u32*)current_block_);
    partial_block_length_ = 0;
  }

  // Final Block
  total_processed_length_ *= 8ULL;  // length is in bits for padding
  n = SHA256_BLOCKSIZE_BYTES - partial_block_length_;
  memset(&current_block_[partial_block_length_], 0, n);
  memcpy(&current_block_[56], ((byte*)&total_processed_length_) + sizeof(u32), sizeof(u32));
  memcpy(&current_block_[60], (byte*)&total_processed_length_,
         sizeof(u32));  // final 8 already little Endian
#ifdef LITTLE_ENDIAN
  LittleEndian(current_block_, SHA256_BLOCKSIZE_BYTES - sizeof(u64));
#endif
  Transform(state_, (u32*)current_block_);
  partial_block_length_ = 0;

  memcpy(final_hash_, state_, SHA256_DIGESTSIZE_BYTES);
}

void Sha256::GetDigest(byte* rgHash) {
  memcpy(rgHash, final_hash_, SHA256_DIGESTSIZE_BYTES);
#ifndef FAKESHA256
#ifdef LITTLE_ENDIAN
  LittleEndian(rgHash, SHA256_DIGESTSIZE_BYTES);
#endif
#endif
}

// -----------------------------------------------------------------------------------
