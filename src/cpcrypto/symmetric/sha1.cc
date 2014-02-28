//
//  File: sha1.cpp
//  Description: sha-1 implementation
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

#include "common.h"
#include "logging.h"
#include "sha1.h"
#include <string.h>

#ifdef TEST
#include <stdio.h>
#endif

// ----------------------------------------------------------------------------

void Sha1::littleEndian(byte* buf, int size) {
  byte* pU = buf;
  byte t;

  while (size >= (int)sizeof(u32)) {
    t = pU[0];
    pU[0] = pU[3];
    pU[3] = t;
    t = pU[1];
    pU[1] = pU[2];
    pU[2] = t;
    size -= sizeof(u32);
    pU += sizeof(u32);
  }
}

void Sha1::Init() {
  state_[0] = IV1;
  state_[1] = IV2;
  state_[2] = IV3;
  state_[3] = IV4;
  state_[4] = IV5;
  total_processed_length_ = 0ULL;
  partial_block_len_ = 0;
}

void Sha1::Update(const byte* data, const u32 long size) {
  const byte* next_block = data;
  int processed = 0;
  int left = size;
  int n;

  // partial block?
  if (partial_block_len_ > 0) {
    if (left < (BLOCKSIZE - partial_block_len_)) {
      memcpy(&current_block_[partial_block_len_], data, left);
      partial_block_len_ += left;
      return;
    }
    n = BLOCKSIZE - partial_block_len_;
    memcpy(&current_block_[partial_block_len_], next_block, n);
#ifdef LITTLE_ENDIAN
    littleEndian(current_block_, BLOCKSIZE);
#endif
    Transform((u32*)current_block_);
    partial_block_len_ = 0;
    left -= n;
    next_block += n;
    processed += BLOCKSIZE;
  }

  while (left > BLOCKSIZE) {
    memcpy(current_block_, next_block, BLOCKSIZE);
#ifdef LITTLE_ENDIAN
    littleEndian(current_block_, BLOCKSIZE);
#endif
    // Transform each 512 bit block
    Transform((u32*)current_block_);
    left -= BLOCKSIZE;
    next_block += BLOCKSIZE;
    processed += BLOCKSIZE;
  }

  // save any partial 512 bit block
  if (left > 0) {
    memcpy(current_block_, next_block, left);
    partial_block_len_ = left;
  }
  total_processed_length_ += processed;
}

void Sha1::Final() {
    //  length is l bits.  Append the bit “1” followed by k zero bits,
  int n;

  if (partial_block_len_ > 0) total_processed_length_ += partial_block_len_;

  // append 1
  current_block_[partial_block_len_++] = 0x80;

  // zero fill if no room for size
  if ((BLOCKSIZE - partial_block_len_) < (int)sizeof(u64)) {
    memset(&current_block_[partial_block_len_], 0, BLOCKSIZE - partial_block_len_);
    partial_block_len_ = BLOCKSIZE;
#ifdef LITTLE_ENDIAN
    littleEndian(current_block_, BLOCKSIZE);
#endif
    Transform((u32*)current_block_);
    partial_block_len_ = 0;
  }

  // Final Block
  total_processed_length_ *= 8ULL;  // length is in bits for padding
  n = BLOCKSIZE - partial_block_len_;
  memset(&current_block_[partial_block_len_], 0, n);
  memcpy(&current_block_[56], ((byte*)&total_processed_length_) + sizeof(u32), 
         sizeof(u32));
  memcpy(&current_block_[60], (byte*)&total_processed_length_, sizeof(u32));
#ifdef LITTLE_ENDIAN
  littleEndian(current_block_, BLOCKSIZE - 8);  // last 8 bytes already little endian
#endif
  Transform((u32*)current_block_);
  partial_block_len_ = 0;
}

void Sha1::getDigest(byte* out) {
  memcpy(out, (byte*)state_, DIGESTSIZE);
  littleEndian(out, DIGESTSIZE);
}

// ------------------------------------------------------------------------------

// Transform was derived in part from Wei Dai's Crypto++, downloadeha.cpp
//       on 4/1/2012 from http://www.cryptopp.com/.  The following applies:
// sha.cpp - modified by Wei Dai from Steve Reid's public domain sha1.c
// Steve Reid implemented SHA-1. Wei Dai implemented SHA-2.
// Both are in the public domain.

template <class T>
inline T rotrFixed(T x, u32 y) {
  return (x >> y) | (x << (sizeof(T) * 8 - y));
}

template <class T>
inline T rotlFixed(T x, u32 y) {
  return T((x << y) | (x >> (sizeof(T) * 8 - y)));
}

#define blk0(i) (W[i] = data[i])
#define blk1(i)           \
  (W[i & 15] = rotlFixed( \
       W[(i + 13) & 15] ^ W[(i + 8) & 15] ^ W[(i + 2) & 15] ^ W[i & 15], 1))

#define f1(x, y, z) (z ^ (x&(y ^ z)))
#define f2(x, y, z) (x ^ y ^ z)
#define f3(x, y, z) ((x& y) | (z&(x | y)))
#define f4(x, y, z) (x ^ y ^ z)

#define R0(v, w, x, y, z, i)                         \
  z += f1(w, x, y) + blk0(i) + K1 + rotlFixed(v, 5); \
  w = rotlFixed(w, 30);
#define R1(v, w, x, y, z, i)                         \
  z += f1(w, x, y) + blk1(i) + K1 + rotlFixed(v, 5); \
  w = rotlFixed(w, 30);
#define R2(v, w, x, y, z, i)                         \
  z += f2(w, x, y) + blk1(i) + K2 + rotlFixed(v, 5); \
  w = rotlFixed(w, 30);
#define R3(v, w, x, y, z, i)                         \
  z += f3(w, x, y) + blk1(i) + K3 + rotlFixed(v, 5); \
  w = rotlFixed(w, 30);
#define R4(v, w, x, y, z, i)                         \
  z += f4(w, x, y) + blk1(i) + K4 + rotlFixed(v, 5); \
  w = rotlFixed(w, 30);

bool Sha1::Transform(u32* data) {
  u32 W[16];

  u32 a = state_[0];
  u32 b = state_[1];
  u32 c = state_[2];
  u32 d = state_[3];
  u32 e = state_[4];

#ifdef CRYPTOTEST
  PrintBytes("Transform\n", (byte*)data, BLOCKSIZE);
#endif

  R0(a, b, c, d, e, 0);
  R0(e, a, b, c, d, 1);
  R0(d, e, a, b, c, 2);
  R0(c, d, e, a, b, 3);
  R0(b, c, d, e, a, 4);
  R0(a, b, c, d, e, 5);
  R0(e, a, b, c, d, 6);
  R0(d, e, a, b, c, 7);
  R0(c, d, e, a, b, 8);
  R0(b, c, d, e, a, 9);
  R0(a, b, c, d, e, 10);
  R0(e, a, b, c, d, 11);
  R0(d, e, a, b, c, 12);
  R0(c, d, e, a, b, 13);
  R0(b, c, d, e, a, 14);
  R0(a, b, c, d, e, 15);
  R1(e, a, b, c, d, 16);
  R1(d, e, a, b, c, 17);
  R1(c, d, e, a, b, 18);
  R1(b, c, d, e, a, 19);
  R2(a, b, c, d, e, 20);
  R2(e, a, b, c, d, 21);
  R2(d, e, a, b, c, 22);
  R2(c, d, e, a, b, 23);
  R2(b, c, d, e, a, 24);
  R2(a, b, c, d, e, 25);
  R2(e, a, b, c, d, 26);
  R2(d, e, a, b, c, 27);
  R2(c, d, e, a, b, 28);
  R2(b, c, d, e, a, 29);
  R2(a, b, c, d, e, 30);
  R2(e, a, b, c, d, 31);
  R2(d, e, a, b, c, 32);
  R2(c, d, e, a, b, 33);
  R2(b, c, d, e, a, 34);
  R2(a, b, c, d, e, 35);
  R2(e, a, b, c, d, 36);
  R2(d, e, a, b, c, 37);
  R2(c, d, e, a, b, 38);
  R2(b, c, d, e, a, 39);
  R3(a, b, c, d, e, 40);
  R3(e, a, b, c, d, 41);
  R3(d, e, a, b, c, 42);
  R3(c, d, e, a, b, 43);
  R3(b, c, d, e, a, 44);
  R3(a, b, c, d, e, 45);
  R3(e, a, b, c, d, 46);
  R3(d, e, a, b, c, 47);
  R3(c, d, e, a, b, 48);
  R3(b, c, d, e, a, 49);
  R3(a, b, c, d, e, 50);
  R3(e, a, b, c, d, 51);
  R3(d, e, a, b, c, 52);
  R3(c, d, e, a, b, 53);
  R3(b, c, d, e, a, 54);
  R3(a, b, c, d, e, 55);
  R3(e, a, b, c, d, 56);
  R3(d, e, a, b, c, 57);
  R3(c, d, e, a, b, 58);
  R3(b, c, d, e, a, 59);
  R4(a, b, c, d, e, 60);
  R4(e, a, b, c, d, 61);
  R4(d, e, a, b, c, 62);
  R4(c, d, e, a, b, 63);
  R4(b, c, d, e, a, 64);
  R4(a, b, c, d, e, 65);
  R4(e, a, b, c, d, 66);
  R4(d, e, a, b, c, 67);
  R4(c, d, e, a, b, 68);
  R4(b, c, d, e, a, 69);
  R4(a, b, c, d, e, 70);
  R4(e, a, b, c, d, 71);
  R4(d, e, a, b, c, 72);
  R4(c, d, e, a, b, 73);
  R4(b, c, d, e, a, 74);
  R4(a, b, c, d, e, 75);
  R4(e, a, b, c, d, 76);
  R4(d, e, a, b, c, 77);
  R4(c, d, e, a, b, 78);
  R4(b, c, d, e, a, 79);

  state_[0] += a;
  state_[1] += b;
  state_[2] += c;
  state_[3] += d;
  state_[4] += e;

  return true;
}

// --------------------------------------------------------------------------------
