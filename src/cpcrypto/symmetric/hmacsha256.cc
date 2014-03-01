//  File: hmacsha256.cpp
//  Description: hmac sha256 and prf_sha256
//
//  Copyright (c) 2012, John Manferdelli.  All rights reserved.
//      Some contributions (c) Intel Corporation
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

#include <stdlib.h>
#include "aesni.h"
#include "sha256.h"
#include "hmacsha256.h"

// ------------------------------------------------------------------------------------

hmacsha256::hmacsha256() {
  memset(in_pad_, 0, SHA256_DIGESTSIZE_BYTES);
  memset(out_pad_, 0, SHA256_DIGESTSIZE_BYTES);
  memset(new_key_, 0, SHA256_DIGESTSIZE_BYTES);
}

hmacsha256::~hmacsha256() {
  memset(new_key_, 0, SHA256_DIGESTSIZE_BYTES);
  memset(in_pad_, 0, SHA256_DIGESTSIZE_BYTES);
  memset(out_pad_, 0, SHA256_DIGESTSIZE_BYTES);
}

void hmacsha256::Init(byte* key, int key_len) {
  int i;
  int k = key_len;

  // if key is longer than SHA256_DIGESTSIZE_BYTES, make it key=SHA256(key)
  if (k > SHA256_DIGESTSIZE_BYTES) {
    local_hash_.Init();
    local_hash_.Update(key, key_len);
    local_hash_.Final();
    local_hash_.GetDigest(new_key_);
    k = SHA256_DIGESTSIZE_BYTES;
  } else {
    memcpy(new_key_, key, k);
    if (k < SHA256_DIGESTSIZE_BYTES) {
      memset(&new_key_[k], 0, SHA256_DIGESTSIZE_BYTES - k);
    }
  }

  for (i = 0; i < SHA256_DIGESTSIZE_BYTES; i++) {
    in_pad_[i] = 0x36 ^ new_key_[i];
    out_pad_[i] = 0x5c ^ new_key_[i];
  }

  // start inner hash
  local_hash_.Init();
  local_hash_.Update(in_pad_, SHA256_DIGESTSIZE_BYTES);

  return;
}

void hmacsha256::Update(const byte* message, int in_len) {
  local_hash_.Update(message, in_len);
  return;
}

void hmacsha256::Final(byte* digest) {
  byte inner_hash[SHA256_DIGESTSIZE_BYTES];

  memset(inner_hash, 0, SHA256_DIGESTSIZE_BYTES);

  // Finish inner hash
  local_hash_.Final();
  local_hash_.GetDigest(inner_hash);

  // Outer hash
  local_hash_.Init();
  local_hash_.Update(out_pad_, SHA256_DIGESTSIZE_BYTES);
  local_hash_.Update(inner_hash, SHA256_DIGESTSIZE_BYTES);
  local_hash_.Final();
  local_hash_.GetDigest(digest);

  return;
}

bool hmac_sha256(byte* message, int in_len, byte* key, int key_len,
                 byte* digest) {
  // hmac-sha256(msg)= Sha256((secret^opad)||Sha256((secret^ipad)||msg))
  hmacsha256 local_mac;

  local_mac.Init(key, key_len);
  local_mac.Update(message, in_len);
  local_mac.Final(digest);
  return true;
}

// ------------------------------------------------------------------------------------

/*
 *  PRF
 *      P_hash(s1, s2)= HMAC_hash(s1, A(1)+s2)+HMAC_hash(s1,
* A(2)+s2)+HMAC_hash(s1, A(3)+s2)+...
 *      PRF(secret, label, seed) = P_<hash>(secret, label+seed)
 *
 *                ipad = the byte 0x36 repeated B times
 *                opad = the byte 0x5C repeated B times.
 *
 *      To compute HMAC over the data `text' we perform
 *
 *                  H(K XOR opad, H(K XOR ipad, text))
 *
 *      Namely,
 *          (1) append zeros to the end of K to create a B byte string
 *              (e.g., if K is of length 20 bytes and B=64, then K will be
 *              appended with 44 zero bytes 0x00)
 *          (2) XOR (bitwise exclusive-OR) the B byte string computed in step
 *              (1) with ipad
 *          (3) append the stream of data 'text' to the B byte string resulting
 *              from step (2)
 *          (4) apply H to the stream generated in step (3)
 *          (5) XOR (bitwise exclusive-OR) the B byte string computed in
 *              step (1) with opad
 *          (6) append the H result from step (4) to the B byte string
 *              resulting from step (5)
 *          (7) apply H to the stream generated in step (6) and output
 *              the result
 */

bool prf_SHA256(int key_len, byte* key, int seed_size, byte* seed,
                const char* label, int out_size, byte* out) {
    // A[0] = label||seed, A[i+1] = HMAC_hash(secret, A[i])
    // PRF(secret, label, seed) = HMAC_hash(key, A[0]||seed)||HMAC_hash(key,
    // A[1]||seed)...
    // For TLS, secret is master secret, seed is server_random||client_random
  byte* in_block = NULL;
  byte out_block[SHA256_DIGESTSIZE_BYTES];
  int label_size = strlen(label);
  int modified_size;

#ifdef TEST1
  LOF(INFO)<< "prf_SHA256 \n";
  PrintBytes("Key  ", key, key_len);
  PrintBytes("Seed ", seed, seed_size);
#endif

  modified_size = seed_size + SHA256_DIGESTSIZE_BYTES + label_size;
  in_block = (byte*)malloc(modified_size);
  if (out_block == NULL) return false;

  // first Block
  memcpy(in_block, label, label_size);
  memcpy(&in_block[label_size], seed, seed_size);
  hmac_sha256(in_block, label_size + seed_size, key, key_len, out_block);  // A[0]

  // keys
  int left_to_process = out_size;
  memcpy(&in_block[SHA256_DIGESTSIZE_BYTES], seed, seed_size);
  while (left_to_process > 0) {
    memcpy(in_block, out_block, SHA256_DIGESTSIZE_BYTES);
    hmac_sha256(in_block, SHA256_DIGESTSIZE_BYTES + seed_size, key, key_len,
                out_block);
    if (left_to_process < SHA256_DIGESTSIZE_BYTES)
      memcpy(out, out_block, left_to_process);
    else
      memcpy(out, out_block, SHA256_DIGESTSIZE_BYTES);
    out += SHA256_DIGESTSIZE_BYTES;
    left_to_process -= SHA256_DIGESTSIZE_BYTES;
  }

  free(in_block);
  return true;
}

// ------------------------------------------------------------------------------------
