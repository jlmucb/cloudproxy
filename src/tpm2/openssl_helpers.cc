#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <tpm20.h>
#include <tpm2_lib.h>
#include <errno.h>

#include <tpm2.pb.h>
#include <openssl/rsa.h>

#include <string>
using std::string;

//
// Copyright 2015 Google Corporation, All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// or in the the file LICENSE-2.0.txt in the top level sourcedirectory
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
//
// Portions of this code were derived TPM2.0-TSS published
// by Intel under the license set forth in intel_license.txt
// and downloaded on or about August 6, 2015.
// File: openssl_helpers.cc

// standard buffer size
#define MAX_SIZE_PARAMS 4096

string* BN_to_base64(BIGNUM& n) {
  return nullptr;
}

bool FillPrivateKeyStructure(RSA& key, public_key_message* msg_key) {
  string* n = nullptr;
  string* e = nullptr;
  bool ret = true;

  n = BN_to_base64(*key.n);
  if (n == nullptr) {
    ret = false;
    goto done;
  }
  e = BN_to_base64(*key.e);
  if (e == nullptr) {
    ret = false;
    goto done;
  }
  msg_key->mutable_public_key()->set_modulus(*n);
  msg_key->mutable_public_key()->set_exponent(*e);

done:
  if (e != nullptr)
    delete e;
  if (n != nullptr)
    delete n;
  return ret;
}

