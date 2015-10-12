#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

#include <tpm20.h>
#include <tpm2_lib.h>
#include <gflags/gflags.h>

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
// Portions of this code were derived tboot published
// by Intel under the license set forth in intel_license.txt
// and downloaded on or about August 6, 2015.
// Portions of this code were derived from the crypto utility
// published by John Manferdelli under the Apache 2.0 license.
// See github.com/jlmucb/crypto.
// File: ClientCreateInterimSigningKey.cc


//   This program creates a primary key and signingkey.  Produces the signed_interim_cert_request_file
//   which contains a protobuf consisting of the endorsement key certificate, and
//   a request signed by the signing key with the public portion of the signing key, the
//   the policy for MakeCredential to activate the key and the date/time.

// Calling sequence: ClientCreateInterimSigningKey.exe
//    --signed_endorsement_cert=input-file-name
//    --storage_key_type=RSA
//    --storage_key_size=2048
//    --signing_key_type=RSA
//    --signing_key_size=2048
//    --signing_key_namespace=name
//    --signing_key_primary_slot=int
//    --signing_key_signing_slot=int
//    --signed_interim_cert_request_file=output-file-name


using std::string;


#define CALLING_SEQUENCE 
" ClientCreateInterimSigningKey.exe \
--signed_endorsement_cert=input-file-name \
--storage_key_type=RSA \
--storage_key_size=2048 \
--signing_key_type=RSA \
--signing_key_size=2048 \
--signing_key_namespace=name \
--signing_key_primary_slot=int \
--signing_key_signing_slot=int \
--signed_interim_cert_request_file=output-file-name\n"

void PrintOptions() {
  printf("Calling sequence: " + CALLING_SEQUENCE);
}


DEFINE_string(signed_endorsement_cert, "", "input-file-name");
DEFINE_string(storage_key_type, "RSA", "storage key type");
DEFINE_int32(storage_key_size, 2048, "storage key type");
DEFINE_string(signing_key_type, "RSA", "signing key type");
DEFINE_int32(signing_key_size, 2048, "signing key type");
DEFINE_string(signing_key_namespace, "", "name");
DEFINE_int32(signing_key_primary_slot, 0, "slot number");
DEFINE_int32(signing_key_signing_slot, 1, "slot number");
DEFINE_string(signed_interim_cert_request_file, "", "output-file-name");

#ifndef GFLAGS_NS
#define GFLAGS_NS gflags
#endif

int main(int an, char** av) {
  LocalTpm tpm;

  GFLAGS_NS::ParseCommandLineFlags(&an, &av, true);
  if (!tpm.OpenTpm("/dev/tpm0")) {
    printf("Can't open tpm\n");
    return 1;
  }

done:
  tpm.CloseTpm();
}

