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
// File: CloudproxySignProgramKey.cc


// This program reads a signed_program_public_key_request_file, verifies validity of the certificate and
//   the request and, if verified, outputs a file (the signed_program_key_cert_file) with a cert for the
//   proposed program key in accordance with the signing isnstructions.

// Calling sequence
//   CloudproxySignProgramKey.exe --program_private_key_file=input-file-name
//     --signing_instructions_file=input-file-name --signed_program_public_key_request_file=input-file-name
//     --signed_program_key_cert_file=output-file-name

using std::string;


#define CALLING_SEQUENCE "CloudproxySignProgramKey.exe" \
"--program_private_key_file=input-file-name" \
"--signing_instructions_file=input-file-name" \
"--signed_program_public_key_request_file=input-file-name" \
"--signed_program_key_cert_file=output-file-name\n"

void PrintOptions() {
  printf("Calling sequence: %s", CALLING_SEQUENCE);
}


DEFINE_string(program_private_key_file, "", "private key file name");
DEFINE_string(signing_instructions_file, "", "private key file name");
DEFINE_string(signed_program_public_key_request_file, "", "signed program public request file");
DEFINE_string(signed_program_key_cert_file, "", "signed program public cert file");

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

