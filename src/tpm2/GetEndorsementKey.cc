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
// File: GetEndorsementKey.cc


// Calling sequence
//   GetEndorsementKey.exe --endorsement_info_file=output-file

using std::string;

// This program creates endorsement key and produces a file containing
//   a protobuf consisting of:
//      a. Algorithm name (string) RSA
//      b. TPM flags
//      c. Date
//      d. Algorithm dependent simplified parameters
//         (i) For RSA:
//             modulus size in bits
//             modulus (most significant byte first)
//             exponent

DEFINE_string(endorsement_info_file, "", "output file");

#ifndef GFLAGS_NS
#define GFLAGS_NS gflags
#endif

void PrintOptions() {
  printf("Calling sequence: GetEndorsementKey.exe --endorsement_info_file=output-file\n");
}

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

