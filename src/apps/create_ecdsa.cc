//  File: create_ecdsa.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An app that creates an ECDSA key pair on disk
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <gflags/gflags.h>
#include <glog/logging.h>
#include "cloudproxy/util.h"

DEFINE_string(private_path, "private", "The name for the private key file");
DEFINE_string(public_path, "public", "The name for the X.509 certificate");
DEFINE_string(password, "password",
              "Password. Obviously, this is just for testing");
DEFINE_string(country_code, "US", "The country code");
DEFINE_string(org, "Google", "The organizational name");
DEFINE_string(cn, "tmroeder", "The common name (CN) to use for this key");

int main(int argc, char** argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  google::InitGoogleLogging(argv[0]);
  // initialize OpenSSL
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  SSL_library_init();
  CHECK(cloudproxy::CreateECDSAKey(
      FLAGS_private_path, FLAGS_public_path, FLAGS_password, FLAGS_country_code,
      FLAGS_org, FLAGS_cn)) << "Could not create the ECDSA key";
  return 0;
}
