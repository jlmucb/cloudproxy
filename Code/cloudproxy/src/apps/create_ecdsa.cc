//  File: create_ecdsa.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An app that creates an ECDSA key pair on disk
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
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

// ------------------------------------------------------------------------

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
  CHECK(cloudproxy::CreateECDSAKey(FLAGS_private_path, FLAGS_public_path, FLAGS_password,
                       FLAGS_country_code, FLAGS_org, FLAGS_cn))
      << "Could not create the ECDSA key";
  return 0;
}
