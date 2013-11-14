//  File: hash_file.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An application that computes the Base64W SHA-256 hash
//  of a file
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

#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <keyczar/base/base64w.h>
#include <keyczar/crypto_factory.h>
#include <gflags/gflags.h>

#include <fstream>
#include <streambuf>
#include <sstream>
#include <string>

using std::ifstream;
using std::string;
using std::stringstream;

DEFINE_string(file, "", "The file to sign");

int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);

  CHECK(!FLAGS_file.empty()) << "Must specify a file";

  // get a fresh key that can be used for hashing
  keyczar::MessageDigestImpl *sha256 = keyczar::CryptoFactory::SHA256();

  ifstream file(FLAGS_file.c_str(), ifstream::in);
  stringstream file_buf;
  file_buf << file.rdbuf();

  string digest;
  CHECK(sha256->Digest(file_buf.str(), &digest))
      << "Could not compute a SHA-256 hash over the file " << FLAGS_file;

  string serializedBase64;
  CHECK(keyczar::base::Base64WEncode(digest, &serializedBase64))
      << " Could not encode the digest under base64w";
  LOG(INFO) << "Digest of file " << FLAGS_file << " was: " << serializedBase64;

  return 0;
}
