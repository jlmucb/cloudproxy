//  File: verify_pub_key.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An app that verifies a signed public key file as used
//  by CloudClient
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

#include <fstream>
#include <memory>
#include <sstream>
#include <streambuf>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <google/protobuf/text_format.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/stl_util-inl.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_file_reader.h>

#include "cloudproxy/cloud_user_manager.h"
#include "cloudproxy/cloudproxy.pb.h"
#include "tao/keys.h"
#include "tao/util.h"

using std::ifstream;
using std::ofstream;
using std::string;
using std::stringstream;
using std::unique_ptr;

using cloudproxy::CloudUserManager;
using tao::VerifySignature;

DEFINE_string(signed_pub_key_file, "keys/tmroeder_pub_signed",
              "The name of the signature file");
DEFINE_string(key_loc, "./policy_public_key", "The location of the public key");

int main(int argc, char** argv) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  google::ParseCommandLineFlags(&argc, &argv, true);

  // load the signature
  ifstream sig(FLAGS_signed_pub_key_file.c_str());
  cloudproxy::SignedSpeaksFor ssf;
  ssf.ParseFromIstream(&sig);

  // get the public key for verification
  scoped_ptr<keyczar::Verifier> verifier(
      keyczar::Verifier::Read(FLAGS_key_loc.c_str()));
  CHECK(verifier.get()) << "Could not get the public key for verification";

  verifier->set_encoding(keyczar::Verifier::NO_ENCODING);

  CHECK(VerifySignature(ssf.serialized_speaks_for(),
                        CloudUserManager::SpeaksForSigningContext,
                        ssf.signature(), verifier.get())) << "Verify failed";

  LOG(INFO) << FLAGS_signed_pub_key_file << " contained a valid signature "
            << " under public key in " << FLAGS_key_loc;

  string text;
  cloudproxy::SpeaksFor sf;
  sf.ParseFromString(ssf.serialized_speaks_for());
  google::protobuf::TextFormat::PrintToString(sf, &text);
  LOG(INFO) << "The SpeaksFor says: " << text;
  return 0;
}
