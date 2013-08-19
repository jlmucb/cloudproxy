//  File: sign_pub_key.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An app that signs a public key for a given user of
//  CloudClient
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



#include <string>
#include <fstream>
#include <streambuf>
#include <sstream>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/stl_util-inl.h>
#include <keyczar/rw/keyset_file_reader.h>

#include "cloudproxy/cloudproxy.pb.h"

using std::string;
using std::stringstream;
using std::ifstream;
using std::ofstream;

DEFINE_string(subject, "tmroeder", "The subject to bind to this key");
DEFINE_string(pub_key_file, "keys/tmroeder_pub/1",
              "The name of the pub key file");
DEFINE_string(meta_file, "keys/tmroeder_pub/meta", "The name of the meta file");
DEFINE_string(key_loc, "./policy_key", "The location of the private key");
DEFINE_string(pass, "cppolicy", "The password to use for this private key");
DEFINE_string(signed_speaks_for, "keys/tmroeder_pub_signed",
              "The location to write the SignedSpeaksFor file");

int main(int argc, char** argv) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  google::ParseCommandLineFlags(&argc, &argv, true);

  // load the pub key file
  ifstream pk(FLAGS_pub_key_file.c_str());
  stringstream pk_buf;
  pk_buf << pk.rdbuf();

  // load the meta file
  ifstream meta(FLAGS_meta_file.c_str());
  stringstream meta_buf;
  meta_buf << meta.rdbuf();

  // decrypt the private policy key so we can construct a signer
  keyczar::base::ScopedSafeString password(new string(FLAGS_pass));
  scoped_ptr<keyczar::rw::KeysetReader> reader(
      new keyczar::rw::KeysetPBEJSONFileReader(FLAGS_key_loc.c_str(),
                                               *password));

  // sign this serialized data with the keyset in FLAGS_key_loc
  scoped_ptr<keyczar::Keyczar> signer(keyczar::Signer::Read(*reader));
  CHECK(signer.get()) << "Could not initialize the signer from "
                      << FLAGS_key_loc;
  signer->set_encoding(keyczar::Keyczar::NO_ENCODING);

  cloudproxy::SpeaksFor sf;
  sf.set_subject(FLAGS_subject);
  sf.set_pub_key(pk_buf.str());
  sf.set_meta(meta_buf.str());

  string sf_serialized;
  CHECK(sf.SerializeToString(&sf_serialized)) << "Could not serialize"
                                                 " the key";

  // print out the length of the string representation of the acl file
  string sig;
  CHECK(signer->Sign(sf_serialized, &sig)) << "Could not sign key";

  cloudproxy::SignedSpeaksFor ssf;
  ssf.set_serialized_speaks_for(sf_serialized);
  ssf.set_signature(sig);

  string serialized;
  CHECK(ssf.SerializeToString(&serialized)) << "Could not serialize the"
                                               " signed SpeaksFor";

  ofstream sig_file(FLAGS_signed_speaks_for.c_str());
  sig_file.write(serialized.data(), serialized.length());
  return 0;
}
