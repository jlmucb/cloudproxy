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

#include <dirent.h>
#include <stdlib.h>
#include <errno.h>

#include <string>
#include <fstream>
#include <streambuf>
#include <sstream>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/stl_util-inl.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_file_reader.h>

#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/cloud_user_manager.h"
#include "tao/keyczar_public_key.pb.h"
#include "tao/util.h"

using std::string;
using std::stringstream;
using std::ifstream;
using std::ofstream;
using std::ios;

using cloudproxy::CloudUserManager;
using cloudproxy::SpeaksFor;
using cloudproxy::SignedSpeaksFor;
using tao::KeyczarPublicKey;
using tao::SignData;

DEFINE_string(subject, "tmroeder", "The subject to bind to this key");
DEFINE_string(pub_key_loc, "keys/tmroeder_pub",
              "The directory containing this public key");
DEFINE_string(key_loc, "./policy_key", "The location of the private key");
DEFINE_string(pass, "cppolicy", "The password to use for this private key");
DEFINE_string(signed_speaks_for, "keys/tmroeder_pub_signed",
              "The location to write the SignedSpeaksFor file");

int main(int argc, char **argv) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  google::ParseCommandLineFlags(&argc, &argv, true);

  SpeaksFor sf;
  sf.set_subject(FLAGS_subject);
  KeyczarPublicKey kpk;

  // load the meta file
  string dir_name(FLAGS_pub_key_loc);
  string meta_file_name = dir_name + string("/meta");
  ifstream meta(meta_file_name.c_str());
  stringstream meta_buf;
  meta_buf << meta.rdbuf();

  kpk.set_metadata(meta_buf.str());

  DIR *dir = opendir(FLAGS_pub_key_loc.c_str());
  CHECK_NOTNULL(dir);

  struct dirent *d = readdir(dir);
  while (d != nullptr) {
    if (d->d_type == DT_REG) {
      string name(d->d_name);
      if (name.compare("meta") != 0) {
        // try to interpret this name as an integer
        errno = 0;
        long n = strtol(d->d_name, nullptr, 0);
        if (errno == 0) {
          // parse this data and add to the KeyczarPublicKey
          KeyczarPublicKey::KeyFile *kf = kpk.add_files();
          kf->set_name(n);
          stringstream file_name_stream;
          file_name_stream << dir_name << "/" << n;
          ifstream file(file_name_stream.str().c_str(),
                        ifstream::in | ios::binary);
          stringstream file_stream;
          file_stream << file.rdbuf();
          kf->set_data(file_stream.str());
        }
      }
    }

    d = readdir(dir);
  }

  string *mutable_pub_key = sf.mutable_pub_key();
  CHECK(kpk.SerializeToString(mutable_pub_key))
      << "Could not serialize the KeyczarPublicKey to a string";

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

  string sf_serialized;
  CHECK(sf.SerializeToString(&sf_serialized)) << "Could not serialize"
                                                 " the key";

  string sig;
  CHECK(SignData(sf_serialized, CloudUserManager::SpeaksForSigningContext, &sig,
                 signer.get())) << "Could not sign key";

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
