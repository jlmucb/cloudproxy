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

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/base/file_util.h>
#include <keyczar/keyczar.h>

#include "cloudproxy/cloud_user_manager.h"
#include "cloudproxy/cloudproxy.pb.h"
#include "tao/keyczar_public_key.pb.h"
#include "tao/keys.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using std::string;

using keyczar::base::WriteStringToFile;

using cloudproxy::CloudUserManager;
using cloudproxy::SignedSpeaksFor;
using cloudproxy::SpeaksFor;
using tao::Keys;
using tao::LoadVerifierKey;
using tao::SerializePublicKey;
using tao::SignData;
using tao::TaoDomain;

DEFINE_string(config_path, "tao.config", "Location of tao configuration");
DEFINE_string(policy_pass, "cppolicy", "A password for the policy private key");

DEFINE_string(subject, "tmroeder", "The subject to bind to this key");
DEFINE_string(pub_key_loc, "keys/tmroeder_pub",
              "The directory containing this public key");
DEFINE_string(signed_speaks_for, "keys/tmroeder_pub_signed",
              "The location to write the SignedSpeaksFor file");

int main(int argc, char **argv) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;
  google::ParseCommandLineFlags(&argc, &argv, true);
  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);
  google::InstallFailureSignalHandler();

  scoped_ptr<keyczar::Verifier> key;
  CHECK(LoadVerifierKey(FLAGS_pub_key_loc, &key)) << "Could not load key from "
                                                  << FLAGS_pub_key_loc;
  string pub_key;
  CHECK(SerializePublicKey(*key, &pub_key))
      << "Could not serialize the key";

  scoped_ptr<TaoDomain> admin(TaoDomain::Load(FLAGS_config_path, FLAGS_policy_pass));
  CHECK(admin.get() != nullptr) << "Could not load configuration";

  SpeaksFor sf;
  sf.set_subject(FLAGS_subject);
  sf.set_pub_key(pub_key);
  string sf_serialized;
  CHECK(sf.SerializeToString(&sf_serialized))
      << "Could not serialize delegation";

  string sig;
  CHECK(SignData(sf_serialized, CloudUserManager::SpeaksForSigningContext, &sig,
                 admin->GetPolicySigner())) << "Could not sign delegation";

  cloudproxy::SignedSpeaksFor ssf;
  ssf.set_serialized_speaks_for(sf_serialized);
  ssf.set_signature(sig);

  string serialized;
  CHECK(ssf.SerializeToString(&serialized)) << "Could not serialize the"
                                               " signed delegation";

  if (!WriteStringToFile(FLAGS_signed_speaks_for, serialized)) {
    LOG(ERROR) << "Could not write signed delegation to "
               << FLAGS_signed_speaks_for;
    return 1;
  }

  return 0;
}
