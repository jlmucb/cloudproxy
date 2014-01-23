//  File: attest_to_key.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Produces an attestation for a keyczar key
//
//  Copyright (c) 2014, Google Inc.  All rights reserved.
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
#include <sstream>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_file_reader.h>

#include "tao/attestation.pb.h"
#include "tao/tao.h"
#include "tao/util.h"

using keyczar::Keyczar;

using std::ifstream;
using std::ofstream;
using std::list;
using std::string;
using std::stringstream;

using tao::Attestation;
using tao::KeyczarPublicKey;
using tao::SerializePublicKey;
using tao::SignData;
using tao::Statement;
using tao::Tao;

DEFINE_string(key, "fake_key", "The path to the key to sign");
DEFINE_string(policy_key, "policy_key", "The path to the policy private key");
DEFINE_string(policy_pass, "cppolicy", "A password for the policy private key");
DEFINE_string(attest_file, "fake_key.attest",
    "The file to hold the attestation");

int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);

  const int AttestationTimeout = 31556926;
  // Get the public key to sign. 
  scoped_ptr<keyczar::rw::KeysetReader> pub_reader(
    new keyczar::rw::KeysetJSONFileReader(FLAGS_key));
  scoped_ptr<keyczar::Keyczar> pub_key(keyczar::Verifier::Read(*pub_reader));
  KeyczarPublicKey kpk;
  CHECK(SerializePublicKey(*pub_key, &kpk))
    << "Could not serialize the public key for signing";
  string serialized_pub_key;
  CHECK(kpk.SerializeToString(&serialized_pub_key))
    << "Could not serialize the key to a string";

  // Decrypt the private policy key so we can construct a signer.
  keyczar::base::ScopedSafeString password(new string(FLAGS_policy_pass));
  scoped_ptr<keyczar::rw::KeysetReader> reader(
      new keyczar::rw::KeysetPBEJSONFileReader(FLAGS_policy_key.c_str(),
                                               *password));

  // Sign this serialized data with the keyset in FLAGS_policy_key.
  scoped_ptr<keyczar::Keyczar> signer(keyczar::Signer::Read(*reader));
  CHECK(signer.get()) << "Could not initialize the signer from "
                      << FLAGS_policy_key;
  signer->set_encoding(keyczar::Keyczar::NO_ENCODING);

  Attestation a;
  Statement s;
  time_t cur_time;
  time(&cur_time);

  s.set_time(cur_time);
  s.set_expiration(cur_time + AttestationTimeout);
  s.set_data(serialized_pub_key);
  s.set_hash_alg("SHA256");
  s.set_hash("FAKE_PCRS");

  string serialized_statement;
  CHECK(s.SerializeToString(&serialized_statement)) << "Could not serialize";
  string sig;
  CHECK(SignData(serialized_statement, Tao::AttestationSigningContext, &sig,
                 signer.get())) << "Could not sign the key";

  // There's no cert, since this is signed by the root key
  a.set_type(tao::ROOT);
  a.set_serialized_statement(serialized_statement);
  a.set_signature(sig);

  ofstream attest_file(FLAGS_attest_file, ofstream::out);
  if (!attest_file) {
    LOG(ERROR) << "Could not open the attest file " << FLAGS_attest_file
               << " for writing";
    return 1;
  }

  CHECK(a.SerializeToOstream(&attest_file))
      << "Could not serialize the attestation to a file";
  return 0;
}
