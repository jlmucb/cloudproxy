//  File: linux_tao.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An implementation of the Tao for the Linux
//  operating system.
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
#include "tao/linux_tao.h"

#include <list>
#include <mutex>

#include <glog/logging.h>
#include <keyczar/base/base64w.h>
#include <keyczar/base/file_path.h>
#include <keyczar/base/file_util.h>
#include <keyczar/keyczar.h>

#include "tao/attestation.pb.h"
#include "tao/hosted_program_factory.h"
#include "tao/hosted_programs.pb.h"
#include "tao/keyczar_public_key.pb.h"
#include "tao/sealed_data.pb.h"
#include "tao/tao_auth.h"
#include "tao/tao_channel.h"
#include "tao/tao_child_channel.h"
#include "tao/util.h"

using std::lock_guard;
using std::mutex;

using keyczar::base::Base64WEncode;
using keyczar::base::ReadFileToString;
using keyczar::base::WriteStringToFile;

namespace tao {

bool LinuxTao::Init() {
  // initialize the host channel
  if (!host_channel_->Init()) {
    LOG(ERROR) << "Could not initialize the host channel";
    return false;
  }
  if (!keys_->InitHosted(*host_channel_)) {
    LOG(ERROR) << "Could not initialize keys";
    return false;
  }
  if (keys_->HasFreshKeys() && !admin_->GetTaoCAHost().empty()) {
    if (!GetTaoCAAttestation()) {
      LOG(ERROR) << "Could not trade self-signed for Tao CA attestation";
      return false;
    }
  }
  if (!ReadFileToString(keys_->AttestationPath(), &attestation_)) {
    LOG(ERROR) << "Could not load attestation for signing key";
    return false;
  }
  VLOG(1) << "LinuxTao: Initialization finished successfully";
  return true;
}

bool LinuxTao::StartHostedProgram(const string &path, const list<string> &args,
                                  string *identifier) {
  string child_hash;
  string child_name = FilePath(path).BaseName().value();
  if (!program_factory_->HashHostedProgram(path, args, &child_hash)) {
    LOG(ERROR) << "Could not hash the hosted program";
    return false;
  }

  {
    lock_guard<mutex> l(auth_m_);
    // TODO(kwalsh) hash alg should come from ProgramFactory::HashHostedProgram
    if (!admin_->IsAuthorized(child_hash, TaoAuth::Sha256, child_name)) {
      LOG(ERROR) << "Program " << path << " with digest " << child_hash
                 << " is not authorized";
      return false;
    }
  }

  VLOG(2) << "The program " << path << " with digest " << child_hash
          << " is authorized";

  {
    lock_guard<mutex> l(data_m_);
    auto child_it = running_children_.find(child_hash);
    if (running_children_.end() != child_it) {
      LOG(ERROR) << "An instance of the program " << path << " with digest "
                 << child_hash << " is already running";
      return false;
    }

    running_children_.insert(child_hash);
  }

  string child_params;
  if (!child_channel_->AddChildChannel(child_hash, &child_params)) {
    LOG(ERROR) << "Could not add a channel to connect to a child with hash "
               << child_hash;
    return false;
  }

  list<string> program_args(args.begin(), args.end());

  // The convention is that the arguments are Base64W encoded as the last
  // argument in the list. The factory chooses how to handle the params.
  string encoded_params;
  if (!Base64WEncode(child_params, &encoded_params)) {
    LOG(ERROR) << "Could not encode the child params for the program";
    return false;
  }

  program_args.push_back(encoded_params);

  if (!program_factory_->CreateHostedProgram(path, program_args, child_hash,
                                             *child_channel_, identifier)) {
    LOG(ERROR) << "Could not start the hosted program";
    return false;
  }

  return true;
}

bool LinuxTao::RemoveHostedProgram(const string &child_hash) {
  {
    lock_guard<mutex> l(data_m_);
    auto child_it = running_children_.find(child_hash);
    if (running_children_.end() == child_it) {
      LOG(ERROR) << "An instance of the program  with digest " << child_hash
                 << " is not running";
      return false;
    }

    running_children_.erase(child_it);
  }

  return true;
}

bool LinuxTao::GetRandomBytes(size_t size, string *bytes) const {
  // just ask keyczar for random bytes, which will ask OpenSSL in turn
  if (!host_channel_->GetRandomBytes(size, bytes)) {
    LOG(ERROR) << "Could not generate random bytes";
    return false;
  }

  return true;
}

bool LinuxTao::Seal(const string &child_hash, const string &data,
                    string *sealed) const {
  {
    lock_guard<mutex> l(data_m_);
    auto child_it = running_children_.find(child_hash);
    if (running_children_.end() == child_it) {
      LOG(ERROR) << "The program with digest " << child_hash << " was not a "
                 << "program that was executing";
      return false;
    }
  }

  SealedData sd;
  sd.set_hash(child_hash);

  // TODO(tmroeder): generalize to other hash algorithms
  sd.set_hash_alg(TaoAuth::Sha256);
  sd.set_data(data);

  string serialized_sd;
  if (!sd.SerializeToString(&serialized_sd)) {
    LOG(ERROR) << "Could not serialize the SealedData";
    return false;
  }

  // encrypt it using our symmetric key
  if (!keys_->Crypter()->Encrypt(serialized_sd, sealed)) {
    LOG(ERROR) << "Could not seal the data";
    return false;
  }

  return true;
}

bool LinuxTao::Unseal(const string &child_hash, const string &sealed,
                      string *data) const {
  {
    lock_guard<mutex> l(data_m_);
    auto child_it = running_children_.find(child_hash);
    if (running_children_.end() == child_it) {
      LOG(ERROR) << "The program with digest " << child_hash << " was not a "
                 << "program that was executing";
      return false;
    }
  }

  // decrypt it using our symmetric key
  string temp_decrypted;
  if (!keys_->Crypter()->Decrypt(sealed, &temp_decrypted)) {
    LOG(ERROR) << "Could not decrypt the sealed data";
    return false;
  }

  // try to parse it as SealedData, and check the hash to make sure it matches
  SealedData sd;
  if (!sd.ParseFromString(temp_decrypted)) {
    // note that this is safe, since we always use authenticated encryption
    LOG(ERROR) << "Could not parse the decrypted data as SealedData";
    return false;
  }

  if (child_hash.compare(sd.hash()) != 0) {
    LOG(ERROR) << "This data was not sealed to this program";
    return false;
  }

  data->assign(sd.data().data(), sd.data().size());

  return true;
}

bool LinuxTao::Attest(const string &child_hash, const string &data,
                      string *attestation) const {
  {
    lock_guard<mutex> l(data_m_);
    auto child_it = running_children_.find(child_hash);
    if (running_children_.end() == child_it) {
      LOG(ERROR) << "The program with digest " << child_hash << " was not a "
                 << "program that was executing";
      return false;
    }
  }

  Statement s;
  s.set_data(data);
  s.set_hash_alg(TaoAuth::Sha256);
  s.set_hash(child_hash);

  return GenerateAttestation(keys_->Signer(), attestation_, &s, attestation);
}

bool LinuxTao::Listen() {
  // All the work of listening and calling the LinuxTao is done in the
  // TaoChannel implementation. See, e.g., PipeTaoChannel
  return child_channel_->Listen(this);
}

// TODO(kwalsh) Move this method to tao::Keys or some future TaoCA class
bool LinuxTao::GetTaoCAAttestation() {
  string serialized_attestation;
  if (!ReadFileToString(keys_->AttestationPath(), &serialized_attestation)) {
    LOG(ERROR) << "Could not load the self-signed attestation";
    return false;
  }
  Attestation attest;
  if (!attest.ParseFromString(serialized_attestation)) {
    LOG(ERROR) << "Could not deserialize the attestation to our key";
    return false;
  }
  string host = admin_->GetTaoCAHost();
  string port = admin_->GetTaoCAPort();
  ScopedFd sock(new int(-1));
  if (!ConnectToTCPServer(host, port, sock.get())) {
    LOG(ERROR) << "Could not connect to tcca";
    return false;
  }

  // The TCCA will convert our attestation into a new attestation signed by the
  // policy key.
  if (!tao::SendMessage(*sock, attest)) {
    LOG(ERROR) << "Could not send our attestation to the TCCA";
    return false;
  }

  Attestation new_attest;
  if (!tao::ReceiveMessage(*sock, &new_attest)) {
    LOG(ERROR) << "Could not get the new attestation from the TCCA";
    return false;
  }

  // Check the attestation to make sure it passes verification.
  if (new_attest.type() != ROOT) {
    LOG(ERROR) << "Expected a Root attestation from TCCA";
    return false;
  }

  string serialized;
  if (!new_attest.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the new attestation";
    return false;
  }

  string dummy_data;
  if (!admin_->VerifyAttestation(serialized, &dummy_data)) {
    LOG(ERROR) << "The attestation did not pass verification";
    return false;
  }

  if (new_attest.serialized_statement() !=
          attest.serialized_statement()) {
    LOG(ERROR) << "The statement in the new attestation doesn't match our "
                  "original statement";
    return false;
  }
  if (!new_attest.SerializeToString(&serialized_attestation)) {
    LOG(ERROR) << "Could not serialize the attestation for our signing key";
    return false;
  }
  if (!WriteStringToFile(keys_->AttestationPath(), serialized_attestation)) {
    LOG(ERROR) << "Could not store the attestation for our signing key";
    return false;
  }
  return true;
}
}  // namespace tao
