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
#include "tao/sealed_data.pb.h"
#include "tao/tao_auth.h"
#include "tao/tao_ca.h"
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
      LOG(ERROR) << "Could not trade intermediate for root attestation";
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
    if (!ignore_seal_hashes_for_testing_)
      return false;
    else
      LOG(ERROR) << "For test/debug purposes, seal hash error will be ignored";
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

  return GenerateAttestation(*keys_, attestation_, &s, attestation);
}

bool LinuxTao::Listen() {
  // All the work of listening and calling the LinuxTao is done in the
  // TaoChannel implementation. See, e.g., PipeTaoChannel
  return child_channel_->Listen(this);
}

bool LinuxTao::GetTaoCAAttestation() {
  // Use TaoCA to convert intermediate attestation into a root one.
  string intermediate_attestation;
  if (!ReadFileToString(keys_->AttestationPath(), &intermediate_attestation)) {
    LOG(ERROR) << "Could not load the intermediate attestation";
    return false;
  }
  TaoCA ca(admin_.get());
  string root_attestation;
  if (!ca.GetAttestation(intermediate_attestation, &root_attestation)) {
    LOG(ERROR) << "Could not get root attestation";
    return false;
  }
  if (!WriteStringToFile(keys_->AttestationPath(), root_attestation)) {
    LOG(ERROR) << "Could not store the root attestation";
    return false;
  }
  return true;
}
}  // namespace tao
