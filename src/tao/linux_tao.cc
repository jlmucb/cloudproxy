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
#include <sstream>

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

  if (host_channel_->GetHostedProgramFullName(&full_name_)) {
    LOG(ERROR) << "Could not obtain our own name from host channel";
    return false;
  }

  last_child_id_ = 0;  // TODO(kwalsh) This should be persistent

  VLOG(1) << "LinuxTao: Initialization finished successfully";
  return true;
}

bool LinuxTao::StartHostedProgram(const string &path, const list<string> &args,
                                  string *child_name) {
  int id = last_child_id_ + 1;
  string tentative_name;
  if (!program_factory_->GetHostedProgramTentativeName(id, path, args,
                                                       &tentative_name)) {
    LOG(ERROR) << "Could not hash the hosted program and its arguments";
    return false;
  }

  {
    lock_guard<mutex> l(auth_m_);
    // TODO(kwalsh) hash alg should come from ProgramFactory::HashHostedProgram
    if (!admin_->IsAuthorized(full_name_ + "::" + tentative_name)) {
      LOG(ERROR) << tentative_name << " is not authorized to run on this Tao";
      return false;
    }
  }

  VLOG(2) << tentative_name << " is authorized to run on this Tao";

  string child_params;
  if (!child_channel_->AddChildChannel(tentative_name, &child_params)) {
    LOG(ERROR) << "Could not add a channel to connect to " << tentative_name;
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

  {
    lock_guard<mutex> l(data_m_);
    running_children_.insert(tentative_name);
  }

  if (!program_factory_->CreateHostedProgram(
          id, path, program_args, tentative_name, child_channel_.get(),
          child_name)) {
    LOG(ERROR) << "Could not start the hosted program";
    {
      lock_guard<mutex> l(data_m_);
      running_children_.erase(tentative_name);
    }
    return false;
  }

  last_child_id_++;
  return true;
}

bool LinuxTao::RemoveHostedProgram(const string &child_name) {
  {
    lock_guard<mutex> l(data_m_);
    auto child_it = running_children_.find(child_name);
    if (running_children_.end() == child_it) {
      LOG(ERROR) << child_name << " is not running";
      return false;
    }

    running_children_.erase(child_it);
  }

  return true;
}

bool LinuxTao::GetTaoFullName(string *tao_name) {
  tao_name->assign(full_name_);
  return true;
}

bool LinuxTao::GetRandomBytes(const string &child_name, size_t size,
                              string *bytes) const {
  // ask host Tao for random bytes
  if (!host_channel_->GetRandomBytes(size, bytes)) {
    LOG(ERROR) << "Could not generate random bytes";
    return false;
  }

  return true;
}

bool LinuxTao::Seal(const string &child_name, const string &data, int policy,
                    string *sealed) const {
  {
    lock_guard<mutex> l(data_m_);
    auto child_it = running_children_.find(child_name);
    if (running_children_.end() == child_it) {
      LOG(ERROR) << child_name << "is not executing";
      return false;
    }
  }

  LinuxTaoSealedData sd;

  // TODO(kwalsh) fix policy hack

  int child_id;
  string path, prog_hash, arg_hash, child_pid, subprin;
  if (!program_factory_->ParseChildName(child_name, &child_id, &path,
                                        &prog_hash, &arg_hash, &child_pid,
                                        &subprin)) {
    LOG(ERROR) << "Can't seal due to bad name.";
    return false;
  }

  if (policy & 1) sd.set_policy_id(child_id);
  if (policy & 2) sd.set_policy_prog_hash(prog_hash);
  if (policy & 4) sd.set_policy_arg_hash(arg_hash);
  if (policy & 8) sd.set_policy_pid(child_pid);
  if (policy & 16) sd.set_policy_subprin(subprin);

  sd.set_data(data);

  string serialized_sd;
  if (!sd.SerializeToString(&serialized_sd)) {
    LOG(ERROR) << "Could not serialize the data";
    return false;
  }

  if (!keys_->Crypter()->Encrypt(serialized_sd, sealed)) {
    LOG(ERROR) << "Could not seal the data";
    return false;
  }

  return true;
}

bool LinuxTao::Unseal(const string &child_name, const string &sealed,
                      string *data, int *policy) const {
  {
    lock_guard<mutex> l(data_m_);
    auto child_it = running_children_.find(child_name);
    if (running_children_.end() == child_it) {
      LOG(ERROR) << child_name << " is not executing";
      return false;
    }
  }

  int child_id;
  string path, prog_hash, arg_hash, child_pid, subprin;
  if (!program_factory_->ParseChildName(child_name, &child_id, &path,
                                        &prog_hash, &arg_hash, &child_pid,
                                        &subprin)) {
    LOG(ERROR) << "Can't unseal due to bad name.";
    return false;
  }

  // Decrypt it.
  string temp_decrypted;
  if (!keys_->Crypter()->Decrypt(sealed, &temp_decrypted)) {
    LOG(ERROR) << "Could not decrypt the sealed data";
    return false;
  }

  // Parse it.
  LinuxTaoSealedData sd;
  if (!sd.ParseFromString(temp_decrypted)) {
    // note that this is safe, since we always use authenticated encryption
    LOG(ERROR) << "Could not parse the decrypted data";
    return false;
  }

  // TODO(kwalsh) fix policy hack

  // Check the policy.
  int pol = 0;
  if (sd.has_policy_id()) pol |= 1;
  if (sd.has_policy_prog_hash()) pol |= 2;
  if (sd.has_policy_arg_hash()) pol |= 4;
  if (sd.has_policy_pid()) pol |= 8;
  if (sd.has_policy_subprin()) pol |= 16;

  bool denied = false;
  denied |= ((pol & 1) && sd.policy_id() != child_id);
  denied |= ((pol & 2) && sd.policy_prog_hash() != prog_hash);
  denied |= ((pol & 4) && sd.policy_arg_hash() != arg_hash);
  denied |= ((pol & 8) && sd.policy_pid() != child_pid);
  denied |= ((pol & 16) && sd.policy_subprin() != subprin);

  if (denied) {
    LOG(ERROR) << "Access denied";
    if (ignore_unseal_policy_for_testing_)
      LOG(ERROR) << "For test/debug purposes, unseal policy will be ignored";
    else
      return false;
  }

  data->assign(sd.data());
  *policy = pol;
  return true;
}

bool LinuxTao::Attest(const string &child_name, const string &data,
                      string *attestation) const {
  {
    lock_guard<mutex> l(data_m_);
    auto child_it = running_children_.find(child_name);
    if (running_children_.end() == child_it) {
      LOG(ERROR) << child_name << " was not executing";
      return false;
    }
  }

  Statement s;
  s.set_data(data);
  s.set_hash(full_name_ + "::" + child_name);  // TODO(kwalsh) should be name

  return GenerateAttestation(*keys_, attestation_, &s, attestation);
}

bool LinuxTao::ExtendName(string *child_name, const string &subprin) {
  // TODO(kwalsh) Check subprin name for format/reasonableness.
  string extended_name = *child_name + "::" + subprin;
  {
    lock_guard<mutex> l(data_m_);
    auto child_it = running_children_.find(*child_name);
    if (running_children_.end() == child_it) {
      LOG(ERROR) << *child_name << " was not executing";
      return false;
    }
    running_children_.erase(*child_name);
    running_children_.insert(extended_name);
  }

  child_name->assign(extended_name);
  return true;
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
