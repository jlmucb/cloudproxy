//  File: tao_domain.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Implementation of administrative methods for the Tao.
//
//  Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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
#include "tao/tao_domain.h"

#include <list>
#include <string>

#include <glog/logging.h>

#include "tao/acl_guard.h"
#include "tao/attestation.h"
#include "tao/datalog_guard.h"
#include "tao/util.h"

namespace tao {

TaoDomain::TaoDomain(const string &path, TaoDomainConfig *config)
    : path_(path), config_(config) {
  string keys_path = config_->policy_keys_path();
  keys_.reset(new Keys(keys_path, Keys::Signing));
}

TaoDomain::~TaoDomain() {}

TaoDomain *TaoDomain::CreateImpl(const string &config_text, const string &path) {
  // Parse the config string.
  unique_ptr<TaoDomainConfig> config(new TaoDomainConfig);
  if (!TextFormat::ParseFromString(confix_text, config)) {
    LOG(ERROR) << path << ": error parsing Tao Domain configuration";
    return nullptr;
  }
  // Construct an object of the appropriate subclass.
  string guard_type = config->guard_type();
  unique_ptr<TaoDomain> admin;
  if (guard_type == ACLGuard::GuardType) {
    admin.reset(new ACLGuard(path, config.release()));
  } else if (guard_type == DatalogGuard::GuardType) {
    admin.reset(new DatalogGuard(path, config.release()));
  } else {
    LOG(ERROR) << path << ": unrecognized guard type " << guard_type;
    return nullptr;
  }
  return admin.release();
}

TaoDomain *TaoDomain::Create(const string &initial_config, const string &path,
                             const string &password) {
  FilePath dir = FilePath(path).DirName();
  if (!CreateDirectory(dir)) {
    LOG(ERROR) << "Can't create directory " << dir.value();
    return nullptr;
  }

  unique_ptr<TaoDomain> admin(CreateImpl(initial_config, path));
  if (admin.get() == nullptr) {
    LOG(ERROR) << "Can't create TaoDomain";
    return nullptr;
  }

  if (!admin->keys_->InitWithPassword(password)) {
    LOG(ERROR) << "Can't create policy keys";
    return nullptr;
  }

  string x509 = admin->keys_->Signer()->CreateSelfSignedX509(
      admin->GetPolicyX509Details());
  if (x509 == "" || !admin->keys_->SetX509(x509)) {
    LOG(ERROR) << "Could not create self-signed x509 for policy key";
    return nullptr;
  }

  if (!admin->Init()) {
    LOG(ERROR) << "Could not initialize guard";
    return nullptr;
  }

  // Save the configuration. Since we did not ParseConfig(), this should save
  // some default auth data (e.g empty ACLs) as well.
  if (!admin->SaveConfig()) {
    LOG(ERROR) << "Could not save the configuration for " << path;
    return nullptr;
  }

  return admin.release();
}

TaoDomain *TaoDomain::Load(const string &path, const string &password) {
  string config_text;
  if (!ReadFileToString(path, &config_text)) {
    LOG(ERROR) << "Can't read configuration from " << path;
    return nullptr;
  }
  unique_ptr<TaoDomain> admin(CreateImpl(config_text, path));
  if (admin.get() == nullptr) {
    LOG(ERROR) << "Can't create TaoDomain";
    return nullptr;
  }
  if (!admin->keys_->InitWithPassword(password)) {
    LOG(ERROR) << "Can't initialize TaoDomain keys";
    return nullptr;
  }
  if (!admin->Init()) {
    LOG(ERROR) << "Could not initialize guard";
    return nullptr;
  }
  if (!admin->ParseConfig()) {
    LOG(ERROR) << "Can't parse configuration file";
    return nullptr;
  }
  return admin.release();
}

bool TaoDomain::GetSubprincipalName(string *subprin) const {
  // Use policy key and guard type as part of name
  string key_prin = GetPolicyVerifier()->ToPrincipalName();
  if (key_prin == "") {
    LOG(ERROR) << "Could not get policy key principal name";
    return false;
  }
  subprin->assign(GuardTypeName() + "(" + key_prin + ")");
  return true;
}

TaoDomain *TaoDomain::DeepCopy() {
  unique_ptr<TaoDomain> other(Load(path_));
  if (other.get() == nullptr) {
    LOG(ERROR) << "Can't reload TaoDomain configuration";
    return nullptr;
  }
  if (keys_->Signer() != nullptr) {
    other->keys_.reset(keys_->DeepCopy());
    if (other->keys_.get() == nullptr) {
      LOG(ERROR) << "Can't copy unlocked TaoDomain keys";
      return nullptr;
    }
  }
  return other.release();
}

string TaoDomain::GetPath(const string &suffix) const {
  return FilePath(path_).DirName().Append(suffix).value();
}

bool TaoDomain::SaveConfig() const {
  string config_text;
  if (!TextFormat::PrintToString(*config_, &config_text) ||
      !WriteStringToFile(path_, config_text)) {
    LOG(ERROR) << "Can't write configuration to " << path_;
    return false;
  }
  return true;
}

int TaoDomain::GetFreshX509CertificateSerialNumber() {
  // TODO(kwalsh) thread safety; also, add integrity and reply protection.
  int ver = config_->policy_x509_last_serial();
  ver++;
  config_->set_policy_x509_last_serial(ver);
  if (!TextFormat::PrintToString(*config_, &config_text) ||
      !WriteStringToFile(path_, config_text)) {
    LOG(ERROR) << "Could not save x509 version number";
    return -1;
  }
  return ver;
}

// bool TaoDomain::AttestKeyNameBinding(const string &key_prin,
//                                      const string &subprin,
//                                      string *attestation) const {
//   if (keys_->Signer() == nullptr) {
//     LOG(ERROR) << "Can't sign attestation, admin is currently locked";
//     return false;
//   }
//   string name;
//   if (!keys_->GetPrincipalName(&name)) {
//     LOG(ERROR) << "Can't get unique ID for policy key";
//     return false;
//   }
//   name += "::" + subprin;
//   string empty_delegation = "";
//   return tao::AttestKeyNameBinding(*keys_, empty_delegation, key_prin, name,
//                                    attestation);
// }
//
// bool TaoDomain::AuthorizeProgramToExecute(const string &path,
//                                           const list<string> &args) {
//   string subprin;
//   ProcessFactory pf;
//   if (!pf.GetHostedProgramTentativeName(0 /* elide id */, path, args,
//                                         &subprin)) {
//     LOG(ERROR) << "Can't compute tentative name for program: " << path;
//     return false;
//   }
//   string name;
//   if (!keys_->GetPrincipalName(&name)) {
//     LOG(ERROR) << "Can't get unique ID for policy key";
//     return false;
//   }
//   name += "::TrustedOS::" + subprin;
//   return Authorize(name, "Execute", list<string>{});
// }
//
// bool TaoDomain::IsAuthorizedToExecute(const string &name) {
//   return IsAuthorized(name, "Execute", list<string>{});
// }
//
// bool TaoDomain::AuthorizeNickname(const string &name, const string &subprin)
// {
//   return Authorize(name, "ClaimName", list<string>{"::" + subprin});
// }
//
// bool TaoDomain::IsAuthorizedNickname(const string &name,
//                                      const string &subprin) {
//   return IsAuthorized(name, "ClaimName", list<string>{"::" + subprin});
// }

}  // namespace tao
