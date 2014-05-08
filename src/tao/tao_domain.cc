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
#include <keyczar/base/base64w.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base/json_reader.h>
#include <keyczar/base/json_writer.h>
#include <keyczar/base/values.h>
#include <keyczar/keyczar.h>

#include "tao/acl_guard.h"
#include "tao/attestation.h"
#include "tao/attestation.pb.h"
#include "tao/keys.pb.h"
#include "tao/process_factory.h"
#include "tao/util.h"

using std::list;
using std::string;

using keyczar::base::CreateDirectory;
using keyczar::base::JSONReader;
using keyczar::base::JSONWriter;
using keyczar::base::ReadFileToString;
using keyczar::base::WriteStringToFile;

namespace tao {

TaoDomain::TaoDomain(const string &path, DictionaryValue *value)
    : path_(path), config_(value) {
  string keys_path = GetConfigPath(JSONPolicyKeysPath);
  keys_.reset(new Keys(keys_path, "policy", Keys::Signing));
}

TaoDomain::~TaoDomain() {}

TaoDomain *TaoDomain::CreateImpl(const string &config, const string &path) {
  // Parse the config string.
  string error;
  scoped_ptr<Value> value(JSONReader::ReadAndReturnError(config, true, &error));
  if (value.get() == nullptr) {
    LOG(ERROR) << path << ": error: " << error;
    return nullptr;
  }

  // Cast it to dictionary.
  if (!value->IsType(Value::TYPE_DICTIONARY)) {
    LOG(ERROR) << path << ": wrong JSON type, expecting dictionary";
    return nullptr;
  }
  scoped_ptr<DictionaryValue> dict(
      static_cast<DictionaryValue *>(value.release()));

  // Construct an object of the appropriate subclass.
  string guard_type;
  if (!dict->GetString(JSONAuthType, &guard_type)) {
    LOG(ERROR) << path << ": missing value for " << JSONAuthType;
    return nullptr;
  }
  scoped_ptr<TaoDomain> admin;
  if (guard_type == ACLGuard::GuardType) {
    admin.reset(new ACLGuard(path, dict.release()));
    // } else if (guard_type == RootAuth::AuthType) {
    //    admin.reset(new RootAuth(path, dict.release()));
  } else {
    LOG(ERROR) << path << ": unrecognized " << JSONAuthType << " "
               << guard_type;
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

  scoped_ptr<TaoDomain> admin(CreateImpl(initial_config, path));
  if (admin.get() == nullptr) {
    LOG(ERROR) << "Can't create TaoDomain";
    return nullptr;
  }

  if (!admin->keys_->InitNonHosted(password)) {
    LOG(ERROR) << "Can't create policy keys";
    return nullptr;
  }

  if (!admin->keys_->CreateSelfSignedX509(admin->GetPolicyX509Details())) {
    LOG(ERROR) << "Could not create self-signed x509 for policy key";
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
  string json;
  if (!ReadFileToString(path, &json)) {
    LOG(ERROR) << "Can't read configuration from " << path;
    return nullptr;
  }
  scoped_ptr<TaoDomain> admin(CreateImpl(json, path));
  if (admin.get() == nullptr) {
    LOG(ERROR) << "Can't create TaoDomain";
    return nullptr;
  }
  if (!admin->keys_->InitNonHosted(password)) {
    LOG(ERROR) << "Can't initialize TaoDomain keys";
    return nullptr;
  }
  if (!admin->ParseConfig()) {
    LOG(ERROR) << "Can't parse configuration file";
    return nullptr;
  }
  return admin.release();
}

TaoDomain *TaoDomain::DeepCopy() {
  scoped_ptr<TaoDomain> other(Load(path_));
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
  string json;
  JSONWriter::Write(config_.get(), true, &json);
  if (!WriteStringToFile(path_, json)) {
    LOG(ERROR) << "Can't write configuration to " << path_;
    return false;
  }
  return true;
}

int TaoDomain::GetFreshX509CertificateSerialNumber() {
  // TODO(kwalsh) thread safety; also, add integrity and reply protection.
  int ver = 0;
  config_->GetInteger(JSONPolicyX509LastSerial, &ver);
  ver++;
  string json;
  if (!config_->SetInteger(JSONPolicyX509LastSerial, ver)) {
    LOG(ERROR) << "Could not save x509 version number";
    return -1;
  }
  JSONWriter::Write(config_.get(), true, &json);
  if (!WriteStringToFile(path_, json)) {
    LOG(ERROR) << "Could not save x509 version number";
    return -1;
  }
  return ver;
}

string TaoDomain::GetConfigString(const string &name) const {
  string value = "";
  if (!config_->GetString(name, &value))
    LOG(WARNING) << "Can't find configuration parameter " << name;
  return value;
}

bool TaoDomain::AttestKeyNameBinding(const string &key_prin,
                                     const string &subprin,
                                     string *attestation) const {
  if (keys_->Signer() == nullptr) {
    LOG(ERROR) << "Can't sign attestation, admin is currently locked";
    return false;
  }
  string name;
  if (!keys_->SignerPrincipalName(&name)) {
    LOG(ERROR) << "Can't get unique ID for policy key";
    return false;
  }
  name += "::" + subprin;
  string empty_delegation = "";
  return tao::AttestKeyNameBinding(*keys_, empty_delegation, key_prin, name,
                                   attestation);
}

bool TaoDomain::AuthorizeProgramToExecute(const string &path,
                                          const list<string> &args) {
  string subprin;
  ProcessFactory pf;
  if (!pf.GetHostedProgramTentativeName(0 /* elide id */, path, args,
                                        &subprin)) {
    LOG(ERROR) << "Can't compute tentative name for program: " << path;
    return false;
  }
  string name;
  if (!keys_->SignerPrincipalName(&name)) {
    LOG(ERROR) << "Can't get unique ID for policy key";
    return false;
  }
  name += "::TrustedOS::" + subprin;
  return Authorize(name, "Execute", list<string>{});
}

bool TaoDomain::IsAuthorizedToExecute(const string &name) {
  return IsAuthorized(name, "Execute", list<string>{});
}

bool TaoDomain::AuthorizeNickname(const string &name, const string &subprin) {
  return Authorize(name, "ClaimName", list<string>{"::" + subprin});
}

bool TaoDomain::IsAuthorizedNickname(const string &name,
                                     const string &subprin) {
  return IsAuthorized(name, "ClaimName", list<string>{"::" + subprin});
}

}  // namespace tao
