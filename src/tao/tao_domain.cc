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

#include <string>

#include <glog/logging.h>
#include <keyczar/base/base64w.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base/json_reader.h>
#include <keyczar/base/json_writer.h>
#include <keyczar/base/values.h>
#include <keyczar/keyczar.h>

#include "tao/root_auth.h"
#include "tao/util.h"
#include "tao/whitelist_auth.h"

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
  string auth_type;
  if (!dict->GetString(JSONAuthType, &auth_type)) {
    LOG(ERROR) << path << ": missing value for " << JSONAuthType;
    return nullptr;
  }
  scoped_ptr<TaoDomain> admin;
  if (auth_type == WhitelistAuth::AuthType) {
    admin.reset(new WhitelistAuth(path, dict.release()));
  } else if (auth_type == RootAuth::AuthType) {
    admin.reset(new RootAuth(path, dict.release()));
  } else {
    LOG(ERROR) << path << ": unrecognized " << JSONAuthType << " " << auth_type;
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

  if (!admin->keys_->CreateSelfSignedX509(admin->GetPolicyX509Country(),
                                          admin->GetPolicyX509State(),
                                          admin->GetPolicyX509Organization(),
                                          admin->GetPolicyX509CommonName())) {
    LOG(ERROR) << "Could not create self-signed x509 for policy key";
    return nullptr;
  }

  // Save the configuration. Since we did not ParseConfig(), this should save
  // any default (empty) whitelist as well.
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

string TaoDomain::GetConfigString(const string &name) const {
  string value = "";
  if (!config_->GetString(name, &value))
    LOG(WARNING) << "Can't find configuration parameter " << name;
  return value;
}

bool TaoDomain::AttestByRoot(Statement *s, Attestation *attestation) const {
  if (keys_->Signer() == nullptr) {
    LOG(ERROR) << "Can't sign attestation, admin is currently locked";
    return false;
  }
  string emptycert = "";  // empty cert because root
  if (!GenerateAttestation(keys_->Signer(), emptycert, s, attestation)) {
    LOG(ERROR) << "Can't sign attestation";
    return false;
  }
  return true;
}

bool TaoDomain::AttestByRoot(Statement *s, string *attestation) const {
  if (keys_->Signer() == nullptr) {
    LOG(ERROR) << "Can't sign attestation, admin is currently locked.";
    return false;
  }
  string emptycert = "";  // empty cert because root
  if (!GenerateAttestation(keys_->Signer(), emptycert, s, attestation)) {
    LOG(ERROR) << "Can't sign attestation";
    return false;
  }
  return true;
}

bool TaoDomain::CheckRootSignature(const Attestation &a) const {
  if (a.type() != ROOT) {
    LOG(ERROR) << "This is not a ROOT attestation, but it claims to be "
                  "signed with the policy public key";
    return false;
  }
  if (!VerifySignature(a.serialized_statement(), Tao::AttestationSigningContext,
                       a.signature(), keys_->Verifier())) {
    LOG(ERROR) << "Verification failed with the policy key";
    return false;
  }
  return true;
}

bool TaoDomain::AuthorizeProgram(const string &path) {
  string program_name = FilePath(path).BaseName().value();
  string program_sha;
  if (!Sha256FileHash(path, &program_sha)) {
    LOG(ERROR) << "Can't hash program";
    return false;
  }

  string program_hash;
  if (!keyczar::base::Base64WEncode(program_sha, &program_hash)) {
    LOG(ERROR) << "Can't encode hash value";
    return false;
  }

  return Authorize(program_hash, Sha256, program_name);
}

}  // namespace tao
