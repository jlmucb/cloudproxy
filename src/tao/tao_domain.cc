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

TaoDomain *TaoDomain::CreateImpl(const string &config, const string &path,
                                 const string &password) {
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
    admin.reset(new WhitelistAuth(path, dict.release(), password));
  } else if (auth_type == RootAuth::AuthType) {
    admin.reset(new RootAuth(path, dict.release(), password));
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

  scoped_ptr<TaoDomain> admin(CreateImpl(initial_config, path, password));
  if (admin.get() == nullptr) {
    LOG(ERROR) << "Can't create TaoDomain";
    return nullptr;
  }

  string priv_path = admin->GetPolicyPrivateKeyPath();
  string pub_path = admin->GetPolicyPublicKeyPath();
  string cert_path = admin->GetPolicyX509CertificatePath();
  // Generate and save the policy public and private keys.
  if (!GenerateSigningKey(priv_path, pub_path, "tao_domain_policy_key",
                          password, &admin->policy_signer_)) {
    LOG(ERROR) << "Could not generate policy signing key";
    return nullptr;
  }
  // Reload the just-created public key as a Verifier.
  if (!LoadVerifierKey(pub_path, &admin->policy_verifier_)) {
    LOG(ERROR) << "Could not load policy verifier key";
    return nullptr;
  }
  // Export an openssl copy of the private key.
  if (!CreateSelfSignedX509(
          admin->GetPolicySigner(), admin->GetPolicyX509Country(),
          admin->GetPolicyX509State(), admin->GetPolicyX509Organization(),
          admin->GetPolicyX509CommonName(), cert_path)) {
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

TaoDomain *TaoDomain::Load(const string &path) {
  string json;
  if (!ReadFileToString(path, &json)) {
    LOG(ERROR) << "Can't read configuration from " << path;
    return nullptr;
  }
  scoped_ptr<TaoDomain> admin(CreateImpl(json, path, "" /* no pass */));
  if (admin.get() == nullptr) {
    LOG(ERROR) << "Can't create TaoDomain";
    return nullptr;
  }
  if (!admin->ParseConfig()) {
    LOG(ERROR) << "Can't load TaoDomain configuration";
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
  if (policy_signer_.get() != nullptr) {
    if (!other->Unlock(password_)) {
      LOG(ERROR) << "Can't unlock reloaded TaoDomain configuration";
      return nullptr;
    }
  }
  return other.release();
}

bool TaoDomain::Unlock(const string &password) {
  if (!LoadSigningKey(GetPolicyPrivateKeyPath(), password, &policy_signer_)) {
    LOG(ERROR) << "The supplied password does not unlock the policy signer key";
    return false;
  }
  password_ = password;
  return true;
}

bool TaoDomain::ParseConfig() {
  if (!password_.empty()) {
    if (!LoadSigningKey(GetPolicyPrivateKeyPath(), password_,
                        &policy_signer_)) {
      LOG(ERROR) << "Could not load policy signer key";
      return false;
    }
  }
  if (!LoadVerifierKey(GetPolicyPublicKeyPath(), &policy_verifier_)) {
    LOG(ERROR) << "Could not load policy verifier key";
    return false;
  }
  return true;
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

const string TaoDomain::GetConfigString(const string &name) const {
  string value = "";
  if (!config_->GetString(name, &value))
    LOG(WARNING) << "Can't find configuration parameter " << name;
  return value;
}

const string TaoDomain::GetConfigPath(const string &name) const {
  return RelativePath(GetConfigString(name));
}

const string TaoDomain::GetConfigPath(const string &name,
                                      const string &suffix) const {
  return FilePath(GetConfigPath(name)).Append(suffix).value();
}

const string TaoDomain::RelativePath(const string &suffix) const {
  return FilePath(path_).DirName().Append(suffix).value();
}

bool TaoDomain::AttestByRoot(Statement *s, Attestation *attestation) const {
  if (policy_signer_.get() == nullptr) {
    LOG(ERROR) << "Can't sign attestation, admin is currently locked";
    return false;
  }
  string emptycert = "";  // empty cert because root
  if (!GenerateAttestation(policy_signer_.get(), emptycert, s, attestation)) {
    LOG(ERROR) << "Can't sign attestation";
    return false;
  }
  return true;
}

bool TaoDomain::AttestByRoot(Statement *s, string *attestation) const {
  if (policy_signer_.get() == nullptr) {
    LOG(ERROR) << "Can't sign attestation, admin is currently locked.";
    return false;
  }
  string emptycert = "";  // empty cert because root
  if (!GenerateAttestation(policy_signer_.get(), emptycert, s, attestation)) {
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
                       a.signature(), policy_verifier_.get())) {
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
