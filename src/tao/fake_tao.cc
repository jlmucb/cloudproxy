//  File: fake_tao.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A fake implementation of the Tao interface that isn't
//  backed by any trusted hardware.
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
#include "tao/fake_tao.h"

#include <list>
#include <string>

#include <glog/logging.h>
#include <keyczar/base/file_util.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/keyczar.h>

#include "tao/attestation.pb.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using std::list;
using std::string;

using keyczar::Crypter;
using keyczar::CryptoFactory;
using keyczar::RandImpl;
using keyczar::base::DirectoryExists;
using keyczar::base::PathExists;
using keyczar::base::ReadFileToString;
using keyczar::base::WriteStringToFile;

namespace tao {

bool FakeTao::Init() {
  string sealing_key_path;
  string signing_key_path;
  string attestation_path;
  if (!keys_path_.empty()) {
    FilePath fp(keys_path_);
    sealing_key_path = fp.Append(tao::keys::SealKeySuffix).value();
    signing_key_path = fp.Append(tao::keys::SignPrivateKeySuffix).value();
    attestation_path = fp.Append(tao::keys::SignKeyAttestationSuffix).value();
  } else {
    signing_key_path = signing_key_path_;
  }

  if (!signing_key_password_.empty()) {
    VLOG(2) << "Fake tao: Using existing signing key " << signing_key_path;
    LoadSigningKey(signing_key_path, signing_key_password_, &signer_);
  } else if (signing_key_path.empty()) {
    VLOG(2) << "Fake tao: Generating temporary signing key";
    GenerateSigningKey(keyczar::KeyType::ECDSA_PRIV, "" /* no priv path */,
                       "" /* no pub path */, "fake_aik", "" /* no passwd */,
                       &signer_);
  } else if (!DirectoryExists(FilePath(signing_key_path))) {
    VLOG(2) << "Fake tao: Generating signing key " << signing_key_path;
    GenerateSigningKey(keyczar::KeyType::ECDSA_PRIV, signing_key_path,
                       "" /* no pub path */, "fake_aik", FakePassword,
                       &signer_);
  } else {
    VLOG(2) << "Fake tao: Using signing key " << signing_key_path;
    LoadSigningKey(signing_key_path, FakePassword, &signer_);
  }
  if (signer_.get() == nullptr) {
    LOG(ERROR) << "Could not load signing key";
    return false;
  }

  if (sealing_key_path.empty()) {
    VLOG(2) << "Fake tao: Generating temporary sealing key";
    GenerateCryptingKey(keyczar::KeyType::AES, "" /* no path */, "fake_srk",
                        "" /* no passwd */, &crypter_);
  } else if (!DirectoryExists(FilePath(sealing_key_path))) {
    VLOG(2) << "Fake tao: Generating sealing key " << sealing_key_path;
    GenerateCryptingKey(keyczar::KeyType::AES, sealing_key_path, "fake_srk",
                        FakePassword, &crypter_);
  } else {
    VLOG(2) << "Fake tao: Using sealing key " << sealing_key_path;
    LoadCryptingKey(sealing_key_path, FakePassword, &crypter_);
  }
  if (crypter_.get() == nullptr) {
    LOG(ERROR) << "Could not load sealing key";
    return false;
  }

  if (admin_.get() == nullptr) {
    VLOG(2) << "Fake tao: Not using any attestation";
  } else if (PathExists(FilePath(attestation_path))) {
    VLOG(2) << "Fake tao: Using attestation " << attestation_path;
    if (!ReadFileToString(attestation_path, &attestation_)) {
      LOG(ERROR) << "Could not load attestation";
      return false;
    }
  } else {
    VLOG(2) << "Fake tao: Creating attestation " << attestation_path;
    string serialized_key = SerializePublicKey(*signer_);
    if (serialized_key.empty()) {
      LOG(ERROR) << "Could not serialize key";
      return false;
    }
    // create a signed, fake tpm attestation
    Statement s;
    s.set_data(serialized_key);
    s.set_hash_alg(TaoDomain::FakeHash);
    s.set_hash("FAKE_TPM");
    // sign this serialized data with policy key
    string attestation;
    if (!admin_->AttestByRoot(&s, &attestation)) {
      LOG(ERROR) << "Could not obtain root attestation";
      return false;
    }
    // save to file
    if (!WriteStringToFile(attestation_path, attestation)) {
      LOG(ERROR) << "Could not write attestation";
      return false;
    }
  }

  return true;
}

bool FakeTao::StartHostedProgram(const string &path, const list<string> &args,
                                 string *identifier) {
  // Just pretend to start the hosted program.
  identifier->assign(path);
  return true;
}

bool FakeTao::GetRandomBytes(size_t size, string *bytes) const {
  // just ask the CryptoFactory::Rand in keyczar for some randomness
  RandImpl *r = CryptoFactory::Rand();
  if (!r->Init()) {
    LOG(ERROR) << "Could not initialize the random factory";
    return false;
  }

  return r->RandBytes(size, bytes);
}

bool FakeTao::Seal(const string &child_hash, const string &data,
                   string *sealed) const {
  // just encrypt it with our crypter
  return crypter_->Encrypt(data, sealed);
}

bool FakeTao::Unseal(const string &child_hash, const string &sealed,
                     string *data) const {
  // decrypt it with our crypter
  return crypter_->Decrypt(sealed, data);
}

bool FakeTao::Attest(const string &child_hash, const string &data,
                     string *attestation) const {
  Statement s;
  s.set_data(data);
  s.set_hash_alg(TaoDomain::Sha256);
  s.set_hash(child_hash);

  return GenerateAttestation(signer_.get(), attestation_, &s, attestation);
}
}  // namespace tao
