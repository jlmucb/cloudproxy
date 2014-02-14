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
#include "tao/keys.h"
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

bool FakeTao::InitTemporaryTPM() {
  VLOG(2) << "Fake tao: Generating temporary signing key";
  keys_.reset(new Keys("fake_tpm", Keys::Signing | Keys::Crypting));
  if (!keys_->InitTemporary()) {
    LOG(ERROR) << "Could not initialize fake tao keys";
    return false;
  }
  return true;
}

bool FakeTao::InitTemporaryTPM(const TaoDomain &admin) {
  if (!InitTemporaryTPM()) {
    LOG(ERROR) << "Could not create fake tao keys";
    return false;
  }
  if (!MakePolicyAttestation(admin)) {
    LOG(ERROR) << "Could not create temporary attestation";
    return false;
  }
  return true;
}

bool FakeTao::InitPseudoTPM(const string &keys_path, const TaoDomain &admin) {
  VLOG(2) << "Fake tao: Generating keys in " << keys_path;
  keys_.reset(new Keys(keys_path, "fake_tpm", Keys::Signing | Keys::Crypting));
  if (!keys_->InitNonHosted(FakePassword)) {
    LOG(ERROR) << "Could not initialize fake tao keys";
    return false;
  }
  string attestation_path = keys_->AttestationPath();
  if (!keys_->HasFreshKeys()) {
    VLOG(2) << "Fake tao: Using attestation " << attestation_path;
    if (!ReadFileToString(attestation_path, &attestation_)) {
      LOG(ERROR) << "Could not load attestation";
      return false;
    }
  } else {
    VLOG(2) << "Fake tao: Creating attestation " << attestation_path;
    if (!MakePolicyAttestation(admin)) {
      LOG(ERROR) << "Could not create attestation";
      return false;
    }
    if (!WriteStringToFile(attestation_path, attestation_)) {
      LOG(ERROR) << "Could not write attestation";
      return false;
    }
  }
  return true;
}

FakeTao *FakeTao::DeepCopy() const {
  scoped_ptr<FakeTao> other(new FakeTao());
  other->keys_.reset(keys_->DeepCopy());
  other->attestation_ = attestation_;
  return other.release();
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
  return keys_->Crypter()->Encrypt(data, sealed);
}

bool FakeTao::Unseal(const string &child_hash, const string &sealed,
                     string *data) const {
  // decrypt it with our crypter
  return keys_->Crypter()->Decrypt(sealed, data);
}

bool FakeTao::Attest(const string &child_hash, const string &data,
                     string *attestation) const {
  Statement s;
  s.set_data(data);
  s.set_hash_alg(TaoDomain::Sha256);
  s.set_hash(child_hash);

  return GenerateAttestation(keys_->Signer(), attestation_, &s, attestation);
}

bool FakeTao::MakePolicyAttestation(const TaoDomain &admin) {
    string serialized_key;
    if (!keys_->SerializePublicKey(&serialized_key)) {
      LOG(ERROR) << "Could not serialize key";
      return false;
    }
    // create a signed, fake tpm attestation
    Statement s;
    s.set_data(serialized_key);
    s.set_hash_alg(TaoDomain::FakeHash);
    s.set_hash("FAKE_TPM");
    // sign this serialized data with policy key
    if (!admin.AttestByRoot(&s, &attestation_)) {
      LOG(ERROR) << "Could not obtain root attestation";
      return false;
    }
    return true;
}
}  // namespace tao
