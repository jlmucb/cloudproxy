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
#include <sstream>
#include <string>

#include <glog/logging.h>
#include <keyczar/base/file_util.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/keyczar.h>

#include "tao/attestation.pb.h"
#include "tao/keys.h"
#include "tao/sealed_data.pb.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using std::list;
using std::string;
using std::stringstream;

using keyczar::Crypter;
using keyczar::CryptoFactory;
using keyczar::RandImpl;
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
    VLOG(2) << "Fake tao: Using policy attestation " << attestation_path;
    if (!ReadFileToString(attestation_path, &policy_attestation_)) {
      LOG(ERROR) << "Could not load policy attestation";
      return false;
    }
  } else {
    VLOG(2) << "Fake tao: Creating policy attestation " << attestation_path;
    if (!MakePolicyAttestation(admin)) {
      LOG(ERROR) << "Could not create policy attestation";
      return false;
    }
    if (!WriteStringToFile(attestation_path, policy_attestation_)) {
      LOG(ERROR) << "Could not write policy attestation";
      return false;
    }
  }
  return true;
}

FakeTao *FakeTao::DeepCopy() const {
  scoped_ptr<FakeTao> other(new FakeTao());
  other->keys_.reset(keys_->DeepCopy());
  other->policy_attestation_ = policy_attestation_;
  return other.release();
}

bool FakeTao::StartHostedProgram(const string &path, const list<string> &args,
                                 string *child_name) {
  // Just pretend to start the hosted program.
  stringstream out;
  out << "FakeProgram(" << last_child_id_ << ", " << quotedString(path) << ")";
  child_name->assign(out.str());
  return true;
}

bool FakeTao::GetTaoFullName(string *tao_name) {
  // FakeTao has no parent, so the local and full name are identical
  return GetLocalName(tao_name);
}

bool FakeTao::GetLocalName(string *name) {
  return keys_->SignerUniqueID(&key_id);
}

bool FakeTao::GetPolicyName(string *name) {
  if (policy_attestation_ == "") {
    LOG(ERROR) << "FakeTao configured without policy key-to-name binding.";
    return false;
  }
  return GetNameFromKeyNameBinding(policy_attestation_, name);
}

bool FakeTao::GetRandomBytes(const string &child_name, size_t size,
                             string *bytes) const {
  // just ask the CryptoFactory::Rand in keyczar for some randomness
  RandImpl *r = CryptoFactory::Rand();
  if (!r->Init()) {
    LOG(ERROR) << "Could not initialize the random factory";
    return false;
  }

  return r->RandBytes(size, bytes);
}

bool FakeTao::Seal(const string &child_name, const string &data, int policy,
                   string *sealed) const {
  // concatenate policy info and data, then encrypt with our crypter
  // FakeTao supports only one policy: unseal can only be done by
  // the principal that called seal.
  stringstream out;
  out << child_name.length() << "|" << child_name << "|" << data;
  string bundle = out.str();

  FakeTaoSealedData sd;
  sd.set_policy_name(child_name);
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

bool FakeTao::Unseal(const string &child_name, const string &sealed,
                     string *data, int *policy) const {
  // Decrypt it.
  string temp_decrypted;
  if (!keys_->Crypter()->Decrypt(sealed, &temp_decrypted)) {
    LOG(ERROR) << "Could not decrypt the sealed data";
    return false;
  }

  // Parse it.
  FakeTaoSealedData sd;
  if (!sd.ParseFromString(temp_decrypted)) {
    // note that this is safe, since we always use authenticated encryption
    LOG(ERROR) << "Could not parse the decrypted data";
    return false;
  }

  // Check the policy.
  if (child_name != sd.policy_name()) {
    LOG(ERROR) << "Access denied";
    return false;
  }

  data->assign(sd.data());
  *policy = 0;  // unused
  return true;
}

bool FakeTao::Attest(const string &child_name, const string &pem_key,
                     string *attestation) const {
  string name, delegation;
  // We have choices here.
  // (1) We can create a binding via parent name, to get:
  //   parent_tao::tao_subprin::child_name
  // where parent_tao is the name of our parent (e.g. a TPM key) and tao_subprin
  // is our name (e.g. a set of PCRs). 
  // (2) We can create a binding via our key, to get:
  //   K_fake::child_name
  // where K_fake is our own attestation key.
  // (3) We can create a binding via the policy key, to get:
  //   K_policy::TrustedOS::child_name
  // where K_policy::TrustedOS is the name we bound to K_fake by TaoCA.
  int option = 2;
  if (option == 1) {
    LOG(ERROR) << "Oops, fake tao does not have a parent";
    return false;
    // if (!GetTaoFullName(&name)) {
    //   LOG(ERROR) << "Could not get full name for attestation";
    //   return false;
    // }
    // name += "::" + child_name;
    // delegation = parent_attestation_;
  } else if (option == 2) {
    if (!GetLocalName(&name)) {
      LOG(ERROR) << "Could not get full name for attestation";
      return false;
    }
    name += "::" + child_name;
    delegation = "";
  } else {
    if (!policy_attestation_) {
      LOG(ERROR) << "No policy attestation available";
      return false;
    }
    if (!GetPolicyName(&name)) {
      LOG(ERROR) << "Could not get full name for attestation";
      return false;
    }
    name += "::" + child_name;
    delegation = policy_attestation_;
  }
  return tao::AttestKeyNameBinding(*keys_, delegation, pem_key, name,
                                   attestation);
}

bool FakeTao::MakePolicyAttestation(const TaoDomain &admin) {
  string pem_key;
  if (!keys_->SerializePublicKey(&pem_key)) {
    LOG(ERROR) << "Could not serialize key";
    return false;
  }
  if (!admin.AttestKeyNameBinding(pem_key, "FakeTPM", , &policy_attestation_)) {
    LOG(ERROR) << "Could not obtain policy attestation";
    return false;
  }
  return true;
}

bool FakeTao::ExtendName(string *child_name, const string &subprin) {
  // TODO(kwalsh) Check subprin name for format/reasonableness.
  string extended_name = *child_name + "::" + subprin;
  child_name->assign(extended_name);
  return true;
}
}  // namespace tao
