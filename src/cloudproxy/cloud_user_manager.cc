//  File: cloud_user_manager.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: Implementation of the CloudUserManager class that
// handles authenticated users for CloudClient and CloudServer
//
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

#include "cloudproxy/cloud_user_manager.h"

#include <glog/logging.h>
#include <keyczar/base/file_util.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_file_reader.h>

#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/util.h"
#include "tao/util.h"

using keyczar::base::PathExists;
using tao::DeserializePublicKey;
using tao::KeyczarPublicKey;
using tao::VerifySignature;

namespace cloudproxy {

bool CloudUserManager::HasKey(const string &user) const {
  return user_private_keys_.end() != user_private_keys_.find(user) ||
         user_public_keys_.end() != user_public_keys_.find(user);
}

bool CloudUserManager::GetKey(const string &user, keyczar::Signer **key) {
  CHECK_NOTNULL(key);
  auto user_it = user_private_keys_.find(user);
  if (user_private_keys_.end() == user_it) {
    return false;
  }

  *key = user_it->second.get();
  return true;
}

bool CloudUserManager::GetKey(const string &user, keyczar::Verifier **key) {
  CHECK_NOTNULL(key);
  auto user_it = user_public_keys_.find(user);
  if (user_public_keys_.end() == user_it) {
    // a private key will suffice if we don't have the public
    auto user_it2 = user_private_keys_.find(user);
    if (user_private_keys_.end() == user_it2) {
      return false;
    }
    *key = user_it2->second.get();
    return true;
  }
  *key = user_it->second.get();
  return true;
}

bool CloudUserManager::AddSigningKey(const string &user, const string &path,
                                     const string &password) {
  scoped_ptr<keyczar::Signer> signer;
  if (!tao::LoadSigningKey(path, password, &signer)) return false;

  shared_ptr<keyczar::Signer> shared_signer(signer.release());
  user_private_keys_[user] = shared_signer;
  return true;
}

bool CloudUserManager::AddKey(const string &user, const string &pub_key) {
  KeyczarPublicKey kpk;
  if (!kpk.ParseFromString(pub_key)) {
    LOG(ERROR) << "Could not deserialize the KeyczarPublicKey";
    return false;
  }

  scoped_ptr<keyczar::Verifier> scoped_verifier;
  if (!DeserializePublicKey(kpk, &scoped_verifier)) {
    LOG(ERROR) << "Could not deserialize the key";
    return false;
  }
  shared_ptr<keyczar::Verifier> verifier(scoped_verifier.release());

  // handle bytes instead of Base64w-encoded strings
  user_public_keys_[user] = verifier;
  return true;
}

bool CloudUserManager::AddKey(const SignedSpeaksFor &ssf,
                              keyczar::Verifier *verifier) {
  // check the signature for this binding
  if (!VerifySignature(ssf.serialized_speaks_for(), SpeaksForSigningContext,
                       ssf.signature(), verifier)) {
    LOG(ERROR) << "The SignedSpeaksFor was not correctly signed";
    return false;
  }

  SpeaksFor sf;
  if (!sf.ParseFromString(ssf.serialized_speaks_for())) {
    LOG(ERROR) << "Could not deserialize the SpeaksFor message";
    return false;
  }

  return AddKey(sf.subject(), sf.pub_key());
}

void CloudUserManager::SetAuthenticated(const string &user) {
  authenticated_.insert(user);
}

bool CloudUserManager::IsAuthenticated(const string &user) {
  return authenticated_.end() != authenticated_.find(user);
}

}  // namespace cloudproxy
