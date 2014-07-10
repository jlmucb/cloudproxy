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

#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/util.h"
#include "tao/keys.h"
#include "tao/util.h"

using keyczar::base::PathExists;
using keyczar::base::WriteStringToFile;

using tao::Keys;

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

bool CloudUserManager::AddSigningKey(const string &user,
                                     const keyczar::Signer &key) {
  unique_ptr<keyczar::Signer> key_copy;
  if (!tao::CopySigner(key, &key_copy)) {
    LOG(ERROR) << "Could not copy user signing private key";
    return false;
  }
  shared_ptr<keyczar::Signer> shared_signer(key_copy.release());
  user_private_keys_[user] = shared_signer;
  return true;
}

bool CloudUserManager::AddKey(const string &user, const string &pub_key) {
  unique_ptr<keyczar::Verifier> scoped_verifier;
  if (!tao::DeserializePublicKey(pub_key, &scoped_verifier)) {
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
  if (verifier == nullptr) {
    LOG(ERROR) << "Could not add null key";
    return false;
  }
  // check the signature for this binding
  if (!tao::VerifySignature(*verifier, ssf.serialized_speaks_for(),
                            SpeaksForSigningContext, ssf.signature())) {
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

bool CloudUserManager::MakeNewUser(const string &path, const string &username,
                                   const string &password,
                                   const keyczar::Signer &policy_key,
                                   unique_ptr<Keys> *key) {
  string keys_path = FilePath(path).Append(username).value();
  key->reset(new Keys(keys_path, username, Keys::Signing));
  if (!(*key)->InitWithPassword(password)) {
    LOG(ERROR) << "Could not create key for user " << username;
    return false;
  }
  string pub_key;
  SpeaksFor sf;
  sf.set_subject(username);
  if (!(*key)->SerializePublicKey(sf.mutable_pub_key())) {
    LOG(ERROR) << "Could not serialize key for user " << username;
    return false;
  }
  SignedSpeaksFor ssf;
  if (!sf.SerializeToString(ssf.mutable_serialized_speaks_for())) {
    LOG(ERROR) << "Could not serialize key for user " << username;
    return false;
  }
  if (!tao::SignData(policy_key, ssf.serialized_speaks_for(),
                     CloudUserManager::SpeaksForSigningContext,
                     ssf.mutable_signature())) {
    LOG(ERROR) << "Could not sign delegation for user " << username;
    return false;
  }
  string serialized_ssf;
  if (!ssf.SerializeToString(&serialized_ssf)) {
    LOG(ERROR) << "Could not serialize delegation for user " << username;
    return false;
  }
  string ssf_path = (*key)->GetPath(UserDelegationSuffix);
  if (!WriteStringToFile(ssf_path, serialized_ssf)) {
    LOG(ERROR) << "Could not write delegation for user " << username;
    return false;
  }
  return true;
}

bool CloudUserManager::LoadUser(const string &path, const string &username,
                                const string &password,
                                unique_ptr<tao::Keys> *key) {
  string keys_path = FilePath(path).Append(username).value();
  if (!PathExists(FilePath(keys_path))) {
    LOG(ERROR) << "No such user " << username;
    return false;
  }
  key->reset(new Keys(keys_path, username, Keys::Signing));
  if (!(*key)->InitWithPassword(password)) {
    LOG(ERROR) << "Could not load key for user " << username;
    return false;
  }
  return true;
}
}  // namespace cloudproxy
