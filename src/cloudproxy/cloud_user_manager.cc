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
#include "cloudproxy/util.h"
#include "cloudproxy/cloudproxy.pb.h"

#include <keyczar/rw/keyset_file_reader.h>

#include <glog/logging.h>

#include "tao/util.h"

using tao::KeyczarPublicKey;
using tao::DeserializePublicKey;
using tao::VerifySignature;

namespace cloudproxy {

bool CloudUserManager::HasKey(const string &user) const {
  return users_.end() != users_.find(user);
}

bool CloudUserManager::GetKey(const string &user, keyczar::Keyczar **key) {
  CHECK_NOTNULL(key);
  auto user_it = users_.find(user);
  if (users_.end() == user_it) {
    return false;
  }

  *key = user_it->second.get();
  return true;
}

bool CloudUserManager::AddSigningKey(const string &user, const string &path,
                                     const string &password) {
  keyczar::base::ScopedSafeString safe_password(new string(password));
  scoped_ptr<keyczar::rw::KeysetReader> reader(
      new keyczar::rw::KeysetPBEJSONFileReader(path.c_str(), *safe_password));

  shared_ptr<keyczar::Keyczar> signer(keyczar::Signer::Read(*reader));
  if (signer.get() == nullptr) {
    LOG(ERROR) << "Could not read the key from " << path;
    return false;
  }

  // get bytes from Sign instead of Base64w-encoded strings
  signer->set_encoding(keyczar::Keyczar::NO_ENCODING);

  users_[user] = signer;
  return true;
}

bool CloudUserManager::AddKey(const string &user, const string &pub_key) {
  KeyczarPublicKey kpk;
  if (!kpk.ParseFromString(pub_key)) {
    LOG(ERROR) << "Could not deserialize the KeyczarPublicKey";
    return false;
  }

  keyczar::Keyset *keyset = nullptr;
  if (!DeserializePublicKey(kpk, &keyset)) {
    LOG(ERROR) << "Could not deserialize the keyset";
    return false;
  }

  shared_ptr<keyczar::Keyczar> verifier(new keyczar::Verifier(keyset));

  // handle bytes instead of Base64w-encoded strings
  verifier->set_encoding(keyczar::Keyczar::NO_ENCODING);
  users_[user] = verifier;
  return true;
}

bool CloudUserManager::AddKey(const SignedSpeaksFor &ssf,
                              keyczar::Keyczar *verifier) {
  // check the signature for this binding
  if (!VerifySignature(ssf.serialized_speaks_for(), ssf.signature(),
                       verifier)) {
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
