//  File: cloud_user_manager.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: Implementation of the CloudUserManager class that
// handles authenticated users for CloudClient and CloudServer
// 
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
//
// Use, duplication and disclosure of this file and derived works of
// this file are subject to and licensed under the Apache License dated
// January, 2004, (the "License").  This License is contained in the
// top level directory originally provided with the CloudProxy Project.
// Your right to use or distribute this file, or derived works thereof,
// is subject to your being bound by those terms and your use indicates
// consent to those terms.
//
// If you distribute this file (or portions derived therefrom), you must
// include License in or with the file and, in the event you do not include
// the entire License in the file, the file must contain a reference
// to the location of the License.

// ------------------------------------------------------------------------

#include "cloudproxy/cloud_user_manager.h"
#include "cloudproxy/util.h"
#include "cloudproxy/cloudproxy.pb.h"

#include <keyczar/rw/keyset_file_reader.h>

namespace cloudproxy {

bool CloudUserManager::HasKey(const string &user) const {
  return users_.end() != users_.find(user);
}

bool CloudUserManager::GetKey(const string &user,
                              shared_ptr<keyczar::Keyczar> *key) {
  CHECK(key) << "null key";
  auto user_it = users_.find(user);
  if (users_.end() == user_it) {
    return false;
  }

  *key = user_it->second;
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

bool CloudUserManager::AddKey(const string &user, const string &key,
                              const string &meta) {
  scoped_ptr<keyczar::Keyset> keyset(new keyczar::Keyset());
  if (!CreateRSAPublicKeyset(key, meta, keyset.get())) {
    LOG(ERROR) << "Could not deserialize the keyset";
    return false;
  }

  shared_ptr<keyczar::Keyczar> verifier(
      new keyczar::Verifier(keyset.release()));

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

  return AddKey(sf.subject(), sf.pub_key(), sf.meta());
}

void CloudUserManager::SetAuthenticated(const string &user) {
  authenticated_.insert(user);
}

bool CloudUserManager::IsAuthenticated(const string &user) {
  return authenticated_.end() != authenticated_.find(user);
}

}  // namespace cloudproxy
