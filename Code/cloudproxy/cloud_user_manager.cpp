#include "cloud_user_manager.h"
#include "util.h"
#include "cloudproxy.pb.h"

bool cloudproxy::CloudUserManager::HasUser(const string &user) {
  return users_.end() != users_.find(user);
}

bool cloudproxy::CloudUserManager::GetKey(const string &user,
    shared_ptr<keyczar::Keyczar> *key) {
  CHECK(key) << "null key";
  auto user_it = users_.find(user);
  if (users_.end() == user_it) {
    return false;
  }

  *key = user_it->second;
  return true;
}

bool cloudproxy::CloudUserManager::AddKey(const string &user,
    const string &key, const string &meta) {
  scoped_ptr<keyczar::Keyset> keyset(new keyczar::Keyset());
  if (!create_keyset(key, meta, keyset.get())) {
    LOG(ERROR) << "Could not deserialize the keyset";
    return false;
  }

  shared_ptr<keyczar::Keyczar> verifier(new keyczar::Verifier(keyset.release()));
  users_[user] = verifier;
  return true;
}

bool cloudproxy::CloudUserManager::AddKey(const string &binding,
    keyczar::Keyczar *verifier) {
  // deserialize the binding and check its signature
  SignedSpeaksFor ssf;
  if (!ssf.ParseFromString(binding)) {
    LOG(ERROR) << "Could not parse a SignedSpeaksFor message";
    return false;
  }

  if (!verify_signature(ssf.serialized_speaks_for(), ssf.signature(), verifier)) {
    LOG(ERROR) << "The SignedSpeaksFor was not correctly signed";
    return false;
  }

  SpeaksFor sf;
  if (!sf.ParseFromString(ssf.seralized_speaks_for())) {
    LOG(ERROR) << "Could not deserialize the SpeaksFor message";
    return false;
  }

  return AddKey(sf.subject(), sf.pub_key(), sf.meta());
}

void cloudproxy::CloudUserManager::SetAuthenticated(const string &user) {
  authenticated_.insert(user);
}

bool cloudproxy::CloudUserManager::IsAuthenticated(const string &user) {
  return authenticated_.end() != authenticated.find(user);
}
