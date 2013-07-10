#include "cloud_user_manager.h"
#include "util.h"
#include "cloudproxy.pb.h"

namespace cloudproxy {

bool CloudUserManager::HasUser(const string &user) {
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

bool CloudUserManager::AddKey(const string &user,
    const string &key, const string &meta) {
  scoped_ptr<keyczar::Keyset> keyset(new keyczar::Keyset());
  if (!CreateRSAPublicKeyset(key, meta, keyset.get())) {
    LOG(ERROR) << "Could not deserialize the keyset";
    return false;
  }

  shared_ptr<keyczar::Keyczar> verifier(new keyczar::Verifier(keyset.release()));
  users_[user] = verifier;
  return true;
}

bool CloudUserManager::AddKey(const string &binding,
    keyczar::Keyczar *verifier) {
  // deserialize the binding and check its signature
  SignedSpeaksFor ssf;
  if (!ssf.ParseFromString(binding)) {
    LOG(ERROR) << "Could not parse a SignedSpeaksFor message";
    return false;
  }

  if (!VerifySignature(ssf.serialized_speaks_for(), ssf.signature(), verifier)) {
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

void CloudUserManager::SetAuthenticated(const string &user) {
  authenticated_.insert(user);
}

bool CloudUserManager::IsAuthenticated(const string &user) {
  return authenticated_.end() != authenticated.find(user);
}

} // namespace cloudproxy
