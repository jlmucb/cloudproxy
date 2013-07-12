#include "cloud_user_manager.h"
#include "util.h"
#include "cloudproxy.pb.h"

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

bool CloudUserManager::AddKey(const string &user,
    const string &key, const string &meta) {
  scoped_ptr<keyczar::Keyset> keyset(new keyczar::Keyset());
  if (!CreateRSAPublicKeyset(key, meta, keyset.get())) {
    LOG(ERROR) << "Could not deserialize the keyset";
    return false;
  }

  shared_ptr<keyczar::Keyczar> verifier(new keyczar::Verifier(keyset.release()));
  
  // handle bytes instead of Base64w-encoded strings
  verifier->set_encoding(keyczar::Keyczar::NO_ENCODING);
  users_[user] = verifier;
  return true;
}

bool CloudUserManager::AddKey(const SignedSpeaksFor &ssf,
    keyczar::Keyczar *verifier) {
  // check the signature for this binding
  if (!VerifySignature(ssf.serialized_speaks_for(), ssf.signature(), verifier)) {
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

} // namespace cloudproxy
