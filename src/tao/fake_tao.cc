#include "tao/fake_tao.h"

#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <keyczar/crypto_factory.h>

#include "tao/attestation.pb.h"
#include "tao/util.h"

using keyczar::Crypter;
using keyczar::CryptoFactory;
using keyczar::Keyczar;
using keyczar::Keyset;
using keyczar::KeysetMetadata;
using keyczar::KeyType;
using keyczar::KeyPurpose;
using keyczar::KeyStatus;
using keyczar::RandImpl;
using keyczar::Signer;

namespace tao {
FakeTao::FakeTao()
    : key_path_(), attestation_(), crypter_(nullptr), key_(nullptr) {}

FakeTao::FakeTao(const string &key_path)
    : key_path_(key_path),
      attestation_(),
      crypter_(nullptr),
      key_(nullptr) {
  // The actual initialization happens in Init().
}

FakeTao::FakeTao(const string &key_path, const string &attestation)
    : key_path_(key_path),
      attestation_(attestation),
      crypter_(nullptr),
      key_(nullptr) {
  // The initialization happens in Init()
}
bool FakeTao::Init() {
  if (!key_path_.empty()) {
    key_.reset(Signer::Read(key_path_.c_str()));
    key_->set_encoding(Keyczar::NO_ENCODING);
  } else {
    scoped_ptr<Keyset> public_pk(new Keyset());
    KeyType::Type public_pk_key_type = KeyType::ECDSA_PRIV;
    KeyPurpose::Type public_pk_key_purpose = KeyPurpose::SIGN_AND_VERIFY;
    KeysetMetadata *public_pk_metadata =
        new KeysetMetadata("fake_tao_public_pk", public_pk_key_type,
                           public_pk_key_purpose, true, 1);
    CHECK_NOTNULL(public_pk_metadata);
    public_pk->set_metadata(public_pk_metadata);
    public_pk->GenerateDefaultKeySize(KeyStatus::PRIMARY);

    key_.reset(new Signer(public_pk.release()));
  }

  scoped_ptr<Keyset> k(new Keyset());
  KeyType::Type crypter_key_type = KeyType::AES;
  KeyPurpose::Type crypter_key_purpose = KeyPurpose::DECRYPT_AND_ENCRYPT;
  KeysetMetadata *crypter_metadata = new KeysetMetadata(
      "fake_tao", crypter_key_type, crypter_key_purpose, true, 1);
  CHECK_NOTNULL(crypter_metadata);

  k->set_metadata(crypter_metadata);
  k->GenerateDefaultKeySize(KeyStatus::PRIMARY);

  crypter_.reset(new Crypter(k.release()));
  crypter_->set_encoding(Keyczar::NO_ENCODING);
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
  time_t cur_time;
  time(&cur_time);

  s.set_time(cur_time);
  s.set_expiration(cur_time + 10000);
  s.set_data(data);
  s.set_hash_alg("SHA256");
  s.set_hash(child_hash);

  string serialized_statement;
  if (!s.SerializeToString(&serialized_statement)) {
    LOG(ERROR) << "Could not serialize the statement";
    return false;
  }

  Attestation a;
  if (attestation_.empty()) {
    a.set_type(ROOT);
  } else {
    a.set_type(INTERMEDIATE);
    a.set_cert(attestation_);
  }

  a.set_serialized_statement(serialized_statement);
  string *sig = a.mutable_signature();
  if (!SignData(serialized_statement, AttestationSigningContext, sig,
                key_.get())) {
    LOG(ERROR) << "Could not sign the data";
    return false;
  }

  return a.SerializeToString(attestation);
}
}  // namespace tao
