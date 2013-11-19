#include "tao/fake_tao.h"
#include "tao/attestation.pb.h"
#include <keyczar/crypto_factory.h>

using keyczar::Crypter;
using keyczar::CryptoFactory;
using keyczar::Keyset;
using keyczar::KeysetMetadata;
using keyczar::KeyType;
using keyczar::KeyPurpose;
using keyczar::KeyStatus;
using keyczar::RandImpl;
using keyczar::Signer;

namespace tao {
FakeTao::FakeTao()
    : crypter_(nullptr), signer_(nullptr), policy_verifier_(nullptr) {
  // The actual initialization happens in Init().
}

bool FakeTao::Init() {
  scoped_ptr<Keyset> k(new Keyset());
  KeyType::Type crypter_key_type = KeyType::AES;
  KeyPurpose::Type crypter_key_purpose = KeyPurpose::DECRYPT_AND_ENCRYPT;
  KeysetMetadata *crypter_metadata = new KeysetMetadata(
      "fake_tao", crypter_key_type, crypter_key_purpose, true, 1);
  CHECK_NOTNULL(crypter_metadata);

  k->set_metadata(crypter_metadata);
  k->GenerateDefaultKeySize(KeyStatus::PRIMARY);

  crypter_.reset(new Crypter(k.release()));

  scoped_ptr<Keyset> pk(new Keyset());
  KeyType::Type pk_key_type = KeyType::ECDSA_PRIV;
  KeyPurpose::Type pk_key_purpose = KeyPurpose::SIGN_AND_VERIFY;
  KeysetMetadata *pk_metadata =
      new KeysetMetadata("fake_tao_pk", pk_key_type, pk_key_purpose, true, 1);
  CHECK_NOTNULL(pk_metadata);
  pk->set_metadata(pk_metadata);
  pk->GenerateDefaultKeySize(KeyStatus::PRIMARY);

  signer_.reset(new Signer(pk.release()));

  scoped_ptr<Keyset> public_pk(new Keyset());
  KeyType::Type public_pk_key_type = KeyType::ECDSA_PRIV;
  KeyPurpose::Type public_pk_key_purpose = KeyPurpose::SIGN_AND_VERIFY;
  KeysetMetadata *public_pk_metadata = new KeysetMetadata(
      "fake_tao_public_pk", public_pk_key_type, public_pk_key_purpose, true, 1);
  CHECK_NOTNULL(public_pk_metadata);
  public_pk->set_metadata(public_pk_metadata);
  public_pk->GenerateDefaultKeySize(KeyStatus::PRIMARY);

  policy_verifier_.reset(new Signer(public_pk.release()));

  return true;
}

bool FakeTao::StartHostedProgram(const string &path, const list<string> &args) {
  // to be implemented after the pipe process code has been refactored
  return false;
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
  // For the fake tao, the statement is just the data.
  Attestation a;
  a.set_type(ROOT);
  a.set_serialized_statement(data);
  string *sig = a.mutable_signature();
  if (!signer_->Sign(data, sig)) {
    LOG(ERROR) << "Could not sign the data";
    return false;
  }

  return a.SerializeToString(attestation);
}

bool FakeTao::VerifyAttestation(const string &attestation, string *data) const {
  // Check the signature directly over the serialized_statement.
  Attestation a;
  if (a.type() != ROOT) {
    LOG(ERROR) << "Wrong type of fake Attestation";
    return false;
  }

  if (a.has_cert()) {
    LOG(ERROR) << "A fake Attestation should not have a cert";
    return false;
  }

  if (!a.ParseFromString(attestation)) {
    LOG(ERROR) << "Could not deserialize the Attestation";
    return false;
  }

  data->assign(a.serialized_statement().data(),
               a.serialized_statement().size());
  return signer_->Verify(a.serialized_statement(), a.signature());
}
}  // namespace tao
