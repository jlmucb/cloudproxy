//  File: keys.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Implementation of cryptographic key utilities for the Tao.
//
//  Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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
#include "tao/keys.h"

#include <sstream>
#include <string>

#include <glog/logging.h>
#include <google/protobuf/text_format.h>
#include <keyczar/base/json_reader.h>
#include <keyczar/base/json_writer.h>
#include <keyczar/base/values.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_file_reader.h>
#include <keyczar/rw/keyset_file_writer.h>
#include <keyczar/rw/keyset_writer.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <openssl/x509v3.h>

#include "tao/attestation.pb.h"
#include "tao/keys.pb.h"
#include "tao/signature.pb.h"
#include "tao/util.h"

using google::protobuf::TextFormat;
using keyczar::Crypter;
using keyczar::Key;
using keyczar::KeyPurpose;
using keyczar::KeyStatus;
using keyczar::KeyType;
using keyczar::Keyczar;
using keyczar::Keyset;
using keyczar::KeysetMetadata;
using keyczar::Signer;
using keyczar::Verifier;
using keyczar::base::JSONReader;
using keyczar::base::JSONWriter;
using keyczar::base::ScopedSafeString;
using keyczar::rw::KeysetJSONFileWriter;
using keyczar::rw::KeysetPBEJSONFileReader;
using keyczar::rw::KeysetPBEJSONFileWriter;
using keyczar::rw::KeysetWriter;

namespace tao {

// Keyczar is evil and runs EVP_cleanup(), which removes all the symbols.
// So, they need to be added again. Typical error is:
// * 336236785:SSL routines:SSL_CTX_new:unable to load ssl2 md5 routines
// This needs to be done as close after PBE operations as possible,
// and we need to reset anything that might be holding a PBE
// object to force it to destruct and EVP_cleanup.
// @param keyset A keyset to be reset.
// @param writer A writer to be reset.
static void KeyczarCleanupFix(scoped_ptr<Keyset> *keyset,
                              scoped_ptr<KeysetWriter> *writer) {
  if (writer) writer->reset();  // reset to force PBE object destruction
  if (keyset) keyset->reset();  // reset to force PBE object destruction
  OpenSSL_add_all_algorithms();
}

/// Generate a key and write it to disk.
/// @param key_type The type of key, e.g. RSA_PRIV, ECDSA_PRIV, HMAC.
/// @param key_purpose The purpose of key, e.g. SIGN_AND_VERIFY.
/// @param nickname A nickname for the new key.
/// @param password A password for encrypting the private key.
/// @param private_path Location to store the private key.
/// @param public_path Location to store public key, or emptystring.
/// @param[out] key A scoped pointer to write the key to.
template <class T>
static bool GenerateKey(KeyType::Type key_type, KeyPurpose::Type key_purpose,
                        const string &nickname, const string &password,
                        const string &private_path, const string &public_path,
                        scoped_ptr<T> *key) {
  if (!CreateDirectory(FilePath(private_path)) ||
      (!public_path.empty() && !CreateDirectory(FilePath(public_path)))) {
    LOG(ERROR) << "Could not create key directories";
    return false;
  }
  int next_version = 1;
  int encrypted = true;  // note: unused, AFAIK
  scoped_ptr<KeysetWriter> private_writer(
      new KeysetPBEJSONFileWriter(private_path, password));
  scoped_ptr<Keyset> keyset(new Keyset());
  // TODO(kwalsh) Error checking for writer; currently not supported by keyczar.
  keyset->AddObserver(private_writer.get());
  keyset->set_encrypted(encrypted);
  keyset->set_metadata(
      new KeysetMetadata(nickname, key_type, key_purpose, encrypted, next_version));
  // There is browser TLSv1.2 support for prime256v1 (secp256r1),
  // but not for keyczar's default secp224r1
  // keyset->GenerateDefaultKeySize(KeyStatus::PRIMARY);
  keyset->GenerateKey(KeyStatus::PRIMARY, 256);
  // We still own the writer, need to RemoveObserver before end of function.
  keyset->RemoveObserver(private_writer.get());
  if (!public_path.empty() &&
      !keyset->PublicKeyExport(KeysetJSONFileWriter(public_path))) {
    LOG(ERROR) << "Can't write public key to directory " << public_path;
    KeyczarCleanupFix(&keyset, &private_writer);
    return false;
  }
  key->reset(new T(keyset.release()));
  (*key)->set_encoding(Keyczar::NO_ENCODING);
  KeyczarCleanupFix(&keyset, &private_writer);
  return true;
}

static bool GenerateCryptingKey(const string &nickname, const string &password,
                                const string &path, scoped_ptr<Crypter> *key) {
  return GenerateKey(KeyType::AES, KeyPurpose::DECRYPT_AND_ENCRYPT, nickname,
                     password, path, "" /* no public */, key);
}

static bool GenerateSigningKey(const string &nickname, const string &password,
                               const string &private_path,
                               const string &public_path,
                               scoped_ptr<Signer> *key) {
  return GenerateKey(KeyType::ECDSA_PRIV, KeyPurpose::SIGN_AND_VERIFY, nickname,
                     password, private_path, public_path, key);
}

static bool GenerateKeyDerivingKey(const string &nickname, const string &password,
                                   const string &path,
                                   scoped_ptr<Signer> *key) {
  return GenerateKey(KeyType::HMAC, KeyPurpose::SIGN_AND_VERIFY, nickname, password,
                     path, "" /* no public */, key);
}

/// Generate a temporary key.
/// @param key_type The type of key, e.g. RSA_PRIV, ECDSA_PRIV, HMAC.
/// @param key_purpose The purpose of key, e.g. SIGN_AND_VERIFY.
/// @param nickname A nickname for the new key.
/// @param[out] key A scoped pointer to write the key to.
template <class T>
static bool GenerateKey(KeyType::Type key_type, KeyPurpose::Type key_purpose,
                        const string &nickname, scoped_ptr<T> *key) {
  int next_version = 1;
  int encrypted = true;  // note: unused, AFAIK
  scoped_ptr<Keyset> keyset(new Keyset());
  keyset->set_encrypted(encrypted);
  keyset->set_metadata(
      new KeysetMetadata(nickname, key_type, key_purpose, encrypted, next_version));
  // There is browser TLSv1.2 support for prime256v1 (secp256r1),
  // but not for keyczar's default secp224r1
  // keyset->GenerateDefaultKeySize(KeyStatus::PRIMARY);
  keyset->GenerateKey(KeyStatus::PRIMARY, 256);
  key->reset(new T(keyset.release()));
  (*key)->set_encoding(Keyczar::NO_ENCODING);
  KeyczarCleanupFix(&keyset, nullptr);
  return true;
}

static bool GenerateCryptingKey(const string &nickname, scoped_ptr<Crypter> *key) {
  return GenerateKey(KeyType::AES, KeyPurpose::DECRYPT_AND_ENCRYPT, nickname, key);
}

static bool GenerateSigningKey(const string &nickname, scoped_ptr<Signer> *key) {
  return GenerateKey(KeyType::ECDSA_PRIV, KeyPurpose::SIGN_AND_VERIFY, nickname,
                     key);
}

static bool GenerateKeyDerivingKey(const string &nickname,
                                   scoped_ptr<Signer> *key) {
  return GenerateKey(KeyType::HMAC, KeyPurpose::SIGN_AND_VERIFY, nickname, key);
}

/// Load a key from disk.
/// @param key_type The type of key, e.g. RSA_PRIV, ECDSA_PRIV, HMAC.
/// @param path Location to read the key.
/// @param password Password protecting the key, or nullptr for unprotected key.
/// @param[out] key A scoped pointer to write the key to.
template <class T>
static bool LoadKey(KeyType::Type key_type, const string &path,
                    const string *password, scoped_ptr<T> *key) {
  // Avoid keyczar CHECK fail if path does not exist.
  if (!PathExists(FilePath(path))) {
    LOG(ERROR) << "Could not load key from " << path;
    return false;
  }
  if (!password)
    key->reset(T::Read(path));
  else
    key->reset(T::Read(KeysetPBEJSONFileReader(path, *password)));
  if (key->get() == nullptr) {
    LOG(ERROR) << "Could not initialize key from " << path;
    KeyczarCleanupFix(nullptr, nullptr);
    return false;
  }
  if ((*key)->keyset()->metadata()->key_type() != key_type) {
    LOG(ERROR) << "Wrong key type detected in " << path;
    KeyczarCleanupFix(nullptr, nullptr);
    return false;
  }
  (*key)->set_encoding(Keyczar::NO_ENCODING);
  KeyczarCleanupFix(nullptr, nullptr);
  return true;
}

bool LoadVerifierKey(const string &path, scoped_ptr<Verifier> *key) {
  return LoadKey(KeyType::ECDSA_PUB, path, nullptr /* no passwd */, key);
}

bool LoadSigningKey(const string &path, const string &password,
                    scoped_ptr<Signer> *key) {
  return LoadKey(KeyType::ECDSA_PRIV, path, &password, key);
}

static bool LoadKeyDerivingKey(const string &path, const string &password,
                               scoped_ptr<Signer> *key) {
  return LoadKey(KeyType::HMAC, path, &password, key);
}

static bool LoadCryptingKey(const string &path, const string &password,
                            scoped_ptr<Crypter> *key) {
  return LoadKey(KeyType::AES, path, &password, key);
}

bool DeserializePublicKey(const string &s, scoped_ptr<Verifier> *key) {
  if (key == nullptr) {
    LOG(ERROR) << "null key";
    return false;
  }
  KeyczarPublicKey kpk;
  if (!kpk.ParseFromString(s)) {
    LOG(ERROR) << "Could not deserialize the KeyczarPublicKey";
    return false;
  }
  string json_error;
  scoped_ptr<Value> meta_value(JSONReader::ReadAndReturnError(
      kpk.metadata(), false /* no trailing comma */, &json_error));
  if (meta_value.get() == nullptr) {
    LOG(ERROR) << "Could not parse keyset metadata: " << json_error;
    return false;
  }
  scoped_ptr<Keyset> ks(new Keyset());
  ks->set_metadata(KeysetMetadata::CreateFromValue(meta_value.get()));
  if (ks->metadata() == nullptr) {
    LOG(ERROR) << "Could not deserialize keyset metadata";
    return false;
  }
  KeyType::Type key_type = ks->metadata()->key_type();
  int key_count = 0;
  for (auto it = ks->metadata()->Begin(); it != ks->metadata()->End(); ++it) {
    int version = it->first;
    if (key_count >= kpk.files_size()) {
      LOG(ERROR) << "Missing key version " << version;
      return false;
    }
    const KeyczarPublicKey::KeyFile &kf = kpk.files(key_count);
    if (kf.name() != version) {
      LOG(ERROR) << "Unexpected key version " << kf.name();
      return false;
    }
    key_count++;
    scoped_ptr<Value> key_value(JSONReader::ReadAndReturnError(
        kf.data(), false /* no trailing comma */, &json_error));
    if (key_value.get() == nullptr) {
      LOG(ERROR) << "Could not parse key data: " << json_error;
      return false;
    }
    scoped_ptr<Key> newkey(Key::CreateFromValue(key_type, *key_value));
    if (!ks->AddKey(newkey.release(), version)) {
      LOG(ERROR) << "Could not add copied key version " << version;
      return false;
    }
    // We can't cleanly copy keyset metadata because the primary key status is
    // tracked in twice: in the metadata
    // (KeysetMetadata::KeyVersion::key_status_)
    // and also in the keyset (Keyset::primary_key_version_number_). These get
    // out
    // of sync. Ideally, Keyset::set_metadata() would update
    // Keyset::primary_key_version_number_.
    // Workaround: demote the primary key then re-promote it.
    if (it->second->key_status() == KeyStatus::PRIMARY) {
      ks->DemoteKey(version);
      ks->PromoteKey(version);
    }
  }
  key->reset(new Verifier(ks.release()));
  if (key->get() == nullptr) {
    LOG(ERROR) << "Could not construct deserialized Verifier";
    return false;
  }
  (*key)->set_encoding(Verifier::NO_ENCODING);
  return true;
}

/// Return the public keytype, if available, corresponding to a given keytype.
/// @param key_type A public, private, or symmetric key type.
static KeyType::Type KeyTypeToPublic(KeyType::Type key_type) {
  // This relies on keyczar's naming convention, which might not be
  // as robust as just enumerating all the KeyType::Type values.
  string name = KeyType::GetNameFromType(key_type);
  size_t n = name.length();
  if (n > 5 && name.substr(n - 5) == "_PRIV")
    return KeyType::GetTypeFromName(name.substr(0, n - 5) + "_PUB");
  else
    return key_type;
}

bool SerializePublicKey(const Verifier &key, string *s) {
  if (s == nullptr) {
    LOG(ERROR) << "Could not serialize to a null string";
    return false;
  }
  scoped_ptr<Value> meta_value(key.keyset()->metadata()->GetValue(true));
  if (meta_value.get() == nullptr) {
    LOG(ERROR) << "Could not serialize keyset metadata";
    return false;
  }
  // If this is actually actually a Signer, we downgrade as we serialize.
  KeyType::Type old_key_type = key.keyset()->metadata()->key_type();
  KeyType::Type new_key_type = KeyTypeToPublic(old_key_type);
  bool downgrade = (new_key_type != old_key_type);
  if (downgrade) {
    // This relies on keyczar's json format.
    if (!meta_value->IsType(Value::TYPE_DICTIONARY)) {
      LOG(ERROR) << "Expecting dictionary from keyczar";
      return false;
    }
    DictionaryValue *dict = static_cast<DictionaryValue *>(meta_value.get());
    dict->SetBoolean("encrypted", false);
    dict->SetString("type", KeyType::GetNameFromType(new_key_type));
    dict->SetString("purpose", "VERIFY");
  }
  KeyczarPublicKey kpk;
  string metadata;
  JSONWriter::Write(meta_value.get(), true /* no pretty print */, &metadata);
  kpk.set_metadata(metadata);
  // fix purpose --> goes to VERIFY, not SIGN_AND_VERIFY
  // fix encrypted --> goes to false
  // fix type --> goes to ECDSA_PUB
  const KeysetMetadata *meta = key.keyset()->metadata();
  for (auto it = meta->Begin(); it != meta->End(); ++it) {
    int version = it->first;
    const Key *k = key.keyset()->GetKey(version);
    if (k == nullptr) {
      LOG(ERROR) << "Missing key version " << version;
      return false;
    }
    scoped_ptr<Value> key_value(downgrade ? k->GetPublicKeyValue()
                                          : k->GetValue());
    if (key_value.get() == nullptr) {
      LOG(ERROR) << "Could not serialize key version " << version;
      return false;
    }
    string keydata;
    JSONWriter::Write(key_value.get(), true /* no pretty print */, &keydata);
    KeyczarPublicKey::KeyFile *kf = kpk.add_files();
    kf->set_name(version);
    kf->set_data(keydata);
  }
  string serialized_pub_key;
  if (!kpk.SerializeToString(s)) {
    LOG(ERROR) << "Could not serialize the key to a string";
    return "";
  }
  return true;
}

bool SignData(const Signer &key, const string &data, const string &context,
              string *signature) {
  if (context.empty()) {
    LOG(ERROR) << "Cannot sign a message with an empty context";
    return false;
  }

  SignedData s;
  s.set_context(context);
  s.set_data(data);
  string serialized;
  if (!s.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the message and context together";
    return false;
  }

  if (!key.Sign(serialized, signature)) {
    LOG(ERROR) << "Could not sign the data";
    return false;
  }

  return true;
}

bool VerifySignature(const Verifier &key, const string &data,
                     const string &context, const string &signature) {
  if (context.empty()) {
    LOG(ERROR) << "Cannot sign a message with an empty context";
    return false;
  }

  SignedData s;
  s.set_context(context);
  s.set_data(data);
  string serialized;
  if (!s.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the message and context together";
    return false;
  }

  if (!key.Verify(serialized, signature)) {
    LOG(ERROR) << "Verify failed";
    return false;
  }

  return true;
}

// Debug code for dumping a keyczar keyset primary key:
// {
//   const Keyset *keyset = key.keyset();
//   const keyczar::Key *primary_key = keyset->primary_key();
//   scoped_ptr<Value> v(primary_key->GetValue());
//   string json;
//   keyczar::base::JSONWriter::Write(v.get(), true /* pretty print */, &json);
//   VLOG(0) << "json for keyset is:\n" << json;
// }

/// Make a (deep) copy of a Keyset.
/// @param keyset The keyset to be copied.
/// @param[out] copy The keyset to fill with the copy.
static bool CopyKeyset(const Keyset &keyset, scoped_ptr<Keyset> *copy) {
  if (copy == nullptr) {
    LOG(ERROR) << "null keyset";
    return false;
  }
  scoped_ptr<Value> meta_value(
      keyset.metadata()->GetValue(true /* "immutable" copy of keyset */));
  if (meta_value.get() == nullptr) {
    LOG(ERROR) << "Could not serialize keyset metadata";
    return false;
  }
  scoped_ptr<Keyset> ks(new Keyset());
  ks->set_metadata(KeysetMetadata::CreateFromValue(meta_value.get()));
  if (ks->metadata() == nullptr) {
    LOG(ERROR) << "Could not deserialize keyset metadata";
    return false;
  }
  KeyType::Type key_type = ks->metadata()->key_type();
  for (auto it = ks->metadata()->Begin(); it != ks->metadata()->End(); ++it) {
    int version = it->first;
    const Key *oldkey = keyset.GetKey(version);
    if (oldkey == nullptr) {
      LOG(ERROR) << "Missing key version " << version;
      return false;
    }
    scoped_ptr<Value> key_value(oldkey->GetValue());
    if (key_value.get() == nullptr) {
      LOG(ERROR) << "Could not serialize key version " << version;
      return false;
    }
    scoped_ptr<Key> newkey(Key::CreateFromValue(key_type, *key_value));
    if (!ks->AddKey(newkey.release(), version)) {
      LOG(ERROR) << "Could not add copied key version " << version;
      return false;
    }
  }
  // We can't cleanly copy keyset metadata because the primary key status is
  // tracked in twice: in the metadata (KeysetMetadata::KeyVersion::key_status_)
  // and also in the keyset (Keyset::primary_key_version_number_). These get out
  // of sync. Ideally, Keyset::set_metadata() would update
  // Keyset::primary_key_version_number_.
  // Workaround: demote the primary key then re-promote it.
  int primary_key = keyset.primary_key_version_number();
  if (primary_key > 0) {
    ks->DemoteKey(primary_key);
    ks->PromoteKey(primary_key);
  }
  copy->reset(ks.release());
  return true;
}

bool CopySigner(const Signer &key, scoped_ptr<Signer> *copy) {
  scoped_ptr<Keyset> keyset;
  if (!CopyKeyset(*key.keyset(), &keyset)) {
    LOG(ERROR) << "Could not copy Signer keyset";
    return false;
  }
  copy->reset(new Signer(keyset.release()));
  if (copy->get() == nullptr) {
    LOG(ERROR) << "Could not construct Signer copy";
    return false;
  }
  (*copy)->set_encoding(Signer::NO_ENCODING);
  return true;
}

bool CopyVerifier(const Verifier &key, scoped_ptr<Verifier> *copy) {
  scoped_ptr<Keyset> keyset;
  if (!CopyKeyset(*key.keyset(), &keyset)) {
    LOG(ERROR) << "Could not copy Verifier keyset";
    return false;
  }
  copy->reset(new Verifier(keyset.release()));
  if (copy->get() == nullptr) {
    LOG(ERROR) << "Could not construct Verifier copy";
    return false;
  }
  (*copy)->set_encoding(Verifier::NO_ENCODING);
  return true;
}

bool CopyCrypter(const Crypter &key, scoped_ptr<Crypter> *copy) {
  scoped_ptr<Keyset> keyset;
  if (!CopyKeyset(*key.keyset(), &keyset)) {
    LOG(ERROR) << "Could not copy Crypter keyset";
    return false;
  }
  copy->reset(new Crypter(keyset.release()));
  if (copy->get() == nullptr) {
    LOG(ERROR) << "Could not construct Crypter copy";
    return false;
  }
  (*copy)->set_encoding(Crypter::NO_ENCODING);
  return true;
}

bool DeriveKey(const keyczar::Signer &key, const string &name, int size,
               string *material) {
  if (material == nullptr) {
    LOG(ERROR) << "Invalid DeriveKey parameters";
    return false;
  }
  if (key.keyset()->metadata()->key_type() != keyczar::KeyType::HMAC) {
    LOG(ERROR) << "DeriveKey requires symmetric main key";
    return false;
  }
  // derive the keys
  string context = "1 || " + name;
  keyczar::base::ScopedSafeString sig(new string());
  // Note that this is not an application of a signature in the normal sense, so
  // it does not need to be transformed into an application of tao::SignData.
  if (!key.Sign(context, sig.get())) {
    LOG(ERROR) << "Could not derive key material";
    return false;
  }
  // skip the header to get the bytes
  size_t header_size = keyczar::Key::GetHeaderSize();
  if (size + header_size > sig->size()) {
    LOG(ERROR) << "There were not enough bytes to get the derived key";
    return false;
  }
  material->assign(sig->data() + header_size, size);
  return true;
}

typedef scoped_ptr_malloc<BIGNUM, CallUnlessNull<BIGNUM, BN_clear_free> >
    ScopedBIGNUM;

static bool ExportKeysetToOpenSSL(const Keyset &keyset, bool include_private,
                                  ScopedEvpPkey *evp_key) {
  // Note: Much of this function is adapted from code in
  // keyczar::openssl::ECDSAOpenSSL::Create().
  // TODO(kwalsh) Implement this function for RSA, other types
  KeyType::Type key_type = keyset.metadata()->key_type();
  if (key_type != KeyType::ECDSA_PUB && key_type != KeyType::ECDSA_PRIV) {
    LOG(ERROR) << "ExportKeysetToOpenSSL only implemented for ECDSA so far";
    return false;
  }
  // Get raw key data out of keyczar
  // see also: GetPublicKeyValue()
  scoped_ptr<Value> value(keyset.primary_key()->GetValue());
  CHECK(value->IsType(Value::TYPE_DICTIONARY));
  DictionaryValue *dict = static_cast<DictionaryValue *>(value.get());
  string curve_name, public_curve_name;
  string private_base64, public_base64, private_bytes, public_bytes;
  bool has_private = dict->HasKey("privateKey");
  if (has_private) {
    if (!dict->GetString("namedCurve", &curve_name) ||
        !dict->GetString("privateKey", &private_base64) ||
        !dict->GetString("publicKey.namedCurve", &public_curve_name) ||
        !dict->GetString("publicKey.publicBytes", &public_base64)) {
      LOG(ERROR) << "Keyczar key missing expected values";
      return false;
    }
    if (public_curve_name != curve_name) {
      LOG(ERROR) << "Keyczar key curve mismatch";
      return false;
    }
  } else {
    if (!dict->GetString("namedCurve", &curve_name) ||
        !dict->GetString("publicBytes", &public_base64)) {
      LOG(ERROR) << "Keyczar key missing expected values";
      return false;
    }
  }
  if (!Base64WDecode(public_base64, &public_bytes)) {
    LOG(ERROR) << "Could not decode keyczar public key data";
    return false;
  }
  if (has_private && !Base64WDecode(private_base64, &private_bytes)) {
    LOG(ERROR) << "Could not decode keyczar private key data";
    return false;
  }
  // check curve name
  int curve_nid = OBJ_sn2nid(curve_name.c_str());  // txt2nid
  if (!OpenSSLSuccess() || curve_nid == NID_undef) {
    LOG(ERROR) << "Keyczar key uses unrecognized ec curve " << curve_name;
    return false;
  }
  ScopedECKey ec_key(EC_KEY_new_by_curve_name(curve_nid));
  if (!OpenSSLSuccess() || ec_key.get() == NULL) {
    LOG(ERROR) << "Could not allocate EC_KEY";
    return false;
  }
  // Make sure the ASN1 will have curve OID should this EC_KEY be exported.
  EC_KEY_set_asn1_flag(ec_key.get(), OPENSSL_EC_NAMED_CURVE);
  // public_key
  EC_KEY *key_tmp = ec_key.get();
  const unsigned char *public_key_bytes =
      reinterpret_cast<const unsigned char *>(public_bytes.data());
  if (!o2i_ECPublicKey(&key_tmp, &public_key_bytes, public_bytes.length())) {
    OpenSSLSuccess();  // print errors
    LOG(ERROR) << "Could not convert keyczar public key to openssl";
    return false;
  }
  // private_key
  if (include_private) {
    if (!has_private) {
      LOG(ERROR) << "Missing private key during export";
      return false;
    }
    const unsigned char *private_key_bytes =
        reinterpret_cast<const unsigned char *>(private_bytes.data());
    ScopedBIGNUM bn(
        BN_bin2bn(private_key_bytes, private_bytes.length(), nullptr));
    if (!OpenSSLSuccess() || bn.get() == NULL) {
      LOG(ERROR) << "Could not parse keyczar private key data";
      return false;
    }
    if (!EC_KEY_set_private_key(ec_key.get(), bn.get())) {
      OpenSSLSuccess();  // print errors
      LOG(ERROR) << "Could not convert keyczar private key to openssl";
      return false;
    }
    bn.reset();
  }
  // final sanity check
  if (!EC_KEY_check_key(ec_key.get())) {
    OpenSSLSuccess();  // print errors
    LOG(ERROR) << "Converted OpenSSL key fails checks";
    return false;
  }
  // Move EC_KEY into EVP_PKEY
  ScopedEvpPkey new_evp_key(EVP_PKEY_new());
  if (!OpenSSLSuccess() || new_evp_key.get() == NULL) {
    LOG(ERROR) << "Could not allocate EVP_PKEY";
    return false;
  }
  if (!EVP_PKEY_set1_EC_KEY(new_evp_key.get(), ec_key.get())) {
    LOG(ERROR) << "Could not convert EC_KEY to EVP_PKEY";
    return false;
  }

  evp_key->reset(new_evp_key.release());

  return true;
}

bool ExportPrivateKeyToOpenSSL(const Signer &key, ScopedEvpPkey *evp_key) {
  if (evp_key == nullptr) {
    LOG(ERROR) << "null evp_key";
    return false;
  }
  return ExportKeysetToOpenSSL(*key.keyset(), true /* private too */, evp_key);
}

bool ExportPublicKeyToOpenSSL(const Verifier &key, ScopedEvpPkey *evp_key) {
  if (evp_key == nullptr) {
    LOG(ERROR) << "null evp_key";
    return false;
  }
  return ExportKeysetToOpenSSL(*key.keyset(), false /* only public */, evp_key);
}

/// Set one detail for an openssl x509 name structure.
/// @param name The x509 name structure to modify. Must be non-null.
/// @param key The country code, e.g. "US"
/// @param id The detail id, e.g. "C" for country or "CN' for common name
/// @param val The value to be set
static void SetX509NameDetail(X509_NAME *name, const string &id,
                              const string &val) {
  X509_NAME_add_entry_by_txt(
      name, id.c_str(), MBSTRING_ASC,
      reinterpret_cast<unsigned char *>(const_cast<char *>(val.c_str())), -1,
      -1, 0);
  if (!OpenSSLSuccess())
    LOG(WARNING) << "Could not set x509 " << id << " detail";
}

/// Set the details for an openssl x509 name structure.
/// @param name The x509 name structure to modify. Must be non-null.
/// @param c The country code, e.g. "US".
/// @param o The organization code, e.g. "Google"
/// @param st The state code, e.g. "Washington"
/// @param cn The common name, e.g. "Example Tao CA Service" or "localhost"
static void SetX509NameDetails(X509_NAME *name, const X509Details &details) {
  if (details.has_country()) SetX509NameDetail(name, "C", details.country());
  if (details.has_state()) SetX509NameDetail(name, "ST", details.state());
  if (details.has_organization())
    SetX509NameDetail(name, "O", details.organization());
  if (details.has_commonname())
    SetX509NameDetail(name, "CN", details.commonname());
}

/// Prepare an X509 structure for signing by filling in version numbers, serial
/// numbers, the subject key, and reasonable timestamps.
/// @param x509 The certificate to modify. Must be non-null.
/// @param version The x509 version number to set. Numbers are off-by-1, so for
/// x509v3 use version=2, etc.
/// @param serial The x509 serial number to set.
/// @param The subject key to set.
static bool PrepareX509(X509 *x509, int version, int serial,
                        EVP_PKEY *subject_key) {
  X509_set_version(x509, version);

  ASN1_INTEGER_set(X509_get_serialNumber(x509), serial);

  // set notBefore and notAfter to get a reasonable validity period
  X509_gmtime_adj(X509_get_notBefore(x509), 0);
  X509_gmtime_adj(X509_get_notAfter(x509), Tao::DefaultAttestationTimeout);

  // This method allocates a new public key for x509, and it doesn't take
  // ownership of the key passed in the second parameter.
  X509_set_pubkey(x509, subject_key);
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Could not add the public key to the X.509 structure";
    return false;
  }

  return true;
}

/// Add an extension to an openssl x509 structure.
/// @param x509 The certificate to modify. Must be non-null.
/// @param nid The NID_* constant for this extension.
/// @param val The string value to be added.
static void AddX509Extension(X509 *x509, int nid, const string &val) {
  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, x509, x509, nullptr, nullptr, 0);

  char *data = const_cast<char *>(val.c_str());
  X509_EXTENSION *ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, data);
  if (!OpenSSLSuccess() || ex == nullptr) {
    LOG(WARNING) << "Could not add x509 extension";
    return;
  }
  X509_add_ext(x509, ex, -1);
  X509_EXTENSION_free(ex);
}

// x509 serialization in DER format
// bool SerializeX509(X509 *x509, string *der) {
//   if (x509 == nullptr ||| der == nullptr) {
//     LOG(ERROR) << "null params";
//     return false;
//   }
//   unsigned char *serialization = nullptr;
//   len = i2d_X509(x509, &serialization);
//   scoped_ptr_malloc<unsigned char> der_x509(serialization);
//   if (!OpenSSLSuccess() || len < 0) {
//     LOG(ERROR) << "Could not encode an X.509 certificate in DER";
//     return false;
//   }
//   der->assign(reinterpret_cast<char *>(der_x509.get()), len);
//   return true;
// }

bool SerializeX509(X509 *x509, string *pem) {
  if (x509 == nullptr || pem == nullptr) {
    LOG(ERROR) << "null params";
    return false;
  }
  ScopedBio mem(BIO_new(BIO_s_mem()));
  if (!PEM_write_bio_X509(mem.get(), x509) || !OpenSSLSuccess()) {
    LOG(ERROR) << "Could not serialize x509 to PEM";
    return false;
  }
  BUF_MEM *buf;
  BIO_get_mem_ptr(mem.get(), &buf);
  pem->assign(buf->data, buf->length);
  return true;
}

bool CreateSelfSignedX509(const Signer &key, const X509Details &details,
                          const string &public_cert_path) {
  // we need an openssl version of the key to create and sign the x509 cert
  ScopedEvpPkey evp_key;
  if (!ExportPrivateKeyToOpenSSL(key, &evp_key)) return false;

  // create the x509 structure
  ScopedX509 x509(X509_new());
  int version = 2;  // self sign uses version=2 (which is x509v3)
  int serial = 1;   // self sign can always use serial 1
  PrepareX509(x509.get(), version, serial, evp_key.get());

  // set up the subject and issuer details to be the same
  X509_NAME *subject = X509_get_subject_name(x509.get());
  SetX509NameDetails(subject, details);

  X509_NAME *issuer = X509_get_issuer_name(x509.get());
  SetX509NameDetails(issuer, details);

  AddX509Extension(x509.get(), NID_basic_constraints, "critical,CA:TRUE");
  AddX509Extension(x509.get(), NID_subject_key_identifier, "hash");
  AddX509Extension(x509.get(), NID_authority_key_identifier, "keyid:always");

  X509_sign(x509.get(), evp_key.get(), EVP_sha1());
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Could not perform self-signing on the X.509 cert";
    return false;
  }

  string pem;
  if (!SerializeX509(x509.get(), &pem) ||
      !CreateDirectory(FilePath(public_cert_path).DirName()) ||
      !WriteStringToFile(public_cert_path, pem)) {
    LOG(ERROR) << "Could not write x509 to " << public_cert_path;
    return false;
  }
  return true;
}

static int no_password_callback(char *buf, int size, int rwflag, void *u) {
  return 0;  // return error
}

Keys::Keys(const string &nickname, int key_types)
    : key_types_(key_types), nickname_(nickname) {}

Keys::Keys(const string &path, const string &nickname, int key_types)
    : key_types_(key_types), path_(path), nickname_(nickname) {}

Keys::Keys(keyczar::Verifier *verifying_key, keyczar::Signer *signing_key,
           keyczar::Signer *derivation_key, keyczar::Crypter *crypting_key)
    : verifier_(verifying_key),
      signer_(signing_key),
      key_deriver_(derivation_key),
      crypter_(crypting_key) {}

Keys::~Keys() {}

bool CreateCASignedX509(const Signer &ca_key, const string &ca_cert_path,
                        int cert_serial, const Verifier &subject_key,
                        const X509Details &subject_details, string *pem_cert) {
  if (!pem_cert) {
    LOG(ERROR) << "null pem";
    return false;
  }
  // we need openssl versions of the keys to create and sign the x509 cert
  ScopedEvpPkey ca_evp_key;
  if (!ExportPrivateKeyToOpenSSL(ca_key, &ca_evp_key)) {
    LOG(ERROR) << "Could not export ca key to openssl";
    return false;
  }
  ScopedEvpPkey subject_evp_key;
  if (!ExportPublicKeyToOpenSSL(subject_key, &subject_evp_key)) {
    LOG(ERROR) << "Could not export subject key to openssl";
    return false;
  }
  // load the ca cert and extract ca details
  ScopedFile ca_cert_file(fopen(ca_cert_path.c_str(), "rb"));
  if (ca_cert_file.get() == nullptr) {
    PLOG(ERROR) << "Could not read " << ca_cert_path;
    return false;
  }
  ScopedX509 ca_x509(PEM_read_X509(ca_cert_file.get(), nullptr /* ptr */,
                                   no_password_callback, nullptr /* cbdata */));
  if (!OpenSSLSuccess() || ca_x509.get() == nullptr) {
    LOG(ERROR) << "Could not write the X.509 certificate to " << ca_cert_path;
    return false;
  }

  // create the x509 structure
  ScopedX509 x509(X509_new());
  int version = 0;  // ca-sign uses version=0 (which is x509v1)
  PrepareX509(x509.get(), version, cert_serial, subject_evp_key.get());

  // set up the subject details
  X509_NAME *subject = X509_get_subject_name(x509.get());
  SetX509NameDetails(subject, subject_details);

  // copy the issuer details from ca_cert
  X509_NAME *issuer = X509_get_issuer_name(ca_x509.get());
  X509_set_issuer_name(x509.get(), issuer);

  X509_sign(x509.get(), ca_evp_key.get(), EVP_sha1());
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Could not perform ca-signing on the X.509 cert";
    return false;
  }

  string ca_pem, subject_pem;
  if (!SerializeX509(x509.get(), &subject_pem) ||
      !SerializeX509(ca_x509.get(), &ca_pem)) {
    LOG(ERROR) << "Could not serialize x509 certificates";
    return false;
  }
  pem_cert->assign(subject_pem + ca_pem);
  return true;
}

bool Keys::InitTemporary() {
  // Generate temporary keys.
  if ((key_types_ & Type::Crypting &&
       !GenerateCryptingKey(nickname_ + "_crypting", &crypter_)) ||
      (key_types_ & Type::Signing &&
       !GenerateSigningKey(nickname_ + "_signing", &signer_)) ||
      (key_types_ & Type::KeyDeriving &&
       !GenerateKeyDerivingKey(nickname_ + "_key_deriving", &key_deriver_))) {
    LOG(ERROR) << "Could not generate temporary keys";
    return false;
  }
  fresh_ = true;
  return true;
}

bool Keys::InitNonHosted(const string &password) {
  if (password.empty()) {
    // Load unprotected verifying key.
    if (key_types_ != Type::Signing) {
      LOG(ERROR) << "With no password, only a signing public key can be loaded";
      return false;
    }
    if (!LoadVerifierKey(SigningPublicKeyPath(), &verifier_)) {
      LOG(ERROR) << "Could not load verifying key";
      return false;
    }
    fresh_ = false;
  } else if ((key_types_ & Type::Crypting &&
              !DirectoryExists(FilePath(CryptingKeyPath()))) ||
             (key_types_ & Type::Signing &&
              !DirectoryExists(FilePath(SigningPrivateKeyPath()))) ||
             (key_types_ & Type::KeyDeriving &&
              !DirectoryExists(FilePath(KeyDerivingKeyPath())))) {
    // Generate PBE-protected keys.
    if ((key_types_ & Type::Crypting &&
         !GenerateCryptingKey(nickname_ + "_crypting", password, CryptingKeyPath(),
                              &crypter_)) ||
        (key_types_ & Type::Signing &&
         !GenerateSigningKey(nickname_ + "_signing", password,
                             SigningPrivateKeyPath(), SigningPublicKeyPath(),
                             &signer_)) ||
        (key_types_ & Type::KeyDeriving &&
         !GenerateKeyDerivingKey(nickname_ + "_key_deriving", password,
                                 KeyDerivingKeyPath(), &key_deriver_))) {
      LOG(ERROR) << "Could not generate protected keys";
      return false;
    }
    fresh_ = true;
  } else {
    // Load PBE-protected keys.
    if ((key_types_ & Type::Crypting &&
         !LoadCryptingKey(CryptingKeyPath(), password, &crypter_)) ||
        (key_types_ & Type::Signing &&
         !LoadSigningKey(SigningPrivateKeyPath(), password, &signer_)) ||
        (key_types_ & Type::KeyDeriving &&
         !LoadKeyDerivingKey(KeyDerivingKeyPath(), password, &key_deriver_))) {
      LOG(ERROR) << "Could not load protected keys";
      return false;
    }
    fresh_ = false;
  }
  return true;
}

bool Keys::InitHosted(const Tao &tao, const string &policy) {
  ScopedSafeString secret(new string());
  if (PathExists(FilePath(SecretPath()))) {
    // Load Tao-protected secret.
    if (!GetSealedSecret(tao, SecretPath(), policy, secret.get())) {
      LOG(ERROR) << "Could not unseal a secret using the Tao";
      return false;
    }
  } else {
    // Generate Tao-protected secret.
    int secret_size = DefaultRandomSecretSize;
    if (!MakeSealedSecret(tao, SecretPath(), policy, secret_size, secret.get())) {
      LOG(ERROR) << "Could not generate and seal a secret using the Tao";
      return false;
    }
  }
  // Load or generate keys using the Tao-protected secret.
  if (!InitNonHosted(*secret)) {
    LOG(ERROR) << "Could not initialize Tao-protected keys";
    return false;
  }
  // Create a delegation for the signing key from the host Tao.
  if (signer_.get() != nullptr) {
    string filename = DelegationPath("host");
    if (PathExists(FilePath(filename))) {
      if (!ReadFileToString(filename, &host_delegation_)) {
        LOG(ERROR) << "Could not load delegation for signing key";
        return false;
      }
    } else {
      string key_name;
      if (!GetPrincipalName(&key_name)) {
        LOG(ERROR) << "Could not get principal name for signing key";
        return false;
      }
      Statement stmt;
      stmt.set_delegate(key_name);
      if (!tao.Attest(stmt, &host_delegation_)) {
        LOG(ERROR) << "Could not get delegation for signing key";
        return false;
      }
      if (!WriteStringToFile(DelegationPath("host"), host_delegation_)) {
        LOG(ERROR) << "Could not store delegation for signing key";
        return false;
      }
    }
  }
  return true;
}

bool VerifierToPrincipalName(const Verifier &key, string *name) {
  string key_data, key_text;
  if (!SerializePublicKey(key, &key_data) ||
      !Base64WEncode(key_data, &key_text)) {
    LOG(ERROR) << "Could not serialize public signing key";
    return false;
  }
  stringstream out;
  out << "Key(" << quotedString(key_text) << ")";
  name->assign(out.str());
  return true;
}

bool VerifierFromPrincipalName(const string &name, scoped_ptr<Verifier> *key) {
  string key_text;
  stringstream in(name);
  skip(in, "Key(");
  getQuotedString(in, &key_text);
  skip(in, ")");
  if (!in || !in.str().empty()) {
    LOG(ERROR) << "Bad format for Tao signer principal name";
    return false;
  }
  string key_data;
  if (!Base64WDecode(key_text, &key_data) ||
      !DeserializePublicKey(key_data, key)) {
    LOG(ERROR) << "Could not deserialize the Tao signer key";
    return false;
  }
  return true;
}

bool Keys::GetPrincipalName(string *name) const {
  if (!Verifier()) {
    LOG(ERROR) << "No managed verifier";
    return false;
  }
  return tao::VerifierToPrincipalName(*Verifier(), name);
}

bool Keys::GetHostDelegation(string *attestation) const {
  if (host_delegation_.empty()) {
    LOG(ERROR) << "No host delegation";
    return false;
  }
  attestation->assign(host_delegation_);
  return true;
}

string Keys::GetPath(const string &suffix) const {
  return FilePath(path_).Append(suffix).value();
}

Keys *Keys::DeepCopy() const {
  scoped_ptr<Keys> other(new Keys(nickname_, path_, key_types_));
  if ((verifier_.get() && !tao::CopyVerifier(*verifier_, &other->verifier_)) ||
      (signer_.get() && !tao::CopySigner(*signer_, &other->signer_)) ||
      (key_deriver_.get() &&
       !tao::CopySigner(*key_deriver_, &other->key_deriver_)) ||
      (crypter_.get() && !tao::CopyCrypter(*crypter_, &other->crypter_))) {
    LOG(ERROR) << "Could not copy managed keys";
    return nullptr;
  }
  other->fresh_ = fresh_;
  return other.release();
}

Verifier *Keys::Verifier() const {
  if (verifier_.get() != nullptr)
    return verifier_.get();
  else
    return signer_.get();
}

bool Keys::SerializePublicKey(string *s) const {
  if (!Verifier()) {
    LOG(ERROR) << "No managed verifier";
    return false;
  }
  return tao::SerializePublicKey(*Verifier(), s);
}

bool Keys::Sign(const string &data, const string &context,
                string *signature) const {
  if (!Signer()) {
    LOG(ERROR) << "No managed signer";
    return false;
  }
  return tao::SignData(*Signer(), data, context, signature);
}

bool Keys::Verify(const string &data, const string &context,
                  const string &signature) const {
  if (!Verifier()) {
    LOG(ERROR) << "No managed verifier";
    return false;
  }
  return tao::VerifySignature(*Verifier(), data, context, signature);
}

bool Keys::Encrypt(const string &data, string *encrypted) const {
  if (!Crypter()) {
    LOG(ERROR) << "No managed crypter";
    return false;
  }
  return Crypter()->Encrypt(data, encrypted);
}

bool Keys::Decrypt(const string &encrypted, string *data) const {
  if (!Crypter()) {
    LOG(ERROR) << "No managed crypter";
    return false;
  }
  return Crypter()->Decrypt(encrypted, data);
}

bool Keys::CopySigner(scoped_ptr<keyczar::Signer> *copy) const {
  if (!Signer()) {
    LOG(ERROR) << "No managed signer";
    return false;
  }
  return tao::CopySigner(*Signer(), copy);
}

bool Keys::CopyKeyDeriver(scoped_ptr<keyczar::Signer> *copy) const {
  if (!KeyDeriver()) {
    LOG(ERROR) << "No managed key-deriver";
    return false;
  }
  return tao::CopySigner(*KeyDeriver(), copy);
}

bool Keys::CopyVerifier(scoped_ptr<keyczar::Verifier> *copy) const {
  if (!Verifier()) {
    LOG(ERROR) << "No managed verifier";
    return false;
  }
  return tao::CopyVerifier(*Verifier(), copy);
}

bool Keys::CopyCrypter(scoped_ptr<keyczar::Crypter> *copy) const {
  if (!Crypter()) {
    LOG(ERROR) << "No managed crypter";
    return false;
  }
  return tao::CopyCrypter(*Crypter(), copy);
}

bool Keys::DeriveKey(const string &name, int size, string *material) const {
  if (!KeyDeriver()) {
    LOG(ERROR) << "No managed key-deriver";
    return false;
  }
  return tao::DeriveKey(*KeyDeriver(), name, size, material);
}

bool Keys::ExportSignerToOpenSSL(ScopedEvpPkey *evp_key) const {
  if (!Signer()) {
    LOG(ERROR) << "No managed signer";
    return false;
  }
  return tao::ExportPrivateKeyToOpenSSL(*Signer(), evp_key);
}

bool Keys::ExportVerifierToOpenSSL(ScopedEvpPkey *evp_key) const {
  if (!Verifier()) {
    LOG(ERROR) << "No managed verifier";
    return false;
  }
  return tao::ExportPublicKeyToOpenSSL(*Verifier(), evp_key);
}

bool Keys::CreateSelfSignedX509(const X509Details &details) const {
  if (!Signer()) {
    LOG(ERROR) << "No managed signer";
    return false;
  }
  string path = SigningX509CertificatePath();
  return tao::CreateSelfSignedX509(*Signer(), details, path);
}

bool Keys::CreateSelfSignedX509(const string &details_text) const {
  X509Details details;
  if (!TextFormat::ParseFromString(details_text, &details)) {
    LOG(ERROR) << "Could not parse x509 details";
    return false;
  }
  return CreateSelfSignedX509(details);
}

bool Keys::CreateCASignedX509(int cert_serial,
                              const keyczar::Verifier &subject_key,
                              const X509Details &subject_details,
                              string *pem_cert) const {
  if (!Signer()) {
    LOG(ERROR) << "No managed signer";
    return false;
  }
  string ca_cert_path = SigningX509CertificatePath();
  return tao::CreateCASignedX509(*Signer(), ca_cert_path, cert_serial,
                                 subject_key, subject_details, pem_cert);
}

}  // namespace tao
