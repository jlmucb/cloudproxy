//  File : keys.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Cryptographic key utilities for the Tao.
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
#ifndef TAO_KEYS_H_
#define TAO_KEYS_H_

#include <string>

#include <openssl/bio.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "tao/keys.pb.h"
#include "tao/tao.h"
#include "tao/util.h"

namespace tao {
using std::string;

/// A variety of utilities and OpenSSL wrappers.
/// @{

/// Cleanse the contents of a string.
/// @param s The string to be cleansed.
void SecureStringErase(string *s);

/// A smart pointer to an OpenSSL X509 structure.
typedef scoped_ptr_malloc<X509, CallUnlessNull<X509, X509_free>> ScopedX509;

/// A smart pointer to an OpenSSL EVP_PKEY object.
typedef scoped_ptr_malloc<EVP_PKEY, CallUnlessNull<EVP_PKEY, EVP_PKEY_free>>
    ScopedEvpPkey;

/// A smart pointer to an OpenSSL RSA object.
typedef scoped_ptr_malloc<RSA, CallUnlessNull<RSA, RSA_free>> ScopedRsa;

/// A smart pointer to an OpenSSL EC_KEY object.
typedef scoped_ptr_malloc<EC_KEY, CallUnlessNull<EC_KEY, EC_KEY_free>> ScopedEc;

/// A smart pointer to an OpenSSL BIO object.
typedef scoped_ptr_malloc<BIO, CallUnlessNull<BIO, BIO_free_all>> ScopedBio;

/// A smart pointer to an OpenSSL EC_KEY object.
typedef scoped_ptr_malloc<EC_KEY, CallUnlessNull<EC_KEY, EC_KEY_free>>
    ScopedECKey;

/// Serialize an openssl X509 structure in PEM format.
/// @param x509 The certificate to serialize.
string SerializeX509(X509 *x509);

/// Deserialize an openssl X509 structure from PEM format.
/// @param pem The serialized certificate.
X509 *DeserializeX509(const string &pem);

/// @}

class Verifier;

/// A Signer represents the private half of an asymmetric key pair to be used
/// for signing data. Currently this only supports 256-bit ECDSA_SHA with the
/// prime256v1 curve.
class Signer {
 public:
  /// Construct a signer from an OpenSSL key.
  /// @param key The key. Ownership is taken.
  explicit Signer(EC_KEY *key) : key_(key) {}

  /// Generate signing key with default algorithm and parameters.
  static Signer *Generate();

  /// Get the public half of this key as a Verifier.
  Verifier *GetVerifier() const;

  /// Sign data.
  /// @param data The data to sign.
  /// @param context The context string to add to the tao::Signature.
  /// WARNING: For security, this must be unique for each context in which
  /// signed messages are used.
  /// @param[out] signature The resulting signature.
  bool Sign(const string &data, const string &context, string *signature) const;

  // TODO(kwalsh) Add Verify method here if needed.

  /// Serialize to a plain-text Tao principal name. This is a base64w-encoded
  /// version of a serialized CryptoKey for the public half of this signing key.
  string ToPrincipalName() const;

  /// Serialize signing key as PEM-encoded PKCS#8 with password-based
  /// encryption.
  /// @param password A password to encrypt the key material.
  string SerializeWithPassword(const string &password) const;

  /// Deserialize key from PEM-encoded PKCS#8 with with password-based
  /// encryption.
  /// @param serialized The serialized signing key.
  /// @param password The password to decrypt the key material.
  static Signer *DeserializeWithPassword(const string &serialized,
                                         const string &password);

  /// Create a self-signed X509 certificate for the corresponding public key.
  /// @param details Text-format encoded X509Details for the subject.
  string CreateSelfSignedX509(const string &details_text) const;

  /// Create a signed X509 certificate for some other subject's key.
  /// @param cert_serial The serial number to use for the new certificate.
  /// @param subject_key The subject's key.
  /// @param subject_details The x509 details for the subject.
  string CreateSignedX509(const string &ca_pem_cert, int cert_serial,
                          const Verifier &subject_key,
                          const string &subject_details) const;

  /// Encode signing key as CryptoKey protobuf message.
  /// @param[out] m A protobuf in which to encode the key.
  bool Encode(CryptoKey *m) const;

  /// Encode public half of signing key as CryptoKey protobuf message.
  /// @param[out] m A protobuf in which to encode the public key.
  bool EncodePublic(CryptoKey *m) const;

  /// Decode signing key from CryptoKey protobuf message.
  /// @param m A protobuf from which to decode the key.
  static Signer *Decode(const CryptoKey &m);

  /// Fill in a header with version and key-hint.
  /// @param[out] h The protobuf to fill.
  bool Header(CryptoHeader *h) const;

  /// Get a copy of the signer as an EVP_PKEY.
  EVP_PKEY *GetEvpPkey() const;

  /// Create a deep copy of this key.
  Signer *DeepCopy() const;

  // Clear or erase?

 private:
  /// Handle to OpenSSL key.
  /// TODO(kwalsh) Use EVP_KEY here and EVP_DigestSign* functions?
  const ScopedECKey key_;

  DISALLOW_COPY_AND_ASSIGN(Signer);
};

/// A Verifier represents the public half of an asymmetric key pair to be used
/// for verifying signatures. Currently this only supports 256-bit ECDSA_SHA
/// with the prime256v1 curve.
class Verifier {
 public:
  /// Construct a verifier from an OpenSSL key.
  /// @param key The key. Ownership is taken.
  explicit Verifier(EC_KEY *key) : key_(key) {}

  /// Verify a signature.
  /// @param data The data that was signed.
  /// @param context The context to check in the tao::Signature.
  /// @param signature The signature on the data.
  bool Verify(const string &data, const string &context,
              const string &signature) const;

  /// Serialize to a plain-text Tao principal name. This is a base64w-encoded
  /// version of a serialized CryptoKey.
  string ToPrincipalName() const;

  /// Deserialize from a plain-text Tao principal name.
  /// @param name The serialized principal name.
  static Verifier *FromPrincipalName(const string &name);

  /// Load a key from a previously validated X509 certificate.
  /// @param pem_cert The serialized PEM-encoded self-signed certificate.
  static Verifier *FromX509(const string &pem_cert);

  /// Encode verifying key as CryptoKey protobuf message.
  /// @param[out] m A protobuf in which to encode the key.
  bool Encode(CryptoKey *m) const;

  /// Decode verifying key from CryptoKey protobuf message.
  /// @param m A protobuf from which to decode the key.
  static Verifier *Decode(const CryptoKey &m);

  /// Fill in a header with version and key-hint.
  /// @param[out] h The protobuf to fill.
  bool Header(CryptoHeader *h) const;

  /// Get a copy of the verifier as an EVP_PKEY.
  EVP_PKEY *GetEvpPkey() const;

  /// Create a deep copy of this key.
  Verifier *DeepCopy() const;

 private:
  /// Handle to an OpenSSL ECDSA key.
  const ScopedECKey key_;

  DISALLOW_COPY_AND_ASSIGN(Verifier);
};

// A Deriver represents a secret symmetric key to be used for deriving secret
// key material or other random secrets. Currently this only supports
// HKDF with HMAC-SHA256.
class Deriver {
 public:
  /// Construct a deriver from HMAC-SHA256 key material.
  /// @param key The key. Ownership is taken.
  explicit Deriver(const string &key) : key_(new string(key)) {}

  /// Generate deriver key with default algorithm and parameters.
  static Deriver *Generate();

  /// Derive secrets.
  /// @param size The number of bytes to generate.
  /// @param context A context string or tag.
  /// @param[out] secret The resulting secret data.
  bool Derive(size_t size, const string &context, string *secret) const;

  /// Encode deriving key as CryptoKey protobuf message.
  /// @param[out] m A protobuf in which to encode the key.
  bool Encode(CryptoKey *m) const;

  /// Decode deriving key from CryptoKey protobuf message.
  /// @param m A protobuf from which to decode the key.
  static Deriver *Decode(const CryptoKey &m);

  // Note: This is never used because deriver never leaves a key hint anywhere.
  // Fill in a header with version and key-hint.
  // @param[out] h The protobuf to fill.
  // bool Header(CryptoHeader *h) const;

  /// Create a deep copy of this key.
  Deriver *DeepCopy() const;

  // Clear or erase?

 private:
  /// The secret key.
  const ScopedSafeString key_;

  DISALLOW_COPY_AND_ASSIGN(Deriver);
};

// A Crypter represents a secret symmetric key to be used for encryption and
// decryption. Currently this only supports AES256 CTR with HMAC-SHA256.
class Crypter {
 public:
  Crypter(const string &aesKey, const string &hmacKey)
      : aesKey_(new string(aesKey)), hmacKey_(new string(hmacKey)) {}

  /// Generate crypting key with default algorithm and parameters.
  static Crypter *Generate();

  /// Encrypt data.
  /// @param data The data to be encrypted.
  /// @param[out] encrypted The encrypted data.
  bool Encrypt(const string &data, string *encrypted) const;

  /// Decrypt data.
  /// @param encrypted The encrypted data.
  /// @param[out] data The decrypted data.
  bool Decrypt(const string &encrypted, string *data) const;

  /// Encode crypting key as CryptoKey protobuf message.
  /// @param[out] m A protobuf in which to encode the key.
  bool Encode(CryptoKey *m) const;

  /// Decode crypting key from CryptoKey protobuf message.
  /// @param m A protobuf from which to decode the key.
  static Crypter *Decode(const CryptoKey &m);

  /// Fill in a header with version and key-hint.
  /// @param[out] h The protobuf to fill.
  bool Header(CryptoHeader *h) const;

  /// Create a deep copy of this key.
  Crypter *DeepCopy() const;

  // Clear or erase?

 private:
  /// The secret keys.
  const ScopedSafeString aesKey_, hmacKey_;

  DISALLOW_COPY_AND_ASSIGN(Crypter);
};

/// A Keys object manages a group of cryptographic signing, crypting, and
/// deriving keys, along with various related delegations and certificates.
/// Typically the group is stored together on disk, but temporary key sets not
/// stored on disk are also supported, e.g. for testing. Currently, at most one
/// of each type of key can be held in a single Keys object, and there is no
/// provision for rekeying (i.e. key versioning or lifetimes).
class Keys {
 public:
  /// Flags used in Keys constructor for declaring which keys should be managed.
  enum KeyType {
    Signing = 1,  // Implicitly includes verifying key as well.
    Crypting = 2,
    Deriving = 4
  };

  /// Construct a new Keys object to manage a group of temporary keys.
  /// InitTemporary() or InitTemporaryHosted() should be called before using the
  /// object.
  /// @param key_type One or more of the Keys::Type flags.
  explicit Keys(int key_types) : key_types_(key_types) {}

  /// Construct a new Keys object to manage a group of on-disk keys.
  /// InitWithPassword() or InitHosted() should be called before using the
  /// object.
  /// @param path The directory under which all keys are stored.
  /// @param key_type One or more of the Keys::Type flags.
  Keys(const string &path, int key_types)
      : key_types_(key_types), path_(new string(path)) {}

  /// Initialize a group of temporary keys. Fresh keys are generated, and none
  /// of the keys are stored on disk. Unit tests use this initializer.
  bool InitTemporary();

  /// Initialize a group of temporary keys. Fresh keys are generated, and none
  /// of the keys are stored on disk. A delegation is created if a signing key
  /// was requested, otherwise this behaves identically to InitTemporary().
  bool InitTemporaryHosted(Tao *tao);

  /// Initialize a group of persistent keys using PBE. If keys exist on disk,
  /// they will be loaded, otherwise keys will be generated and saved. If only a
  /// signer is requested, the key is stored in PKCS#8 format.  Otherwise, all
  /// keys are stored in a custom PBE format. The password must be non-empty. As
  /// a special case, if the password is empty and only a signing key is
  /// requested, an attempt is made to load just the corresponding public
  /// verifier key using a previously-generated self-signed or CA-signed x509
  /// certificate, if available. Non-hosted programs without access to a host
  /// Tao
  /// should use this initializer.
  ///
  /// @param password The password used to encrypt the key on disk, or
  /// emptystring to load only the verification key.
  bool InitWithPassword(const string &password);

  /// Initialize a group of persistent keys using Tao-sealed secrets. If keys
  /// exist on disk they will be loaded, otherwise keys will be generated and
  /// saved. All private keys will be stored in a single Tao-sealed file. Hosted
  /// programs should use this initializer.
  /// @param tao The interface to access the host Tao.
  /// @param policy A sealing policy used to protect the secret keys.
  bool InitHosted(Tao *tao, const string &policy);

  /// Whether or not the manged keys were freshly generated by Init methods().
  bool HasFreshKeys() const { return fresh_; }

  /// Get managed keys, or nullptr if not available.
  /// @{
  tao::Verifier *Verifier() const { return verifier_.get(); }
  tao::Signer *Signer() const { return signer_.get(); }
  tao::Deriver *Deriver() const { return deriver_.get(); }
  tao::Crypter *Crypter() const { return crypter_.get(); }
  /// @}

  /// Get the tao delegation for the managed signing key. This is only available
  /// for hosted key sets. For persistent keysets, the delegation is stored in
  /// DelegationPath().
  string GetHostDelegation() const { return delegation_; }

  /// Set the X509 certificate for the managed verifier key. For
  /// persistent keysets, the certificate will be written to X509Path().
  /// @param details Text-format encoded X509Details for the subject.
  bool SetX509(const string &pem_cert);

  /// Get the X509 certificate for the managed verifier key.
  string GetX509() const { return x509_; }

  /// Create a deep copy of this key set.
  /// Note: If an x509 is subsequently added to one of the key sets, the two
  /// copies will become out of sync.
  Keys *DeepCopy() const;

  /// Get a path relative to the directory where the managed keys are stored.
  /// @param suffix The suffix to append.
  string GetPath(const string &suffix) const;

  /// Get the path to the sealed private KeySet.
  string SealedKeysetPath() const { return GetPath(SealedKeysetSuffix); }

  /// Get the path to the PBE private KeySet.
  string PBEKeysetPath() const { return GetPath(PBEKeysetSuffix); }

  /// Get the path to the PKCS#8 PBE private signing key.
  string PBESignerPath() const { return GetPath(PBESignerSuffix); }

  /// Get the path to the public verifier delegation.
  string DelegationPath() const { return GetPath(DelegationSuffix); }

  /// Get the path to the public verifier x509 certificate.
  string X509Path() const { return GetPath(X509Suffix); }

  /// all files are stored under a single path using these naming conventions.
  /// For consistency, other applications may use these same naming conventions
  /// as well.
  /// @{

  /// Suffix for a tao-sealed keyset.
  constexpr static auto SealedKeysetSuffix = "keyset.tao_sealed";
  /// Suffix for a PBE keyset.
  constexpr static auto PBEKeysetSuffix = "keyset.pbe_sealed";
  /// Suffix for a PKCS#8 PBE signer.
  constexpr static auto PBESignerSuffix = "signing.pk8";
  /// Suffix for a signing key host Tao delegation.
  constexpr static auto DelegationSuffix = "public_delegation.tao";
  /// Suffix for a signing key x509 certificate.
  constexpr static auto X509Suffix = "public_cert.pem";

  /// @}

 private:
  /// The types of keys to be generated or loaded.
  int key_types_;

  /// The path to the directory storing keys and related files, or emptystring.
  scoped_ptr<string> path_;

  /// Whether or not the manged keys were freshly generated by Init().
  bool fresh_;

  /// The host tao delegation, or nullptr.
  string delegation_;

  /// The host tao delegation, or nullptr.
  string x509_;

  /// The managed keys, or nullptr if not requested..
  /// @{
  scoped_ptr<tao::Verifier> verifier_;
  scoped_ptr<tao::Signer> signer_;
  scoped_ptr<tao::Deriver> deriver_;
  scoped_ptr<tao::Crypter> crypter_;
  /// @}

  /// Load specified keys from a keyset.
  /// @param m The keyset.
  /// @param signer Whether to expect a signer or not.
  /// @param deriver Whether to expect a deriver or not.
  /// @param crypter Whether to expect a crypter or not.
  bool Decode(const CryptoKeyset &m, bool signer, bool deriver, bool crypter);

  /// Write keys into a keyset.
  /// @param m The keyset.
  bool Encode(CryptoKeyset *m) const;

  DISALLOW_COPY_AND_ASSIGN(Keys);
};
}  // namespace tao

#endif  // TAO_KEYS_H_
