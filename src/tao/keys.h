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

#include <keyczar/base/scoped_ptr.h>
#include <keyczar/openssl/util.h>

#include "tao/keys.pb.h"
#include "tao/tao_child_channel.h"

using std::string;

namespace keyczar {
class Signer;
class Crypter;
class Verifier;
}  // namespace keyczar

namespace tao {

/// A smart pointer wrapping an OpenSSL EVP_PKEY that gets cleaned up when this
/// wrapper is deleted.
typedef scoped_ptr_malloc<EVP_PKEY, keyczar::openssl::OSSLDestroyer<
                                        EVP_PKEY, EVP_PKEY_free>> ScopedEvpPkey;

/// Load a clear-text ECDSA verifier key.
/// @param path The location of the key on disk.
/// @param[in,out] key A scoped Verifier to fill with the key.
/// TODO(kwalsh) Eventually, this function should be removed.
bool LoadVerifierKey(const string &path, scoped_ptr<keyczar::Verifier> *key);

/// Load a password-protected ECDSA signing private key.
/// @param path path The location of the key on disk.
/// @param password The password used to encrypt the key on disk.
/// TODO(kwalsh) Eventually, this function should be removed.
bool LoadSigningKey(const string &path, const string &password,
                    scoped_ptr<keyczar::Signer> *key);

/// Convert a serialized verifier key representation to an in-memory key.
/// @param s The serialized key.
/// @param[out] key A verifier key created from this public key.
bool DeserializePublicKey(const string &s, scoped_ptr<keyczar::Verifier> *key);

/// Convert a Keyczar public key to a serialized string. If the key is
/// actually a Signer, only the public half will be serialized.
/// @param key The key to serialize.
/// @param[out] s The serialized key.
bool SerializePublicKey(const keyczar::Verifier &key, string *serialized_key);

/// Sign data with a key using Signer.
/// @param data The data to sign.
/// @param context The context string to add to the tao::Signature. WARNING:
/// for security, this must be unique for each context in which signed
/// messages are used.
/// @param[out] signature The resulting signature.
/// @param key The key to use for signing.
bool SignData(const keyczar::Signer &key, const string &data,
              const string &context, string *signature);

/// Verify a signature using Verifier.
/// @param data The data that was signed.
/// @param context The context to check in the tao::Signature.
/// @param signature The signature on the data.
/// @param key The key to use for verification.
bool VerifySignature(const keyczar::Verifier &key, const string &data,
                     const string &context, const string &signature);

/// Make a (deep) copy of a Signer, either a signing or a key-derivation key.
/// @param key The key to be copied.
/// @param[out] copy The key to fill with the copy.
bool CopySigner(const keyczar::Signer &key, scoped_ptr<keyczar::Signer> *copy);

/// Make a (deep) copy of a Verifier or the public half of a Signer.
/// @param key The key to be copied. If key is actually a Signer, only
/// the public half will be copied.
/// @param[out] copy The key to fill with the copy.
bool CopyVerifier(const keyczar::Verifier &key,
                  scoped_ptr<keyczar::Verifier> *copy);

/// Make a (deep) copy of a Crypter.
/// @param key The key to be copied.
/// @param[out] copy The key to fill with the copy.
bool CopyCrypter(const keyczar::Crypter &key,
                 scoped_ptr<keyczar::Crypter> *copy);

/// Derive a key from a main key.
/// @param key The key to use for key derivation.
/// @param name A unique name for the derived key.
/// @param size The size of the material to be derived.
/// @param[out] material The key material derived from main_key.
bool DeriveKey(const keyczar::Signer &key, const string &name, int size,
               string *material);

/// Convert a keyczar private signing key to an OpenSSL EVP_PKEY structure.
/// Only the primary key from the keyset is exported. The resulting EVP_PKEY
/// will contain both public and private keys.
/// @param key The keyczar key to export.
/// @param pem_key[out] The new OpenSSL EVP_PKEY.
bool ExportPrivateKeyToOpenSSL(const keyczar::Signer &key,
                               ScopedEvpPkey *pem_key);

/// Convert a keyczar public signing key to an OpenSSL EVP_PKEY structure.
/// Only the primary key from the keyset is exported. The EVP_PKEY will
/// contain only a public key, even if key is actually a keyczar::Signer.
/// @param key The keyczar key to export.
/// @param pem_key[out] The new OpenSSL EVP_PKEY.
bool ExportPublicKeyToOpenSSL(const keyczar::Verifier &key,
                              ScopedEvpPkey *pem_key);

/// Create a self-signed X509 certificate for a key.
/// @param key The key to use for both the subject and the issuer.
/// @param details The x509 details for the subject.
/// @param public_cert_path File name to hold the resulting x509 certificate.
bool CreateSelfSignedX509(const keyczar::Signer &key,
                          const X509Details &details,
                          const string &public_cert_path);

/// Create a CA-signed X509 certificate for a key.
/// @param ca_key The key to use for the issuer.
/// @param ca_cert_path The location of the issuer certificate.
/// @param cert_serial The serial number to use for the new certificate.
/// @param subject_key The key to use for the subject.
/// @param subject_details The x509 details for the subject.
/// @param[out] pem_cert The signed certificate chain.
bool CreateCASignedX509(const keyczar::Signer &ca_key,
                        const string &ca_cert_path, int cert_serial,
                        const keyczar::Verifier &subject_key,
                        const X509Details &subject_details, string *pem_cert);

/// Serialize an openssl X509 structure in PEM format.
/// @param x509 The certificate to serialize.
/// @param[out] pem The serialized certificate.
bool SerializeX509(X509 *x509, string *serialized_x509);

/// A Keys object manages a group of cryptographic verifier, signing, crypting,
/// and key-derivation keys. Currently, at most one of each type of key can be
/// held in a single Keys object. Static convenience methods are also provided
/// for generating, loading, using, and exporting Keyczar keys.
class Keys {
 public:
  /// Flags used in Keys constructor for declaring which keys should be managed.
  enum Type {
    Signing = 1 << 1,  // This is a key pair.
    Crypting = 1 << 2,
    KeyDeriving = 1 << 3
  };

  /// Construct a new Keys object to manage a group of temporary keys.
  /// InitTemporary() should be called before using the object.
  /// @param name The base name for the group of keys.
  /// @param key_type One or more of the Keys::Type flags.
  Keys(const string &name, int key_types);

  /// Construct a new Keys object to manage a group of on-disk keys.
  /// InitNonHosted() or InitHosted() should be called before using the object.
  /// @param path The directory under which all keys are stored.
  /// @param name The base name for the group of keys.
  /// @param key_type One or more of the Keys::Type flags.
  Keys(const string &path, const string &name, int key_types);

  /// Construct a new Keys object to hold the given keys. Ownership is taken
  /// for all keys. It is not necessary to call any of the Init() methods.
  /// @param verifying_key A verifier key.
  /// @param signing_key A signing key.
  /// @param derivation_key A signing key.
  /// @param crypting_key A signing key.
  Keys(keyczar::Verifier *verifying_key, keyczar::Signer *signing_key,
       keyczar::Signer *derivation_key, keyczar::Crypter *crypting_key);

  virtual ~Keys();

  /// Initialize a group of temporary keys. Unit tests use this initializer.
  /// Fresh keys are generated, and none of the keys are stored on disk.
  bool InitTemporary();

  /// Initialize the group of keys using PBE. If password is emptystring, only
  /// verification keys can be loaded. Otherwise, keys will be loaded if
  /// possible, otherwise generated and saved. Non-hosted programs without
  /// access to a host Tao should use this initializer.
  /// @param password The password used to encrypt the key on disk, or
  /// emptystring to load only the verification key.
  bool InitNonHosted(const string &password);

  /// Initialize the group of keys using Tao-sealed secrets. Keys will be
  /// loaded if they already exist, otherwise they will be generated and saved.
  /// Hosted programs should use this initializer. If a crypter is available, it
  /// will be protected using a Tao-sealed secret, and any othe keys will be
  /// protected using the crypter. Otherwise, if no crypter is available, all
  /// keys will be protected using a Tao-sealed secret.
  /// @param channel The channel to access the host Tao.
  /// @param name The base name for the group of keys.
  bool InitHosted(const TaoChildChannel &channel);

  /// Whether or not the manged keys were freshly generated by Init methods().
  bool HasFreshKeys() const { return fresh_; }

  /// Get the name of this group of keys.
  string Name() const { return name_; }

  /// Get a unique ID for the signing key.
  /// @param[out] identifier The unique ID.
  bool SignerUniqueID(string *identifier) const;

  /// Get the managed verifier key. If no verifier is available, the signer will
  /// be returned instead if it is available. Otherwise, nullptr will be
  /// returned.
  keyczar::Verifier *Verifier() const;

  /// Get the managed signing key.
  keyczar::Signer *Signer() const { return signer_.get(); }

  /// Get the managed key-derivation key.
  keyczar::Signer *KeyDeriver() const { return key_deriver_.get(); }

  /// Get the managed crypting key.
  keyczar::Crypter *Crypter() const { return crypter_.get(); }

  /// Get a path relative to the directory where the managed keys are stored.
  /// @param suffix The suffix to append.
  string GetPath(const string &suffix) const;

  /// Get the path to the managed signing public key.
  string SigningPublicKeyPath() const {
    return GetPath(SigningPublicKeySuffix);
  }

  /// Get the path to the managed signing private key.
  string SigningPrivateKeyPath() const {
    return GetPath(SigningPrivateKeySuffix);
  }

  /// Get the path to the managed key-deriving key.
  string KeyDerivingKeyPath() const { return GetPath(KeyDerivingKeySuffix); }

  /// Get the path to the managed crypting key.
  string CryptingKeyPath() const { return GetPath(CryptingKeySuffix); }

  /// Get the path to the attestation for the managed signing key.
  string AttestationPath() const {
    return GetPath(SigningKeyAttestationSuffix);
  }

  /// Get the path to the Tao-sealed secret for protecting managed keys.
  string SecretPath() const { return GetPath(CryptingSecretSuffix); }

  /// Get the path to a self-signed x509 certificate for the signing public key.
  string SigningX509CertificatePath() const {
    return GetPath(SigningPublicKeyX509Suffix);
  }

  /// Create a self-signed X509 certificate for the managed signing key.
  /// The certificate will be written to SigningX509CertificatePath().
  /// @param details Details for the subject.
  bool CreateSelfSignedX509(const X509Details &details) const;

  /// Create a self-signed X509 certificate for a key.
  /// The certificate will be written to SigningX509CertificatePath().
  /// @param details Text-format encoded x509Details for the subject.
  bool CreateSelfSignedX509(const string &details_text) const;

  /// Create a signed X509 certificate issued by the managed signing key.
  /// @param cert_serial The serial number to use for the new certificate.
  /// @param subject_key The key to use for the subject.
  /// @param subject_details The x509 details for the subject.
  /// @param[out] pem_cert The signed certificate chain.
  bool CreateCASignedX509(int cert_serial, const keyczar::Verifier &subject_key,
                          const X509Details &subject_details,
                          string *pem_cert) const;

  /// Convert the managed signing public key to a serialized string.
  /// @param[out] s The serialized key.
  bool SerializePublicKey(string *s) const;

  /// Sign data with the managed signing private key.
  /// @param data The data to sign.
  /// @param context The context string to add to the tao::Signature.
  /// WARNING: for security, this must be unique for each context in which
  /// signed messages are used.
  /// @param[out] signature The resulting signature.
  bool SignData(const string &data, const string &context,
                string *signature) const;

  /// Verify a signature the managed signing public or private key.
  /// @param data The data that was signed.
  /// @param context The context to check in the tao::Signature.
  /// @param signature The signature on the data.
  bool VerifySignature(const string &data, const string &context,
                       const string &signature) const;

  /// Make a (deep) copy of this object.
  Keys *DeepCopy() const;

  /// Make a (deep) copy of the managed signing private key.
  /// @param[out] copy The key to fill with the copy.
  bool CopySigner(scoped_ptr<keyczar::Signer> *copy) const;

  /// Make a (deep) copy of the managed key-derivation key.
  /// @param[out] copy The key to fill with the copy.
  bool CopyKeyDeriver(scoped_ptr<keyczar::Signer> *copy) const;

  /// Make a (deep) copy of the managed Verifier or the public half of the
  /// managed Signer.
  /// @param[out] copy The key to fill with the copy.
  bool CopyVerifier(scoped_ptr<keyczar::Verifier> *copy) const;

  /// Make a (deep) copy of the managed Crypter.
  /// @param key The key to be copied.
  /// @param[out] copy The key to fill with the copy.
  bool CopyCrypter(scoped_ptr<keyczar::Crypter> *copy) const;

  /// Derive key material from the managed key-derivation key.
  /// @param name A unique name for the derived key.
  /// @param size The size of the material to be derived.
  /// @param[out] material The key material derived from main_key.
  bool DeriveKey(const string &name, int size, string *material) const;

  /// Convert the managed signing private key to an OpenSSL EVP_PKEY structure.
  /// Only the primary key from the keyset is exported. The EVP_PKEY will
  /// contain both public and private keys.
  /// @param pem_key[out] The new OpenSSL EVP_PKEY.
  bool ExportSignerToOpenSSL(ScopedEvpPkey *pem_key) const;

  /// Convert the managed signing public key to an OpenSSL EVP_PKEY structure.
  /// Only the primary key from the keyset is exported. The EVP_PKEY will
  /// contain only a public key.
  /// @param pem_key[out] The new OpenSSL EVP_PKEY.
  bool ExportVerifierToOpenSSL(ScopedEvpPkey *pem_key) const;

  /// Keys stores all its files under a single path using these naming
  /// conventions. For consistency, other applications may use these same naming
  /// conventions as well.
  /// @{

  /// Suffix for a signing public key in keyczar format.
  constexpr static auto SigningPublicKeySuffix = "signing/public.key";
  /// Suffix for a signing private key in keyczar format.
  constexpr static auto SigningPrivateKeySuffix = "signing/private.key";
  /// Suffix for a Tao attestation for a signing key.
  constexpr static auto SigningKeyAttestationSuffix = "signing/attestation";
  /// Suffix for a signing public key x509 certificate in openssl format.
  constexpr static auto SigningPublicKeyX509Suffix = "signing/x509cert.pem";
  /// Suffix for a crypting key in keyczar format.
  constexpr static auto CryptingKeySuffix = "crypting/private.key";
  /// Suffix for a key-derivation key in keyczar format.
  constexpr static auto KeyDerivingKeySuffix = "keyderiving/private.key";
  /// Suffix for a sealed secret used for Tao-protected keys
  constexpr static auto CryptingSecretSuffix = "secret";

  /// @}

 private:
  /// The types of keys to be generated or loaded.
  int key_types_;

  /// The path to the directory storing keys and related files, or emptystring.
  string path_;

  /// The name of the group of keys.
  string name_;

  /// Whether or not the manged keys were freshly generated by Init().
  bool fresh_;

  /// The managed verifier key, or null.
  scoped_ptr<keyczar::Verifier> verifier_;

  /// The managed signing private key, or null.
  scoped_ptr<keyczar::Signer> signer_;

  /// The managed key-derivation key, or null.
  scoped_ptr<keyczar::Signer> key_deriver_;

  /// The managed derivation key, or null.
  scoped_ptr<keyczar::Crypter> crypter_;

 private:
  DISALLOW_COPY_AND_ASSIGN(Keys);
};
}  // namespace tao

#endif  // TAO_KEYS_H_
