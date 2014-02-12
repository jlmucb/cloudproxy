//  File: util.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Utility methods for the Tao.
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
#ifndef TAO_UTIL_H_
#define TAO_UTIL_H_

#include <string>

#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <keyczar/openssl/util.h>
#include <openssl/x509.h>

#include "tao/attestation.pb.h"
#include "tao/keyczar_public_key.pb.h"
#include "tao/tao.h"
#include "tao/tao_child_channel.h"
#include "tao/tao_child_channel_registry.h"

using std::string;

struct sockaddr;

/// Handle a remove message from nftw(). This deletes the current file or empty
/// directory.
/// @param path The path of the current file or directory to delete.
/// @param sb A stat structure for the path.
/// @param tflag A flag specifying more information about the state of
/// directories (e.g., whether or not all its children have been handled).
/// @param ftwbuf Extra information provided by nftw().
int remove_entry(const char *path, const struct stat *sb, int tflag,
                 struct FTW *ftwbuf);

namespace tao {
class TaoDomain;

namespace keys {
// TODO(kwalsh) Move these constants to a better location once keyczar
// load/save issues are resolved, e.g. inside some class.
// TODO(kwalsh) How to best do global C++ string constants?

/// Suffix for a signing public key in keyczar format.
constexpr static auto SignPublicKeySuffix = "signing/public.key";
/// Suffix for a signing private key in keyczar format.
constexpr static auto SignPrivateKeySuffix = "signing/private.key";
/// Suffix for a Tao attestation for a signing key.
constexpr static auto SignKeyAttestationSuffix = "signing/attestation";
/// Suffix for a signing public key x509 certificate in openssl format.
constexpr static auto SignPublicKeyX509Suffix = "signing/x509cert.pem";
/// Suffix for a signing private key in openssl format.
constexpr static auto SignPrivateKeyPKCS8Suffix = "signing/private.pem";
/// Suffix for a sealing key in keyczar format.
constexpr static auto SealKeySuffix = "sealing/private.key";
/// Suffix for a sealed secret used to PBE-encrypt a sealing key
constexpr static auto SealKeySecretSuffix = "sealing/secret";
}  // namespace keys

/// A pointer to an OpenSSL RSA object.
typedef scoped_ptr_malloc<RSA, keyczar::openssl::OSSLDestroyer<RSA, RSA_free>>
    ScopedRsa;

/// Close a file descriptor and ignore the return value. This is used by the
/// definition of ScopedFd.
/// @param fd A pointer to the file descriptor to close and free.
void fd_close(int *fd);

/// Close a FILE and ignore the return value. This is used by the
/// definition of ScopedFile.
/// @param fd A pointer to the FILE to close and free.
void file_close(FILE *file);

/// Remove a directory and all its subfiles and subdirectories. This is used by
/// the definition of ScopedTempDir.
/// @param dir The path to the directory.
void temp_file_cleaner(string *dir);

/// A pointer to a managed file descriptor that gets closed when this wrapper is
/// deleted.
typedef scoped_ptr_malloc<int, keyczar::openssl::OSSLDestroyer<int, fd_close>>
    ScopedFd;

/// A smart pointer wrapping a FILE pointer that gets closed when this wrapper
/// is deleted.
typedef scoped_ptr_malloc<
    FILE, keyczar::openssl::OSSLDestroyer<FILE, file_close>> ScopedFile;

/// A smart pointer wrapping an OpenSSL X509 structure that gets cleaned up
/// when this wrapper is deleted.
typedef scoped_ptr_malloc<
    X509, keyczar::openssl::OSSLDestroyer<X509, X509_free>> ScopedX509Ctx;

/// A smart pointer wrapping an OpenSSL EVP_PKEY that gets cleaned up when this
/// wrapper is deleted.
typedef scoped_ptr_malloc<EVP_PKEY, keyczar::openssl::OSSLDestroyer<
                                        EVP_PKEY, EVP_PKEY_free>> ScopedEvpPkey;

typedef scoped_ptr_malloc<string, keyczar::openssl::OSSLDestroyer<
                                      string, temp_file_cleaner>> ScopedTempDir;

/// Set the disposition of SIGCHLD to prevent child zombification.
bool LetChildProcsDie();

/// Hash a file using SHA256.
/// @param path The path of the file to hash.
/// @param[out] hash The resulting hash.
bool Sha256FileHash(const string &path, string *hash);

/// Hash a set of virtual machine parameters in a composite structure: hash each
/// one, then concatenate them and hash them together.
/// @param vm_template_path A file containing template to use to create the VM.
/// @param name The name of the virtual machine.
/// @param kernel_path The kernel to use (the filename; not the bytes).
/// @param initrd_path The initrd to use (the filename; not the bytes).
/// @param[out] hash The resulting hash.
bool HashVM(const string &vm_template, const string &name,
            const string &kernel_path, const string &initrd_path, string *hash);

/// Register some well-known TaoChannels with the registry. The list of
/// registered TaoChannels is:
/// - KvmUnixTaoChannel
/// - PipeTaoChannel
/// @param registry The registry to fill with the channels
bool RegisterKnownChannels(TaoChildChannelRegistry *registry);

/// Call the OpenSSL initialization routines and set up locking for
/// multi-threaded access.
bool InitializeOpenSSL();

/// Check for, log, and clear any recent openssl errors on the current thread.
/// Returns true iff there were no recent errors.
///
/// This function can be used for non-fatal errors, e.g.
///    X509 *cert = SSL_get_certificate(...);
///    if (!OpenSSLSuccess()) {
///      LOG(ERROR) << "Could not find certificate, dropping this connection";
///      return false;
///    }
///
/// Or, this function can be used with google-glog CHECK for fatal errors, e.g.
///    X509 *cert = SSL_get_certificate(...);
///    CHECK(OpenSSLSuccess()) << "Could not find a required certificate,
/// exiting program";
///
/// We also install an OpenSSL FailureFunction that will call this function
/// before
/// exiting on any FATAL error, e.g. errors from any CHECK(...) failure. So this
/// will also
/// print details on ssl errors:
///    X509 *cert = SSL_get_certificate(...);
///    CHECK(cert != null) << "Could not find a required certificate, exiting
/// program";
bool OpenSSLSuccess();

/// Open a listening TCP socket on the given port.
/// @param host The host to listen on.
/// @param port The port to listen on.
/// @param[out] sock The socket opened for this port.
bool OpenTCPSocket(const string &host, const string &port, int *sock);

/// Load a password-protected crypting key.
/// @param path The location of the key on disk.
/// @param password The password used to encrypt the key on disk.
/// Note: This function will return nullptr if the key could not be read.
bool LoadCryptingKey(const string &path, const string &password,
                     scoped_ptr<keyczar::Crypter> *key);

/// Load a password-protected signing key.
/// @param path The location of the key on disk.
/// @param password The password used to encrypt the key on disk.
/// Note: This function will return nullptr if the key could not be read.
bool LoadSigningKey(const string &path, const string &password,
                    scoped_ptr<keyczar::Signer> *key);

/// Load a signing key that was saved using key-based encryption.
/// @param path The location of the signing key on disk.
/// @param crypter_path The location of the crypting key on disk that was used
/// to encrypt the signing key.
/// @param crypter_password The password used to encrypt the crypting key on
/// disk.
/// Note: This function will return nullptr if either the crypting key or the
/// signing key could not be read.
bool LoadEncryptedSigningKey(const string &path, const string &crypter_path,
                             const string &crypter_password,
                             scoped_ptr<keyczar::Signer> *key);

/// Load a clear-text verifier key.
/// @param path The location of the key on disk.
/// Note: this function will return nullptr if the key could not be read.
bool LoadVerifierKey(const string &path, scoped_ptr<keyczar::Verifier> *key);

/// Generate and optionally save a crypting key.
/// @param path The location to save the key. If emptystring, the key will not
/// be saved on disk.
/// @param name A name for the key.
/// @param password A password to encrypt the key. If path is given, then a
/// non-empty password is required.
/// @param[in,out] key A scoped Crypter to fill with the key.
bool GenerateCryptingKey(const string &path, const string &name,
                         const string &password,
                         scoped_ptr<keyczar::Crypter> *key);

/// Generate a signing key, optionally save it using using password-based
/// encryption, and optionally save the public key in the clear.
/// @param private_path The location to save the private key. If emptystring,
/// the key will not be saved on disk.
/// @param public_path The location to save the public key. If emptystring, the
/// public half will not be saved separately on disk.
/// @param name A name for the key.
/// @param password A password to encrypt the private key. If private_path is
/// given, then a non-empty password is required.
/// @param[in,out] key A scoped Signer to fill with the key.
bool GenerateSigningKey(const string &private_path, const string &public_path,
                        const string &name, const string &password,
                        scoped_ptr<keyczar::Signer> *key);

/// Generate a signing key and save it using using key-based encryption,
/// and optionally save save the public key in the clear.
/// @param private_path The location to save the private key. Must be non-empty.
/// @param public_path The location to save the public key. If emptystring, the
/// public half will not be saved separately on disk.
/// @param name A name for the key.
/// @param crypter_path The location to load the crypting key. Must be
/// non-empty.
/// @param crypter_password A password to decrypt the crypting key. Must be
/// non-empty.
/// @param[in,out] key A scoped Signer to fill with the key.
bool GenerateEncryptedSigningKey(const string &private_path,
                                 const string &public_path, const string &name,
                                 const string &crypter_path,
                                 const string &crypter_password,
                                 scoped_ptr<keyczar::Signer> *key);

/// Generate a signed ROOT or INTERMEDIATE attestation.
/// @param signer The signing key, i.e. the principal attesting to s.
/// @param cert An attestation for the singer key for INTERMEDIATE, otherwise
/// emptystring for ROOT attestation.
/// @param statement[in,out] The statement to attest to. Missing timestamps will
/// be filled in with default values.
/// @param attestation[out] The signed attestation.
/// TODO(kwalsh) signer should be const reference
/// TODO(kwalsh) signer should be Signer
bool GenerateAttestation(const keyczar::Signer *signer, const string &cert,
                         Statement *statement, Attestation *attestation);
bool GenerateAttestation(const keyczar::Signer *signer, const string &cert,
                         Statement *statement, string *attestation);

/// Convert a serialized KeyczarPublicKey representation to an in-memory key.
/// @param kpk The public key to deserialize.
/// @param[out] key A verifier key created from this public key.
bool DeserializePublicKey(const KeyczarPublicKey &kpk,
                          scoped_ptr<keyczar::Verifier> *key);

/// Convert a Keyczar public key to a serialized string.
/// @param key The private key to serialize.
/// @return The serialized key, or emptystring on error.
/// TODO(kwalsh) misleading function name
string SerializePublicKey(const keyczar::Signer &key);

/// Convert a Keyczar public key to a serialized KeyczarPublicKey structure.
/// @param key The private key to serialize.
/// @param[out] kpk The serialized public key.
/// TODO(kwalsh) misleading function name
bool SerializePublicKey(const keyczar::Signer &key, KeyczarPublicKey *kpk);

/// Convert a Keyczar public keyset to a serialized KeyczarPublicKey structure.
/// @param keyset The keyset listing the key versions to serialize.
/// @param path The location where the metadata and public keys are stored.
/// @param[out] kpk The serialized public key.
bool SerializeKeyset(const keyczar::Keyset *keyset, const string &path,
                     KeyczarPublicKey *kpk);

/// Sign data with a key using Signer.
/// @param data The data to sign.
/// @param context The context string to add to the tao::Signature. WARNING: for
/// security, this must be unique for each context in which signed messages are
/// used.
/// @param[out] signature The resulting signature.
/// @param key The key to use for signing.
/// TODO(kwalsh) key should be const reference
bool SignData(const string &data, const string &context, string *signature,
              const keyczar::Signer *key);

/// Verify a signature using Verifier.
/// @param data The data that was signed.
/// @param context The context to check in the tao::Signature.
/// @param signature The signature on the data.
/// @param key The key to use for verification.
/// TODO(kwalsh) key should be const reference
bool VerifySignature(const string &data, const string &context,
                     const string &signature, const keyczar::Verifier *key);

/// Copy the value of a Signer into a Verifier.
/// @param key The key to copy.
/// @param[out] copy The key to fill with the copy.
/// TODO(kwalsh) This function would be useful if it worked for signers and
/// crypters. As it is, it is not used anywhere.
/// TODO(kwalsh) misleading function name
bool CopyPublicKey(const keyczar::Signer &key,
                   scoped_ptr<keyczar::Verifier> *copy);

/// If sealed_path is a file, then try to unseal it. Otherwise, create a new
/// secret and seal it at sealed_path.
/// @param t The channel to access the host Tao.
/// @param sealed_path The file name to use.
/// @param[out] secret The secret to generate or unseal.
bool SealOrUnsealSecret(const TaoChildChannel &t, const string &sealed_path,
                        string *secret);

/// Receive a protobuf message on a file descriptor.
/// @param fd The file descriptor to read.
/// @param[out] m The received message.
bool ReceiveMessage(int fd, google::protobuf::Message *m);

/// Send a protobuf message on a file descriptor.
/// @param fd The file descriptor to write.
/// @param m The message to send.
bool SendMessage(int fd, const google::protobuf::Message &m);

/// Receive a protobuf message on a file descriptor.
/// @param fd The file descriptor to read.
/// @param[out] m The received message.
/// @param[out] addr The address the message was received from.
/// @param[out] addr_len The length of the address the message was received
/// from.
bool ReceiveMessageFrom(int fd, google::protobuf::Message *m,
                        struct sockaddr *addr, socklen_t *addr_len);

/// Send a protobuf message on a file descriptor.
/// @param fd The file descriptor to write.
/// @param m The message to send.
/// @param addr The address to send the message to.
/// @param addr_len The length of the address to send the message to.
bool SendMessageTo(int fd, const google::protobuf::Message &m,
                   struct sockaddr *addr, socklen_t addr_len);

/// Opens a Unix domain socket at a given path.
/// @param path The path for the new Unix domain socket.
/// @param[out] sock The file descriptor for this socket.
bool OpenUnixDomainSocket(const string &path, int *sock);

/// Connect as a client to a Unix domain socket.
/// @param path The path to the existing socket.
/// @param[out] sock The connected socket.
bool ConnectToUnixDomainSocket(const string &path, int *sock);

/// Create a temporary directory.
/// @param prefix The path of the directory to create.
/// @param[out] dir A pointer to an object that will take ownership of the
/// new temporary directory.
bool CreateTempDir(const string &prefix, ScopedTempDir *dir);

/// Create a temporary directory with a temporary configuration using whitelist
/// auth. The policy password will be "temppass".
/// @param[out] temp_dir The new directory.
/// @param[out] admin The new configuration.
bool CreateTempWhitelistDomain(ScopedTempDir *temp_dir,
                               scoped_ptr<TaoDomain> *admin);

/// Create a temporary directory with a temporary configuration using root auth.
/// @param[out] temp_dir The new directory. The policy password will be
/// "temppass".
/// @param[out] admin The new configuration.
bool CreateTempRootDomain(ScopedTempDir *temp_dir,
                          scoped_ptr<TaoDomain> *admin);

/// Connect to a remote server.
/// @param host The name of the remote host.
/// @param port The port to connect to.
/// @param[out] sock The connected client socket.
bool ConnectToTCPServer(const string &host, const string &port, int *sock);

/// Convert a keyczar private signing key to an OpenSSL EVP_PKEY structure. As a
/// side effect, this writes the key to a password-encrypted PKCS8 file.
/// @param key The keyczar key to export.
/// @param pem_key_path Location to store the intermediate PKCS8 file.
/// @param secret Password to use for encrypting the PKCS8 file.
/// @param pem_key[out] The new OpenSSL EVP_PKEY.
bool ExportKeyToOpenSSL(keyczar::Signer *key, const string &pem_key_path,
                        const string &secret, ScopedEvpPkey *pem_key);

/// Serialize an X.509 certificate.
/// @param x509 The certificate to serialize.
/// @param[out] serialized_x509 The serialized form of the certificate.
bool SerializeX509(X509 *x509, string *serialized_x509);

/// Create a self-signed X509 certificate for a key. As a side effect, this
/// writes the key to a password-encrypted PKCS8 file.
/// @param key The keyczar key to use for both the subject and the issuer.
/// @param pem_key_path Location to store the intermediate PKCS8 file.
/// @param secret Password to use for encrypting the PKCS8 file.
/// @param org The name to use for the x509 Organization detail.
/// @param cn The name to use for the x509 CommonName detail.
/// @param public_cert_path File name to hold the resulting x509 certificate.
/// TODO(kwalsh) key should be const reference (but then we can't print name)
/// TODO(kwalsh) encode x509 name details in a single json string, perhaps?
bool CreateSelfSignedX509(keyczar::Signer *key, const string &pem_key_path,
                          const string &secret, const string &coutry,
                          const string &state, const string &org,
                          const string &cn, const string &public_cert_path);

}  // namespace tao

#endif  // TAO_UTIL_H_
