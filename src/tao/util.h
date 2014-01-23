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
#ifndef TAO_UTIL_TAO_H_
#define TAO_UTIL_TAO_H_

#include <sys/types.h>
#include <sys/socket.h>

#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <keyczar/openssl/util.h>
#include <openssl/x509.h>

#include "tao/keyczar_public_key.pb.h"
#include "tao/tao.h"
#include "tao/tao_child_channel.h"
#include "tao/tao_child_channel_registry.h"

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

/// A pointer to an OpenSSL RSA object.
typedef scoped_ptr_malloc<RSA, keyczar::openssl::OSSLDestroyer<RSA, RSA_free>>
    ScopedRsa;

/// Close a file descriptor and ignore the return value. This is used by the
/// definition of ScopedFd.
/// @param fd A pointer to the file descriptor to close and free.
void fd_close(int *fd);

/// Remove a directory and all its subfiles and subdirectories. This is used by
/// the definition of ScopedTempDir.
/// @param dir The path to the directory.
void temp_file_cleaner(string *dir);

/// A pointer to a managed file descriptor that gets closed when this wrapper is
/// deleted.
typedef scoped_ptr_malloc<int, keyczar::openssl::OSSLDestroyer<int, fd_close>>
    ScopedFd;

typedef scoped_ptr_malloc<string, keyczar::openssl::OSSLDestroyer<
                                      string, temp_file_cleaner>> ScopedTempDir;

/// Set the disposition of SIGCHLD to prevent child zombification.
bool LetChildProcsDie();

/// Hash a set of virtual machine parameters in a composite structure: hash each
/// one, then concatenate them and hash them together.
/// @param vm_template The template string to use to create the VM.
/// @param name The name of the virtual machine.
/// @param kernel The kernel to use (not the filename; the bytes).
/// @param initrd The initrd to use (not the filename; the bytes).
/// @param[out] hash The resulting hash.
bool HashVM(const string &vm_template, const string &name, const string &kernel,
            const string &initrd, string *hash);

/// Register some well-known TaoChannels with the registry. The list of
/// registered TaoChannels is:
/// - KvmUnixTaoChannel
/// - PipeTaoChannel
/// @param registry The registry to fill with the channels
bool RegisterKnownChannels(TaoChildChannelRegistry *registry);

/// Call the OpenSSL initialization routines and set up locking for
/// multi-threaded access.
bool InitializeOpenSSL();

/// Open a listening TCP socket on the given port.
/// @param host The host to listen on.
/// @param port The port to listen on.
/// @param[out] sock The socket opened for this port.
bool OpenTCPSocket(const string &host, const string &port, int *sock);

/// Create a Keyczar key with the given parameters.
/// @param writer The writer to use to write this key to disk.
/// @param key_type The type of key, like ECDSA_PRIV.
/// @param key_purpose The purpose the key will be used for, like
/// SIGN_AND_VERIFY.
/// @param key_name A name for this key.
/// @param[in,out] key A scoped Keyczar to fill with the key.
bool CreateKey(keyczar::rw::KeysetWriter *writer,
               keyczar::KeyType::Type key_type,
               keyczar::KeyPurpose::Type key_purpose, const string &key_name,
               scoped_ptr<keyczar::Keyczar> *key);

/// Convert a serialized KeyczarPublicKey representation to an in-memory keyset.
/// @param kpk The public key to deserialize.
/// @param[out] keyset A keyset created from this public key.
bool DeserializePublicKey(const KeyczarPublicKey &kpk,
                          keyczar::Keyset **keyset);

/// Convert a Keyczar public key to a serialized KeyczarPublicKey structure.
/// @param key The public key to serialize.
/// @param[out] kpk The serialized public key.
bool SerializePublicKey(const keyczar::Keyczar &key, KeyczarPublicKey *kpk);

/// Sign data with a key using Keyczar.
/// @param data The data to sign.
/// @param context The context string to add to the tao::Signature. WARNING: for
/// security, this must be unique for each context in which signed messages are
/// used.
/// @param[out] signature The resulting signature.
/// @param key The key to use for signing.
bool SignData(const string &data, const string &context, string *signature,
              keyczar::Keyczar *key);

/// Verify a signature using Keyczar.
/// @param data The data that was signed.
/// @param context The context to check in the tao::Signature.
/// @param signature The signature on the data.
/// @param key The key to use for verification.
bool VerifySignature(const string &data, const string &context,
                     const string &signature, keyczar::Keyczar *key);

/// Copy the value of a public key into another keyset.
/// @param public_key The key to copy.
/// @param[out] keyset The key to fill with the copy.
bool CopyPublicKeyset(const keyczar::Keyczar &public_key,
                      keyczar::Keyset **keyset);

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

/// Create a ECDSA key with the default security parameters.
/// @param path The path to create the key at. This path must already exist.
/// @param key_name The name of the key.
/// @param[out] key A pointer to an existing scoped_ptr that will take
/// ownership of the newly created key.
bool CreateECDSAKey(const string &path, const string &key_name,
                    scoped_ptr<keyczar::Keyczar> *key);

/// Create a policy ECDSA key with the default security parameters.
/// @param path The path to create the key at. This path must already exist.
/// @param[out] key A pointer to an existing scoped_ptr that will take
/// ownership of the newly created key.
bool CreatePubECDSAKey(const string &path, scoped_ptr<keyczar::Keyczar> *key);

/// Create a temporary directory.
/// @param prefix The path of the directory to create.
/// @param[out] dir A pointer to an object that will take ownership of the
/// new temporary directory.
bool CreateTempDir(const string &prefix, ScopedTempDir *dir);

/// Create a temporary directory and a temporary key in this directory.
/// @param[out] temp_dir The new directory.
/// @param[out] key The new key.
bool CreateTempPubKey(ScopedTempDir *temp_dir,
                      scoped_ptr<keyczar::Keyczar> *key);

/// Connect to a remote server.
/// @param host The name of the remote host.
/// @param port The port to connect to.
/// @param[out] sock The connected client socket.
bool ConnectToTCPServer(const string &host, const string &port, int *sock);
}  // namespace tao

#endif  // TAO_UTIL_TAO_H_
