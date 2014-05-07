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

#include <sys/socket.h>

#include <string>

#include <keyczar/openssl/util.h>
#include <openssl/x509.h>

#include "tao/tao.h"

using std::string;

struct sockaddr;

namespace google {
namespace protobuf {
class Message;
}  // namespace protobuf
}  // namespace google

namespace tao {
class TaoChildChannel;
class TaoChildChannelRegistry;
class TaoDomain;

/// A pointer to an OpenSSL RSA object.
typedef scoped_ptr_malloc<RSA, keyczar::openssl::OSSLDestroyer<RSA, RSA_free>>
    ScopedRsa;

/// A pointer to an OpenSSL EC_KEY object.
typedef scoped_ptr_malloc<
    EC_KEY, keyczar::openssl::OSSLDestroyer<EC_KEY, EC_KEY_free>> ScopedECKey;

/// A pointer to an OpenSSL BIO object.
typedef scoped_ptr_malloc<
    BIO, keyczar::openssl::OSSLDestroyer<BIO, BIO_free_all>> ScopedBio;

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

/// Close a self-pipe and ignore the return value. This is used by
/// the definition of ScopedSelfPipeFd.
/// @param fd A pointer to the self-pipe file descriptor.
void selfpipe_release(int *fd);

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
    X509, keyczar::openssl::OSSLDestroyer<X509, X509_free>> ScopedX509;

typedef scoped_ptr_malloc<string, keyczar::openssl::OSSLDestroyer<
                                      string, temp_file_cleaner>> ScopedTempDir;

/// A pointer to a self-pipe that gets cleaned up when this wrapper is deleted.
typedef scoped_ptr_malloc<int, keyczar::openssl::OSSLDestroyer<
                                   int, selfpipe_release>> ScopedSelfPipeFd;

/// Create a self-pipe for a signal. A signal handler is installed that writes
/// the signal number (cast to a byte) to the pipe. Callers can use the returned
/// file descriptor as part of a select() call. When a byte is available on the
/// file descriptor, it means that that signal has been received. An error is
/// returned if another self-pipe already exists (this limitation stems from the
/// need for global variables).
/// @param signum The signal to catch.
/// @return A file descriptor suitable for select() and read(), or -1 on error.
int GetSelfPipeSignalFd(int signum);

/// Destroy a self-pipe, restoring any previous signal handler.
/// @param fd The file descriptor returned from GetSelfPipeSignalFd().
bool ReleaseSelfPipeSignalFd(int fd);

/// Set the disposition of SIGCHLD to prevent child zombification.
bool LetChildProcsDie();

/// Hash a string using SHA256.
/// @param s The string to hash.
/// @param[out] hash The resulting hash.
bool Sha256(const string &s, string *hash);

/// Hash a file using SHA256.
/// @param path The path of the file to hash.
/// @param[out] hash The resulting hash.
bool Sha256FileHash(const string &path, string *hash);

/// Register some well-known TaoChannels with the registry. The list of
/// registered TaoChannels is:
/// - KvmUnixTaoChannel
/// - PipeTaoChannel
/// @param registry The registry to fill with the channels
bool RegisterKnownChannels(TaoChildChannelRegistry *registry);

/// Call the OpenSSL initialization routines and set up locking for
/// multi-threaded access.
bool InitializeOpenSSL();

/// Perform application initialization routines, including initialization for
/// OpenSSL, google logging, google protobuffers, and google flags. The
/// parameters have the same semantics as google flags.
/// @param argc Pointer to argc from main.
/// @param argv Pointer to argv from main.
/// @param remove_args Whether or not to remove processed args.
bool InitializeApp(int *argc, char ***argv, bool remove_args);

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

/// Generate and save a random secret, sealed against the host Tao.
/// @param t The channel to access the host Tao.
/// @param path The location to store the sealed secret.
/// @param secret_size The number of random bytes for the new secret.
/// @param[out] secret The new random secret.
/// @param policy A seal/unseal policy under which to seal the secret.
bool MakeSealedSecret(const TaoChildChannel &t, const string &path,
                      int secret_size, string *secret, int policy);

/// Read and unseal a secret that is sealed against the host Tao.
/// @param t The channel to access the host Tao.
/// @param path The location to store the sealed secret.
/// @param secret[out] The unsealed secret.
/// @param policy[out] The policy under which the secret had been sealed.
bool GetSealedSecret(const TaoChildChannel &t, const string &path,
                     string *secret, int *policy);

/// Read and unseal a secret that is sealed against the host Tao, if possible.
/// Otherwise, if the file does not exist, generate and save a new random sealed
/// secret.
/// @param t The channel to access the host Tao.
/// @param path The location to read or store the sealed secret.
/// @param secret[out] The unsealed or new random secret.
/// @param policy A seal/unseal policy for this secret.
/// TODO(kwalsh) Delete this: bad semantics, and all existing uses are bugs.
bool SealOrUnsealSecret(const TaoChildChannel &t, const string &path,
                        string *secret, int policy);

/// Receive a protobuf message on a file descriptor.
/// @param fd The file descriptor to read.
/// @param[out] m The received message.
/// @param[out] eof Set to true if end of stream is reached.
bool ReceiveMessage(int fd, google::protobuf::Message *m, bool *eof);

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
                   const struct sockaddr *addr, socklen_t addr_len);

/// Opens a Unix domain socket at a given path.
/// @param path The path for the new Unix domain socket.
/// @param[out] sock The file descriptor for this socket.
bool OpenUnixDomainSocket(const string &path, int *sock);

/// Connect as a client to a Unix domain socket.
/// @param path The path to the existing socket.
/// @param[out] sock The connected socket.
bool ConnectToUnixDomainSocket(const string &path, int *sock);

/// Create a temporary directory.
/// @param prefix The partial path of the directory to create.
/// @param[out] dir A pointer to an object that will take ownership of the
/// new temporary directory.
bool CreateTempDir(const string &prefix, ScopedTempDir *dir);

/// Create a temporary directory with a temporary configuration using ACL
/// guards. The policy password will be "temppass".
/// @param[out] temp_dir The new directory.
/// @param[out] admin The new configuration.
bool CreateTempACLsDomain(ScopedTempDir *temp_dir,
                          scoped_ptr<TaoDomain> *admin);

/// Create a temporary directory with a temporary configuration using root auth.
/// @param[out] temp_dir The new directory. The policy password will be
/// "temppass".
/// @param[out] admin The new configuration.
/* bool CreateTempRootDomain(ScopedTempDir *temp_dir,
                          scoped_ptr<TaoDomain> *admin); */

/// Connect to a remote server.
/// @param host The name of the remote host.
/// @param port The port to connect to.
/// @param[out] sock The connected client socket.
bool ConnectToTCPServer(const string &host, const string &port, int *sock);

/// Add double-quotes to a string, but escape any existing backslashes or
/// double-quotes.
/// @param s The string to escape and add quotes around.
string quotedString(const string &s);

/// Read a double-quoted string from a stream, and remove the outer
/// double-quotes and escapes for inner double-quotes and backslashes.
/// This also ignores leading whitespace, as typical of istream operations.
/// @param in The input stream.
/// @param s The resulting quoted string.
std::stringstream &getQuotedString(std::stringstream &in, string *s);  // NOLINT

std::stringstream &skip(std::stringstream &in, const string &s);  // NOLINT

}  // namespace tao

#endif  // TAO_UTIL_H_
