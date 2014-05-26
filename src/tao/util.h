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

#include <sys/socket.h>  // for socklen_t

#include <list>
#include <set>
#include <sstream>
#include <string>
#include <memory>

/// These basic utilities from Keyczar and the standard library are used
/// extensively throughout the Tao implementation, so we include them here.
#include <keyczar/base/base64w.h>
#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN
#include <keyczar/base/file_util.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/base/values.h>  // for ScopedSafeString

#include "tao/tao.h"

struct sockaddr;

namespace google {
namespace protobuf {
class Message;
}  // namespace protobuf
}  // namespace google

namespace tao {
/// These basic utilities from Keyczar and the standard library are used
/// extensively throughout the Tao implementation, so we import them into the
/// tao namespace here.
/// @{

using std::list;
using std::set;
using std::string;
using std::stringstream;
using std::unique_ptr;  // TODO(kwalsh) Discuss unique_ptr vs. scoped_ptr.
// using std::make_unique;  // TODO(kwalsh) Discuss unique_ptr vs. scoped_ptr.

using keyczar::base::Base64WDecode;
using keyczar::base::Base64WEncode;
using keyczar::base::CreateDirectory;
using keyczar::base::DirectoryExists;
// using keyczar::base::FilePath;  // Why isn't this in keyczar::base ?
using keyczar::base::PathExists;
// using keyczar::base::ReadFileToString; // Define our own version below.
using keyczar::base::ScopedSafeString;
using keyczar::base::WriteStringToFile;
using keyczar::base::Delete;

/// @}

/// Exception-safe factory for unique_ptr.
/// Author: Herb Sutter (http://herbsutter.com/gotw/_102/)
template <typename T, typename... Args>
std::unique_ptr<T> make_unique(Args &&... args) {
  return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
}

// class TaoChildChannelRegistry;
class TaoDomain;

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

/// A functor template for wrapping deallocators that misbehave on nullptr.
template <typename T, void (*F)(T *)>
struct CallUnlessNull {
  void operator()(T *ptr) const {
    if (ptr) F(ptr);
  }
};

/// A smart pointer to a file descriptor.
typedef scoped_ptr_malloc<int, CallUnlessNull<int, fd_close>> ScopedFd;

/// A smart pointer to a FILE.
typedef scoped_ptr_malloc<FILE, CallUnlessNull<FILE, file_close>> ScopedFile;

/// A smart pointer to a temporary directory to be cleaned upon destruction.
typedef scoped_ptr_malloc<string, CallUnlessNull<string, temp_file_cleaner>>
    ScopedTempDir;

/// A smart pointer to a self-pipe.
typedef scoped_ptr_malloc<int, CallUnlessNull<int, selfpipe_release>>
    ScopedSelfPipeFd;

/// Create a self-pipe for a signal. A signal handler is installed that writes
/// the signal number (cast to a byte) to the pipe. Callers can use the returned
/// file descriptor as part of a select() call. When a byte is available on the
/// file descriptor, it means that that signal has been received. An error is
/// returned if another self-pipe already exists (this limitation stems from the
/// need for global variables).
/// @param signum The signal to catch.
/// @param sa_flags Flags to modify the signal behavior. See sigaction(2).
/// @return A file descriptor suitable for select() and read(), or -1 on error.
int GetSelfPipeSignalFd(int signum, int sa_flags);

/// Destroy a self-pipe, restoring any previous signal handler.
/// @param fd The file descriptor returned from GetSelfPipeSignalFd().
bool ReleaseSelfPipeSignalFd(int fd);

/// Hash a string using SHA256.
/// @param s The string to hash.
/// @param[out] hash The resulting hash.
bool Sha256(const string &s, string *hash);

/// Hash a file using SHA256.
/// @param path The path of the file to hash.
/// @param[out] hash The resulting hash.
bool Sha256FileHash(const string &path, string *hash);

/// Read contents of a file and store (not append) in string. In contrast,
/// keyczar::base::ReadFileToString() appends the contents to the string.
/// @param path The path to the file, can be string or FilePath.
/// @param[out] contents The contents of the file.
template <class T>
bool ReadFileToString(const T &path, string *contents) {
  contents->clear();
  return keyczar::base::ReadFileToString(path, contents);
}

/// Register some well-known TaoChannels with the registry. The list of
/// registered TaoChannels is:
/// - KvmUnixTaoChannel
/// - PipeTaoChannel
/// @param registry The registry to fill with the channels
// bool RegisterKnownChannels(TaoChildChannelRegistry *registry);

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
///    CHECK(OpenSSLSuccess()) << "Required cert missing, exiting program";
///
/// We also install an OpenSSL FailureFunction that will call this function
/// before exiting on any FATAL error, e.g. errors from any CHECK(...) failure.
/// So this will also print details on ssl errors:
///    X509 *cert = SSL_get_certificate(...);
///    CHECK(cert != null) << "Could not find a required certificate, exiting
/// program";
bool OpenSSLSuccess();

/// Open a listening TCP socket on the given port.
/// @param host The host to listen on.
/// @param port The port to listen on.
/// @param[out] sock The socket opened for this port.
bool OpenTCPSocket(const string &host, const string &port, int *sock);

/// Get local address information about an open TCP socket.
/// @param sock The socket.
/// @param[out] host The local host address.
/// @param[out] port The local port.
bool GetTCPSocketInfo(int sock, string *host, string *port);

/// Connect to a remote server.
/// @param host The name of the remote host.
/// @param port The port to connect to.
/// @param[out] sock The connected client socket.
bool ConnectToTCPServer(const string &host, const string &port, int *sock);

/// Generate and save a random secret, sealed against the host Tao.
/// @param tao The interface to access the host Tao.
/// @param path The location to store the sealed secret.
/// @param policy A sealing policy under which to seal the secret.
/// @param secret_size The number of random bytes for the new secret.
/// @param[out] secret The new random secret.
bool MakeSealedSecret(Tao *tao, const string &path, const string &policy,
                      int secret_size, string *secret);

/// Read and unseal a secret that is sealed against the host Tao.
/// @param tao The interface to access the host Tao.
/// @param path The location to store the sealed secret.
/// @param policy The policy under which the secret is expected to have been
/// sealed. The call will fail if this does not match the actual policy under
/// which the secret was sealed.
/// @param secret[out] The unsealed secret.
bool GetSealedSecret(Tao *tao, const string &path, const string &policy,
                     string *secret);

/// Create a temporary directory.
/// @param prefix The partial path of the directory to create.
/// @param[out] dir A pointer to an object that will take ownership of the
/// new temporary directory.
bool CreateTempDir(const string &prefix, ScopedTempDir *dir);

/// Receive partial data from a file descriptor. This reads into buffer[i],
/// where filled_len <= i < buffer_len, and it returns the number of bytes read,
/// or 0 if end of stream, or negative on error.
/// @param fd The file descriptor to use to receive the data.
/// @param[out] buffer The buffer to fill with data.
/// @param filed_len The length of buffer that is already filled.
/// @param buffer_len The total length of buffer.
int ReceivePartialData(int fd, void *buffer, size_t filled_len,
                       size_t buffer_len);

/// Receive data from a file descriptor.
/// @param fd The file descriptor to use to receive the data.
/// @param[out] buffer The buffer to fill with data.
/// @param buffer_len The length of buffer.
/// @param[out] eof Will be set to true iff end of stream reached.
bool ReceiveData(int fd, void *buffer, size_t buffer_len, bool *eof);

/// Receive a string from a file descriptor.
/// @param fd The file descriptor to use to receive the data.
/// @param max_size The maximum allowable size string to receive.
/// @param[out] s The string to receive the data.
/// @param[out] eof Will be set to true iff end of stream reached.
bool ReceiveString(int fd, size_t max_size, string *s, bool *eof);

/// Send data to a file descriptor.
/// @param fd The file descriptor to use to send the data.
/// @param buffer The buffer containing data to send.
/// @param buffer_len The length of buffer.
bool SendData(int fd, const void *buffer, size_t buffer_len);

/// Send a string to a file descriptor.
/// @param fd The file descriptor to use to send the string.
/// @param s The string to send.
bool SendString(int fd, const string &s);

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

/// Skip a sequence of characters in a stream.
/// @param in The input stream.
/// @param s The characters to skip.
std::stringstream &skip(std::stringstream &in, const string &s);  // NOLINT

/// Elide a string for debug-printing purposes.
/// Non-printing and backslashes will be converted to escape sequences, and
/// long sequences of characters between double-quotes will be truncated.
string elideString(const string &s);

/// Elide an array of bytes for debug-printing purposes.
/// Bytes will be printed in hex, with long sequences truncated.
string elideBytes(const string &s);

/// Encode an array of bytes as hex.
/// @param s The array of bytes.
string bytesToHex(const string &s);

/// Decode hex into an array of bytes.
/// @param hex The hex string.
/// @param[out] s The array of bytes.
bool bytesFromHex(const string &hex, string *s);

/// Join a sequence of printable values as a string. Values are converted to
/// strings using the standard put << operator.
/// @param it An STL-like iterator marking the start of the sequence.
/// @param end An STL-like iterator marking the end of the sequence.
/// @param delim A dilimiter to put between values.
template <class T>
static string join(T it, T end, const string &delim) {
  stringstream out;
  bool first = true;
  for (; it != end; ++it) {
    if (!first) out << delim;
    first = false;
    out << *it;
  }
  return out.str();
}

/// Join a list of printable values as a string. Values are converted to
/// strings using the standard put << operator.
/// @param values A list of values.
/// @param delim A dilimiter to put between values.
template <class T>
static string join(const list<T> &values, const string &delim) {
  return join(values.begin(), values.end(), delim);
}

/// Join a set of printable values as a string. Values are converted to
/// strings using the standard put << operator.
/// @param values A set of values.
/// @param delim A dilimiter to put between values.
template <class T>
static string join(const set<T> &values, const string &delim) {
  return join(values.begin(), values.end(), delim);
}

/// Split a string into a list of strings.
/// @param s The string to split.
/// @param delim The delimiter used to separate the values.
/// @param[out] values A list of substrings from s, with delimiters discarded.
bool split(const string &s, const string &delim, list<string> *values);

/// Split a string into a list of integers.
/// @param s The string to split.
/// @param delim The delimiter used to separate the integers.
/// @param[out] values A list of integers from s.
bool split(const string &s, const string &delim, list<int> *values);

/// Get the modification timestamp for a file.
/// @param path The file path.
time_t FileModificationTime(const string &path);

}  // namespace tao

#endif  // TAO_UTIL_H_
