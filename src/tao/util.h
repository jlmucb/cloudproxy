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

/// These basic utilities from the standard library are used extensively
/// throughout the Tao implementation, so we include them here.
#include <list>
#include <memory>
#include <set>
#include <sstream>
#include <string>

/// These basic utilities from Keyczar are used extensively throughout the Tao
/// implementation, so we include them here.
/// TODO(kwalsh) Most of this is actually not original to Keyczar, but is
/// instead borrowed from Chromium, protobufs, or elsewhere. Perhaps we should
/// do
/// likewise?
#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN
#include <keyczar/base/file_util.h>

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
using std::unique_ptr;
// using std::make_unique;  // implemented below

using keyczar::base::CreateDirectory;    // NOLINT
using keyczar::base::Delete;             // NOLINT
using keyczar::base::DirectoryExists;    // NOLINT
using keyczar::base::PathExists;         // NOLINT
using keyczar::base::WriteStringToFile;  // NOLINT

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

/// A version of unique_ptr::reset() that returns the new pointer. Useful for
/// putting reset inside of conditionals.
/// @param t The unique_ptr to be reset.
/// @param p The new pointer to manage.
template <typename T>
T *reset(unique_ptr<T> &t, T *p) {  // NOLINT
  t.reset(p);
  return p;
}

/// A functor template for wrapping unique_ptr deallocator functions.
template <typename T, void (*F)(T *)>
struct UniquePointerDeleter {
  void operator()(T *ptr) const { F(ptr); }
};

/// A typedef template (aka type alias, alias template) for zero-overhead
/// unique_ptr with a custom deallocator function.
template <typename T, void (*F)(T *)>
using unique_free_ptr = unique_ptr<T, UniquePointerDeleter<T, F>>;

/// Cleanse the contents of a string.
/// @param s The string to be cleansed.
void SecureStringErase(string *s);

/// Cleanse the contents of a string then free it.
/// @param s The string to be cleansed and freed.
void SecureStringFree(string *s);

/// A smart pointer to a string that clears itself.
typedef unique_free_ptr<string, SecureStringFree> ScopedSafeString;

/// A smart pointer to a file descriptor.
typedef unique_free_ptr<int, fd_close> ScopedFd;

/// A smart pointer to a FILE.
typedef unique_free_ptr<FILE, file_close> ScopedFile;

/// A smart pointer to a temporary directory to be cleaned upon destruction.
typedef unique_free_ptr<string, temp_file_cleaner> ScopedTempDir;

/// A smart pointer to a self-pipe.
typedef unique_free_ptr<int, selfpipe_release> ScopedSelfPipeFd;

/// Extract pointer to string data. These can be used for library functions
/// that require raw pointers instead of C++ strings. Returned const pointers
/// should not be written to. Returned non-const pointers can be written. Any
/// string operation that invalidates an iterator will also invalidate the
/// returned pointer.
/// @param s The string.
/// @{
// TODO(kwalsh) See cryptic note about string_as_array vs const_cast in Keyczar
// and elsewhere saying:
//    DO NOT USE const_cast<char*>(str->data())! See the unittest for why.
// This likely has to do with the fact that the buffer returned from data() is
// not meant to be modified and might in fact be copy-on-write shared.
inline const char *str2char(const string &s) {
  return s.empty() ? nullptr : &*s.begin();
}
inline const unsigned char *str2uchar(const string &s) {
  return reinterpret_cast<const unsigned char *>(str2char(s));
}
inline char *str2char(string *s) { return s->empty() ? nullptr : &*s->begin(); }
inline unsigned char *str2uchar(string *s) {
  return reinterpret_cast<unsigned char *>(str2char(s));
}
/// @}

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

/// Hash a string using SHA1 or SHA256.
/// @param s The string to hash.
/// @param[out] hash The resulting hash.
/// @{
bool Sha1(const string &s, string *hash);
bool Sha256(const string &s, string *hash);
/// @}

/// Hash a file using SHA1 or SHA256.
/// @param path The path of the file to hash.
/// @param[out] hash The resulting hash.
/// @{
bool Sha1FileHash(const string &path, string *hash);
bool Sha256FileHash(const string &path, string *hash);
/// @}

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
/// @param delim A delimiter to put between values.
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
/// @param delim A delimiter to put between values.
template <class T>
static string join(const list<T> &values, const string &delim) {
  return join(values.begin(), values.end(), delim);
}

/// Join a set of printable values as a string. Values are converted to
/// strings using the standard put << operator.
/// @param values A set of values.
/// @param delim A delimiter to put between values.
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

/// Get random bytes from OpenSSL.
/// @param size The number of bytes to get.
/// @param[out] s A string in which to place the bytes.
bool WeakRandBytes(size_t size, string *s);

/// Get random bytes from host Tao, if available, otherwise from OpenSSL.
/// @param size The number of bytes to get.
/// @param[out] s A string in which to place the bytes.
// TODO(kwalsh) Rethink this function.
bool RandBytes(size_t size, string *s);

/// Encode string using web-safe base64w. No padding or newlines are added. This
/// function does not fail.
/// @param in The string to be encoded. May be emptystring.
string Base64WEncode(const string &in);

/// Encode string using web-safe base64w. No padding or newlines are added.
/// @param in The string to be encoded. May be emptystring.
/// @param[out] out A string to be overwritten with the result.
/// @return false if and only if out is nullptr.
bool Base64WEncode(const string &in, string *out);

/// Decode string using web-safe base64w. This function fails if padding,
/// newlines, or other unexpected characters are found in the input, or if the
/// input length is not valid.
/// @param in The string to be encoded. May be emptystring.
/// @param[out] out A string to be overwritten with the result.
bool Base64WDecode(const string &in, string *out);

}  // namespace tao

#endif  // TAO_UTIL_H_
