//  File: util.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Implementation of utility methods for the Tao.
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
#include "tao/util.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/unistd.h>

#include <memory>
#include <mutex>
#include <sstream>
#include <vector>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <modp/modp_b64w.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>

#include "tao/tao.h"

using std::lock_guard;
using std::mutex;
using std::shared_ptr;
using std::stringstream;
using std::vector;

using google::protobuf::io::StringOutputStream;
using google::protobuf::io::CodedOutputStream;

namespace tao {

void SecureStringErase(string *s) {
  // TODO(kwalsh) Keyczar has a nice 'fixme' note about making sure the memset
  // isn't optimized away, and a commented-out call to openssl's cleanse. What
  // to do?
  OPENSSL_cleanse(str2uchar(s), s->size());
  memset(str2uchar(s), 0, s->size());
}

void SecureStringFree(string *s) {
  SecureStringErase(s);
  delete s;
}

void fd_close(int *fd) {
  if (fd && *fd >= 0) {
    if (close(*fd) < 0) {
      PLOG(ERROR) << "Could not close file descriptor " << *fd;
    }
    delete fd;
  }
}

void file_close(FILE *file) {
  if (file) fclose(file);
}

void temp_file_cleaner(string *dir) {
  if (dir) {
    if (!DeleteFile(*dir, true /* recursive */))
      PLOG(ERROR) << "Could not remove temp directory " << *dir;
    delete dir;
  }
}

vector<shared_ptr<mutex>> locks;

static void locking_function(int mode, int n, const char *file, int line) {
  if (mode & CRYPTO_LOCK) {
    locks[n]->lock();
  } else {
    locks[n]->unlock();
  }
}

bool OpenSSLSuccess() {
  uint32_t last_error = ERR_get_error();
  if (last_error) {
    LOG(ERROR) << "OpenSSL errors:";
    while (last_error) {
      const char *lib = ERR_lib_error_string(last_error);
      const char *func = ERR_func_error_string(last_error);
      const char *reason = ERR_reason_error_string(last_error);
      LOG(ERROR) << " * " << last_error << ":" << (lib ? lib : "unknown") << ":"
                 << (func ? func : "unknown") << ":"
                 << (reason ? reason : "unknown");
      last_error = ERR_get_error();
    }
    return false;
  } else {
    return true;
  }
}

bool InitializeOpenSSL() {
  SSL_load_error_strings();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();
  OpenSSL_add_all_algorithms();
  SSL_library_init();

  // set up locking in OpenSSL
  int lock_count = CRYPTO_num_locks();
  locks.resize(lock_count);
  for (int i = 0; i < lock_count; i++) {
    locks[i].reset(new mutex());
  }
  CRYPTO_set_locking_callback(locking_function);
  return true;
}

bool InitializeApp(int *argc, char ***argv, bool remove_args) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;
  // FLAGS_alsologtostderr = true;
  google::ParseCommandLineFlags(argc, argv, remove_args);
  // google::InitGoogleLogging((*argv)[0]);
  google::InitGoogleLogging("/Users/jlm/tmp");
  google::InstallFailureSignalHandler();
  signal(SIGPIPE, SIG_IGN);
  return InitializeOpenSSL();
}

bool MakeSealedSecret(Tao *tao, const string &path, const string &policy,
                      int secret_size, string *secret) {
  if (secret == nullptr) {
    LOG(ERROR) << "Could not seal null secret";
    return false;
  }
  if (!tao->GetRandomBytes(secret_size, secret)) {
    LOG(ERROR) << "Could not generate a random secret to seal";
    return false;
  }
  string sealed_secret;
  if (!tao->Seal(*secret, policy, &sealed_secret)) {
    LOG(ERROR) << "Can't seal the secret";
    return false;
  }
  if (!CreateDirectory(FilePath(path).DirName())) {
    LOG(ERROR) << "Can't create directory for " << path;
    return false;
  }
  if (!WriteStringToFile(path, sealed_secret)) {
    LOG(ERROR) << "Can't write the sealed secret to " << path;
    return false;
  }
  VLOG(2) << "Sealed a secret of size " << secret_size;
  return true;
}

bool GetSealedSecret(Tao *tao, const string &path, const string &policy,
                     string *secret) {
  if (secret == nullptr) {
    LOG(ERROR) << "Could not unseal null secret";
    return false;
  }
  string sealed_secret;
  if (!ReadFileToString(path, &sealed_secret)) {
    LOG(ERROR) << "Can't read the sealed secret from " << path;
    return false;
  }
  string unseal_policy;
  if (!tao->Unseal(sealed_secret, secret, &unseal_policy)) {
    LOG(ERROR) << "Can't unseal the secret";
    return false;
  }
  if (unseal_policy != policy) {
    LOG(ERROR) << "Unsealed secret, but provenance is uncertain";
    return false;
  }
  VLOG(2) << "Unsealed a secret of size " << secret->size();
  return true;
}

bool CreateTempDir(const string &prefix, ScopedTempDir *dir) {
  // Get a temporary directory to use for the files.
  string dir_template = string("/tmp/temp_") + prefix + string("_XXXXXX");
  unique_ptr<char[]> temp_name(new char[dir_template.size() + 1]);
  memcpy(temp_name.get(), dir_template.data(), dir_template.size() + 1);

  if (!mkdtemp(temp_name.get())) {
    LOG(ERROR) << "Could not create the temporary directory";
    return false;
  }

  dir->reset(new string(temp_name.get()));
  return true;
}

bool ConnectToTCPServer(const string &host, const string &port, int *sock) {
  // Set up a socket to communicate with the TCCA.
  *sock = socket(AF_INET, SOCK_STREAM, 0);

  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  struct addrinfo *addrs = nullptr;
  int info_err = getaddrinfo(host.c_str(), port.c_str(), &hints, &addrs);
  if (info_err == -1) {
    PLOG(ERROR) << "Could not get address information for " << host << ":"
                << port;
    return false;
  }

  int connect_err = connect(*sock, addrs->ai_addr, addrs->ai_addrlen);
  if (connect_err == -1) {
    PLOG(ERROR) << "Could not connect to TCP server at " << host << ":" << port;
    freeaddrinfo(addrs);
    return false;
  }

  freeaddrinfo(addrs);

  return true;
}

string quotedString(const string &s) {
  stringstream out;
  out << '\"';
  for (const char &c : s) {
    if (c == '\\' || c == '\"') out << '\\';
    out << c;
  }
  out << '\"';
  return out.str();
}

stringstream &getQuotedString(stringstream &in, string *s) {  // NOLINT
  stringstream out;
  char c;
  while (in.get(c) && (c == ' ' || c == '\t')) {
  }
  if (!in || c != '\"') {
    in.setstate(std::ios::failbit);
    return in;
  }
  bool escape = false;
  while (in.get(c)) {
    if (!escape) {
      if (c == '\"') {
        s->assign(out.str());
        return in;
      } else if (c == '\\') {
        escape = true;
      } else {
        out << c;
      }
    } else {
      if ((c == '\"') || (c == '\\')) {
        out << c;
        escape = false;
      } else {
        in.setstate(std::ios::failbit);
        return in;
      }
    }
  }
  in.setstate(std::ios::failbit);
  return in;
}

stringstream &skip(stringstream &in, const string &s) {  // NOLINT
  for (unsigned int i = 0; in && i < s.size(); i++) {
    char c;
    in.get(c);
    if (c != s[i]) in.setstate(std::ios::failbit);
  }
  return in;
}

/// Elide a already-escaped string if necessary. If the string is short, it will
/// be returned as-is. Otherwise, a few characters at the beginning and end
/// will be left, and the middle replaced with ellipses. Escape sequences will
/// not be broken, and it is assumed that all backslashes are followed by
/// either a 3-character octal escape or a 1-character non-octal escape.
/// @param s The string to be elided.
/// @param thresh If s is no longer than this, it will be returned as-is.
/// @param prefix At least this many characters will be left before the
/// ellipses.
/// @param suffix At least this many characters will be left after the ellipses.
static string elideQuote(const string &s, size_t thresh, size_t prefix,
                         size_t suffix) {
  if (s.size() < thresh) return s;
  size_t i = 0;
  while (i < prefix) {
    if (s[i] == '\\' && '0' <= s[i + 1] && s[i + 1] <= '7')
      i += 4;  // skip octal escape
    else if (s[i] == '\\')
      i += 2;  // skip other escape
    else
      i++;
  }
  prefix = i;
  size_t j = i;
  while (s.size() - i >= suffix) {
    j = i;
    if (s[i] == '\\' && '0' <= s[i + 1] && s[i + 1] <= '7')
      i += 4;  // skip octal escape
    else if (s[i] == '\\')
      i += 2;  // skip other escape
    else
      i++;
  }
  suffix = j;
  return s.substr(0, prefix) + "..." + s.substr(suffix);
}

string elideString(const string &s) {
  stringstream out, elided;
  bool inQuote = false;
  for (auto &c : s) {
    if (c == '\0')
      out << "\0";
    else if (c == '\a')
      out << "\\a";
    else if (c == '\b')
      out << "\\b";
    else if (c == '\t')
      out << "\\t";
    else if (c == '\n')
      out << "\\n";
    else if (c == '\v')
      out << "\\v";
    else if (c == '\f')
      out << "\\f";
    else if (c == '\r')
      out << "\\r";
    else if (c == '\\')
      out << "\\\\";
    else if (c < ' ' || c > '~') {
      out << "\\" << ('0' + ((c >> 6) & 0x7)) << ('0' + ((c >> 3) & 0xf))
          << ('0' + ((c >> 0) & 0x7));
    } else if (c == '\"') {
      if (!inQuote)
        elided << out.str() << "\"";
      else
        elided << elideQuote(out.str(), 30, 10, 10) << "\"";
      out.str("");
      inQuote = !inQuote;
    } else {
      out << c;
    }
  }
  elided << out.str();
  return elided.str();
}

string elideBytes(const string &s) {
  if (s.length() <= 20)
    return bytesToHex(s);
  else
    return bytesToHex(s.substr(0, 4)) + "..." +
           bytesToHex(s.substr(s.size() - 5));
}

string bytesToHex(const string &s) {
  stringstream out;
  string hex = "0123456789abcdef";
  for (auto &c : s) out << hex[(c >> 4) & 0xf] << hex[(c >> 0) & 0xf];
  return out.str();
}

static int hexToInt(char c, int *i) {
  if ('0' <= c && c <= '9')
    *i = (c - '0');
  else if ('a' <= c && c <= 'f')
    *i = 10 + (c - 'a');
  else if ('A' <= c && c <= 'F')
    *i = 10 + (c - 'A');
  else
    return false;
  return true;
}

bool bytesFromHex(const string &hex, string *s) {
  stringstream out;
  if (hex.size() % 2) return false;
  for (unsigned int i = 0; i < hex.size(); i += 2) {
    int x, y;
    if (!hexToInt(hex[i], &x) || !hexToInt(hex[i + 1], &y)) return false;
    out.put((x << 4) | y);
  }
  s->assign(out.str());
  return true;
}

bool split(const string &s, const string &delim, list<string> *values) {
  values->clear();
  if (s == "") return true;
  stringstream in(s);
  while (in) {
    // no errors yet, still strings to be read
    string value;
    getline(in, value, delim[0]);
    // no errors yet, eof set if last string, maybe other chars
    values->push_back(value);
    if (in.eof()) return true;
    // no errors yet, not last string, maybe other chars
    skip(in, delim.substr(1));
    // errors if delim was missing, else still strings to be read
  }
  return false;
}

bool split(const string &s, const string &delim, list<int> *values) {
  values->clear();
  if (s == "") return true;
  stringstream in(s);
  while (in) {
    // no errors yet, still values to be read
    int value;
    in >> value;
    if (!in) return false;
    // no errors yet, eof set if last int, maybe other chars
    values->push_back(value);
    if (in.eof()) return true;
    // no errors yet, not last int, maybe other chars
    skip(in, delim);
    // errors if delim was missing, else still values to be read
  }
  return false;
}

time_t FileModificationTime(const string &path) {
  struct stat st;
  if (stat(path.c_str(), &st) != 0) {
    LOG(ERROR) << "File does not exist: " << path;
    return 0;
  }
  return st.st_mtime;
}

bool WeakRandBytes(size_t size, string *s) {
  // Use openssl.
  s->resize(size);
  return (RAND_bytes(str2uchar(s), size) == 1);
}

string Base64WEncode(const string &in) {
  string out;
  Base64WEncode(in, &out);  // does not fail
  return out;
}

bool Base64WEncode(const string &in, string *out) {
  if (out == nullptr) {
    return false;
  }
  size_t in_len = in.size();
  out->resize(modp_b64w_encode_len(in_len));
  size_t out_len = modp_b64w_encode(str2char(out), str2char(in), in_len);
  out->resize(out_len);
  return true;
}

bool Base64WDecode(const string &in, string *out) {
  if (out == nullptr) {
    return false;
  }
  size_t in_len = in.size();
  out->resize(modp_b64w_decode_len(in_len));
  int out_len = modp_b64w_decode(str2char(out), str2char(in), in_len);
  if (out_len < 0) {
    out->clear();
    return false;
  }
  out->resize(out_len);
  return true;
}

// These constants give the tags needed to encode a key auth.Prin in binary form
// in a Speaksfor statement.
static int tagPrin = 0x1;
static int tagBytes = 0x4;
static int tagSpeaksfor = 0xd;
static int tagSubPrin = 0x11;
bool MarshalSpeaksfor(const string &key, const string &binaryTaoName,
                      string *out) {

  StringOutputStream *sos = new StringOutputStream(out);
  CodedOutputStream *cos = new CodedOutputStream(sos);
  // Tag this as a Speaksfor object.
  cos->WriteVarint32(tagSpeaksfor);

  string delegate;
  if (!MarshalKeyPrin(key, &delegate)) {
    delete cos;
    delete sos;
    return false;
  }

  cos->WriteRaw(delegate.data(), delegate.size());

  // The delegator is written directly, since it's already a binary-encoded
  // Term.
  cos->WriteRaw(binaryTaoName.data(), binaryTaoName.size());

  delete cos;
  delete sos;
  return true;
}

bool MarshalKeyPrin(const string &key, string *out) {
  StringOutputStream *sos = new StringOutputStream(out);
  CodedOutputStream *cos = new CodedOutputStream(sos);

  // auth.Prin is tagPrin, then a string type "key", then a Key buffer, and no
  // extensions (this is marshaled as tagSubPrin, 0).
  cos->WriteVarint32(tagPrin);

  // Type: "key"
  string keyType("key");
  cos->WriteVarint32(keyType.size());
  cos->WriteRaw(keyType.data(), keyType.size());

  // Key: auth.Bytes[...]
  cos->WriteVarint32(tagBytes);
  cos->WriteVarint32(key.size());
  cos->WriteRaw(key.data(), key.size());

  // Ext: auth.SubPrin of length 0
  cos->WriteVarint32(tagSubPrin);
  cos->WriteVarint32(0);

  delete cos;
  delete sos;
  return true;
}

bool InitNewCounter(Tao *tao, const string &label, const int64_t& c) {
/*
  if (!tao->GetRandomBytes(secret_size, secret)) {
    LOG(ERROR) << "Could not generate a random secret to seal";
    return false;
  }
*/
  return false;
}

bool GetACounter(Tao *tao, const string &label, const int64_t* c) {
  return false;
}

bool MakeRollbackProtectedSealedSecret(Tao *tao, const string &path,
      const string &policy, int secret_size, string *secret) {
  return false;
}

bool GetRollbackProtectedSealedSecret(Tao *tao, const string &path,
      const string &policy, string *secret) {
  return false;
}

}  // namespace tao
