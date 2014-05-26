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
//#include <google/protobuf/text_format.h>
//#include <keyczar/base/base64w.h>
//#include <keyczar/base/file_util.h>
#include <keyczar/crypto_factory.h>
#include <openssl/crypto.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
//#include <openssl/x509.h>

#include "tao/attestation.pb.h"
#include "tao/keys.h"
//#include "tao/kvm_unix_tao_child_channel.h"
//#include "tao/pipe_tao_child_channel.h"
//#include "tao/tao_child_channel.h"
//#include "tao/tao_child_channel_registry.h"
#include "tao/tao_domain.h"

using std::lock_guard;
using std::mutex;
using std::shared_ptr;
using std::stringstream;
using std::vector;

// Workaround for keyczar logging.
// There is no obvious API to disable keyczar message logging to console. This
// is particularly annoying for expected-case "errors", e.g. when the user types
// the wrong password for PBE decryption. Keyczar uses an old google logging
// implementation borrowed from an old version of google protobuf, and we
// can hook that to divert all log messages to our own handler.

// Log levels defined in keyczar/base/logging.h
enum LogLevel {
  LOGLEVEL_KEYCZAR_INFO = 0,
  LOGLEVEL_KEYCZAR_WARNING,
  LOGLEVEL_KEYCZAR_ERROR,
  LOGLEVEL_KEYCZAR_FATAL
};

// Handler type defined in keyczar/base/logging.h
typedef void KeyczarLogHandler(LogLevel level, const char *filename, int line,
                               const std::string &message);

// Hook defined in keyczar/base/logging.h
KeyczarLogHandler *SetLogHandler(KeyczarLogHandler *new_func);

// Our log sink
static void QuietKeyczarLogHandler(LogLevel level, const char *filename,
                                   int line, const std::string &message) {
  // ignore filename and line, they are always keyczar/openssl/util.h:33
  switch (level) {
    case LOGLEVEL_KEYCZAR_INFO:
      LOG(INFO) << "Keyczar info: " << message;
      break;
    case LOGLEVEL_KEYCZAR_WARNING:
      LOG(WARNING) << "Keyczar warning: " << message;
      break;
    case LOGLEVEL_KEYCZAR_FATAL:
      LOG(FATAL) << "Keyczar fatal: " << message;
      break;
    default:
      LOG(ERROR) << "Keyczar error: " << message;
      break;
  }
}

namespace tao {

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
    if (!keyczar::base::Delete(FilePath(*dir), true /* recursive */))
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

bool Sha256(const string &s, string *hash) {
  if (!keyczar::CryptoFactory::SHA256()->Digest(s, hash)) {
    // This should be fatal. If it happens, then openssl has died.
    LOG(ERROR) << "Can't compute hash";
    return false;
  }
  return true;
}

bool Sha256FileHash(const string &path, string *hash) {
  string contents;
  if (!ReadFileToString(path, &contents)) {
    LOG(ERROR) << "Can't read " << path;
    return false;
  }

  return Sha256(contents, hash);
}

/*
bool RegisterKnownChannels(TaoChildChannelRegistry *registry) {
  if (registry == nullptr) {
    LOG(ERROR) << "Could not register channels with a null registry";
    return false;
  }

  registry->Register(
      KvmUnixTaoChildChannel::ChannelType(),
      TaoChildChannelRegistry::CallConstructor<KvmUnixTaoChildChannel>);

  registry->Register(
      PipeTaoChildChannel::ChannelType(),
      TaoChildChannelRegistry::CallConstructor<PipeTaoChildChannel>);

  return true;
}
*/

bool OpenSSLSuccess() {
  uint32 last_error = ERR_get_error();
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
  google::InitGoogleLogging((*argv)[0]);
  google::InstallFailureSignalHandler();
  SetLogHandler(QuietKeyczarLogHandler);
  signal(SIGPIPE, SIG_IGN);
  return InitializeOpenSSL();
}

constexpr int MaxSelfPipeSignum = NSIG;
struct SelfPipe {
  bool open;
  int fd[2];
  struct sigaction sa;
};
SelfPipe selfPipe[MaxSelfPipeSignum] = { };
static mutex selfPipeMutex;

static void SelfPipeHandler(int signum) {
  if (signum <= 0 || signum > MaxSelfPipeSignum)
    return;
  if (!selfPipe[signum-1].open)
    return;
  int savedErrno = errno;
  char b = static_cast<char>(signum);
  write(selfPipe[signum-1].fd[1], &b, 1);
  errno = savedErrno;
}

static bool SetFdFlags(int fd, int flags) {
  int f = fcntl(fd, F_GETFL);
  if (f == -1) {
    LOG(ERROR) << "Could not get flags for fd " << fd;
    return false;
  }
  if (fcntl(fd, F_SETFL, f | flags) == -1) {
    LOG(ERROR) << "Could not set flags for fd " << fd;
    return false;
  }
  return true;
}

int GetSelfPipeSignalFd(int signum, int sa_flags) {
  if (signum <= 0 || signum > MaxSelfPipeSignum) {
    LOG(ERROR) << "Invalid self-pipe signal number " << signum;
    return -1;
  }
  lock_guard<mutex> l(selfPipeMutex);
  if (selfPipe[signum - 1].open) {
    LOG(ERROR) << "Self-pipe already opened";
    // We could instead return the existing fd here if callers can share it.
    return -1;
  }
  if (pipe(selfPipe[signum - 1].fd) == -1) {
    LOG(ERROR) << "Could not create self-pipe";
    return -1;
  }
  if (!SetFdFlags(selfPipe[signum - 1].fd[0], O_NONBLOCK) ||
      !SetFdFlags(selfPipe[signum - 1].fd[1], O_NONBLOCK)) {
    PLOG(ERROR) << "Could not set self-pipe disposition";
    close(selfPipe[signum - 1].fd[0]);
    close(selfPipe[signum - 1].fd[1]);
    selfPipe[signum - 1].fd[0] = selfPipe[signum - 1].fd[1] = -1;
    return -1;
  }
  struct sigaction act;
  memset(&act, 0, sizeof(struct sigaction));
  act.sa_handler = SelfPipeHandler;
  act.sa_flags = sa_flags;
  if (sigaction(signum, &act, &selfPipe[signum - 1].sa) < 0) {
    PLOG(ERROR) << "Could not set self-pipe handler";
    close(selfPipe[signum - 1].fd[0]);
    close(selfPipe[signum - 1].fd[1]);
    selfPipe[signum - 1].fd[0] = selfPipe[signum - 1].fd[1] = -1;
    return -1;
  }
  selfPipe[signum - 1].open = true;
  return selfPipe[signum - 1].fd[0];
}

bool ReleaseSelfPipeSignalFd(int fd) {
  if (fd < 0) {
    LOG(ERROR) << "Invalid self-pipe fd " << fd;
    return false;
  }
  lock_guard<mutex> l(selfPipeMutex);
  for (int signum = 1; signum <= MaxSelfPipeSignum; signum++) {
    if (!selfPipe[signum-1].open || selfPipe[signum-1].fd[0] != fd) 
      continue;
    selfPipe[signum -1].open = false;
    bool success = true;
    if (sigaction(signum, &selfPipe[signum-1].sa, nullptr) < 0) {
      PLOG(ERROR) << "Could not restore old handler for signal " << signum;
      success = false;
    }
    close(selfPipe[signum-1].fd[0]);
    close(selfPipe[signum-1].fd[1]);
    selfPipe[signum-1].fd[0] = selfPipe[signum-1].fd[1] = -1;
    return success;
  }
  LOG(ERROR) << "No such self-pipe fd " << fd;
  return false;
}

void selfpipe_release(int *fd) {
  if (fd && *fd >= 0) {
    if (!ReleaseSelfPipeSignalFd(*fd)) {
      PLOG(ERROR) << "Could not close self-pipe fd " << *fd;
    }
    delete fd;
  }
}

bool OpenTCPSocket(const string &host, const string &port, int *sock) {
  if (sock == nullptr) {
    LOG(ERROR) << "null socket parameter";
    return false;
  }

  *sock = socket(AF_INET, SOCK_STREAM, 0);
  if (*sock == -1) {
    PLOG(ERROR) << "Could not create a socket to listen on";
    return false;
  }

  // Don't allow TIME_WAIT sockets from interfering with bind() below. The
  // socket option SO_REUSEADDR allows this socket to bind even when there is
  // another bound socket in TIME_WAIT.
  int val = 1;
  if (setsockopt(*sock, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) != 0) {
    PLOG(ERROR) << "Could not set SO_REUSEADDR on the socket for " << host
                << ":" << port;
    return false;
  }

  struct addrinfo hints;
  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  struct addrinfo *addrs = nullptr;
  int info_err = getaddrinfo(host.c_str(), port.c_str(), &hints, &addrs);
  if (info_err != 0) {
    LOG(ERROR) << "Could not get address information for " << host << ":"
               << port;
    return false;
  }

  int bind_err = bind(*sock, addrs->ai_addr, addrs->ai_addrlen);
  if (bind_err == -1) {
    PLOG(ERROR) << "Could not bind the socket";
    return false;
  }

  int listen_err = listen(*sock, 128 /* max completed connections */);
  if (listen_err == -1) {
    PLOG(ERROR) << "Could not set the socket up for listening";
    return false;
  }

  return true;
}

bool GetTCPSocketInfo(int sock, string *host, string *port) {
  struct sockaddr_in addr;
  unsigned int len = sizeof(addr);
  if (getsockname(sock, (struct sockaddr *)&addr, &len) == -1) {
    PLOG(ERROR) << "Could not get socket name";
    return false;
  }
  char buf[INET_ADDRSTRLEN];
  host->assign(inet_ntop(AF_INET, &addr.sin_addr, buf, sizeof(buf)));
  stringstream out;
  out << (unsigned)ntohs(addr.sin_port);
  port->assign(out.str());
  return true;
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
  scoped_array<char> temp_name(new char[dir_template.size() + 1]);
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

int ReceivePartialData(int fd, void *buffer, size_t filled_len,
                       size_t buffer_len) {
  if (fd < 0 || buffer == nullptr || filled_len >= buffer_len) {
    LOG(ERROR) << "Invalid ReceivePartialData parameters";
    return -1;
  }

  int in_len = read(fd, reinterpret_cast<unsigned char *>(buffer) + filled_len,
                    buffer_len - filled_len);
  if (in_len < 0) PLOG(ERROR) << "Failed to read data from file descriptor";

  return in_len;
}

bool ReceiveData(int fd, void *buffer, size_t buffer_len, bool *eof) {
  *eof = false;
  size_t filled_len = 0;
  while (filled_len != buffer_len) {
    int in_len = ReceivePartialData(fd, buffer, filled_len, buffer_len);
    if (in_len == 0) {
      *eof = true;
      return (filled_len == 0);  // fail only on truncated message
    }
    if (in_len < 0) return false;   // fail on errors
    filled_len += in_len;
  }

  return true;
}

bool ReceiveString(int fd, size_t max_size, string *s, bool *eof) {
  uint32_t net_len;
  if (!ReceiveData(fd, &net_len, sizeof(net_len), eof)) {
    LOG(ERROR) << "Could not get the length of the data";
    return false;
  } else if (*eof) {
    return true;
  }

  // convert from network byte order to get the length
  uint32_t len = ntohl(net_len);
  
  if (len > max_size) {
    LOG(ERROR) << "Message exceeded maximum allowable size";
    return false;
  }
  scoped_array<char> temp_data(new char[len]);

  if (!ReceiveData(fd, temp_data.get(), static_cast<size_t>(len), eof) || *eof) {
    LOG(ERROR) << "Could not get the data";
    return false;
  }

  s->assign(temp_data.get(), len);

  return true;
}

bool SendData(int fd, const void *buffer, size_t buffer_len) {
  int bytes_written = write(fd, buffer, buffer_len);
  if (bytes_written < 0) {
    PLOG(ERROR) << "Could not send data";
    return false;
  }
  if (static_cast<size_t>(bytes_written) != buffer_len) {
    LOG(ERROR) << "Could not send complete data";
    return false;
  }
  return true;
}

bool SendString(int fd, const string &s) {
  uint32_t net_len = htonl(s.size());
  return SendData(fd, &net_len, sizeof(net_len)) &&
      SendData(fd, s.c_str(), s.size());
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

}  // namespace tao
