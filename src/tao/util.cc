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

#include <dirent.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/unistd.h>

#include <memory>
#include <mutex>
#include <sstream>
#include <vector>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <google/protobuf/text_format.h>
#include <keyczar/base/base64w.h>
#include <keyczar/base/file_util.h>
#include <keyczar/crypto_factory.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "tao/attestation.pb.h"
#include "tao/keys.h"
#include "tao/kvm_unix_tao_child_channel.h"
#include "tao/pipe_tao_child_channel.h"
#include "tao/signature.pb.h"
#include "tao/tao_child_channel.h"
#include "tao/tao_child_channel_registry.h"
#include "tao/tao_domain.h"

using std::lock_guard;
using std::mutex;
using std::shared_ptr;
using std::stringstream;
using std::vector;

using keyczar::CryptoFactory;
using keyczar::base::CreateDirectory;
using keyczar::base::Delete;
using keyczar::base::PathExists;
using keyczar::base::ReadFileToString;
using keyczar::base::WriteStringToFile;

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

/// 20 MB is the maximum allowed message on our channel implementations.
static size_t MaxChannelMessage = 20 * 1024 * 1024;

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
    if (!Delete(FilePath(*dir), true /* recursive */))
      PLOG(ERROR) << "Could not remove temp directory " << *dir;
    delete dir;
  }
}

vector<shared_ptr<mutex>> locks;

void locking_function(int mode, int n, const char *file, int line) {
  if (mode & CRYPTO_LOCK) {
    locks[n]->lock();
  } else {
    locks[n]->unlock();
  }
}

bool LetChildProcsDie() {
  struct sigaction sig_act;
  memset(&sig_act, 0, sizeof(sig_act));
  sig_act.sa_handler = SIG_DFL;
  sig_act.sa_flags = SA_NOCLDWAIT;  // don't zombify child processes
  int sig_rv = sigaction(SIGCHLD, &sig_act, nullptr);
  if (sig_rv < 0) {
    LOG(ERROR) << "Could not set the disposition of SIGCHLD";
    return false;
  }

  return true;
}

bool Sha256(const string &s, string *hash) {
  if (!CryptoFactory::SHA256()->Digest(s, hash)) {
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
  return InitializeOpenSSL();
}

// TODO(kwalsh) handle interaction between multi-threading and signals
static mutex selfPipeMutex;
static int selfPipe[2] = {-1, -1};
static int selfPipeSignum;
static struct sigaction selfPipeSavedAction;

static void SelfPipeHandler(int signum) {
  int savedErrno = errno;
  char b = static_cast<char>(signum);
  write(selfPipe[1], &b, 1);
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

// TODO(kwalsh) Take multiple signums if needed.
int GetSelfPipeSignalFd(int signum) {
  {
    lock_guard<mutex> l(selfPipeMutex);
    if (selfPipe[0] != -1) {
      LOG(ERROR) << "Self-pipe already opened";
      return -1;
    }
    if (pipe(selfPipe) == -1) {
      LOG(ERROR) << "Could not create self-pipe";
      return -1;
    }
    if (!SetFdFlags(selfPipe[0], O_NONBLOCK) ||
        !SetFdFlags(selfPipe[1], O_NONBLOCK)) {
      PLOG(ERROR) << "Could not set self-pipe disposition";
      close(selfPipe[0]);
      close(selfPipe[1]);
      selfPipe[0] = selfPipe[1] = -1;
      return -1;
    }
    struct sigaction act;
    memset(&act, 0, sizeof(struct sigaction));
    act.sa_handler = SelfPipeHandler;
    selfPipeSignum = signum;
    if (sigaction(signum, &act, &selfPipeSavedAction) < 0) {
      PLOG(ERROR) << "Could not set self-pipe handler";
      close(selfPipe[0]);
      close(selfPipe[1]);
      selfPipe[0] = selfPipe[1] = -1;
      return false;
    }
    return selfPipe[0];
  }
}

bool ReleaseSelfPipeSignalFd(int fd) {
  lock_guard<mutex> l(selfPipeMutex);
  if (fd == -1 || selfPipe[0] != fd) {
    LOG(ERROR) << "Incorrect self-pipe fd " << fd;
    return false;
  }
  if (sigaction(selfPipeSignum, &selfPipeSavedAction, nullptr) < 0) {
    PLOG(ERROR) << "Could not restore the old signal handler.";
  }
  close(selfPipe[0]);
  close(selfPipe[1]);
  selfPipe[0] = selfPipe[1] = -1;
  return true;
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

// TODO(kwalsh) fix policy hack
bool MakeSealedSecret(const TaoChildChannel &t, const string &path,
                      int secret_size, string *secret, int policy) {
  if (secret == nullptr) {
    LOG(ERROR) << "Could not seal null secret";
    return false;
  }
  if (!t.GetRandomBytes(secret_size, secret)) {
    LOG(ERROR) << "Could not generate a random secret to seal";
    return false;
  }
  string sealed_secret;
  if (!t.Seal(*secret, policy, &sealed_secret)) {
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

bool GetSealedSecret(const TaoChildChannel &t, const string &path,
                     string *secret, int *policy) {
  if (secret == nullptr) {
    LOG(ERROR) << "Could not unseal null secret";
    return false;
  }
  string sealed_secret;
  if (!ReadFileToString(path, &sealed_secret)) {
    LOG(ERROR) << "Can't read the sealed secret from " << path;
    return false;
  }
  if (!t.Unseal(sealed_secret, secret, policy)) {
    LOG(ERROR) << "Can't unseal the secret";
    return false;
  }
  VLOG(2) << "Unsealed a secret of size " << secret->size();
  return true;
}

// TODO(kwalsh) Remove this function
bool SealOrUnsealSecret(const TaoChildChannel &t, const string &path,
                        string *secret, int policy) {
  if (PathExists(FilePath(path))) {
    int unseal_policy;
    return GetSealedSecret(t, path, secret, &unseal_policy);
    if (policy != unseal_policy) {
      LOG(ERROR) << "Unsealed data, but provenance is uncertain.";
      return false;
    }
  } else {
    const int SecretSize = 16;
    return MakeSealedSecret(t, path, SecretSize, secret, policy);
  }
}

bool SendMessage(int fd, const google::protobuf::Message &m) {
  // send the length then the serialized message
  string serialized;
  if (!m.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the Message to a string";
    return false;
  }

  size_t len = serialized.size();
  ssize_t bytes_written = write(fd, &len, sizeof(size_t));
  if (bytes_written != sizeof(size_t)) {
    PLOG(ERROR) << "Could not write the length to the fd " << fd;
    return false;
  }

  bytes_written = write(fd, serialized.data(), len);
  if (bytes_written != static_cast<ssize_t>(len)) {
    PLOG(ERROR) << "Could not write the serialized message to the fd";
    return false;
  }

  return true;
}

bool SendMessageTo(int fd, const google::protobuf::Message &m,
                   const struct sockaddr *addr, socklen_t addr_len) {
  // send the length then the serialized message
  string serialized;
  if (!m.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the Message to a string";
    return false;
  }

  size_t len = serialized.size();
  ssize_t bytes_written = sendto(fd, &len, sizeof(size_t), 0, addr, addr_len);
  if (bytes_written != sizeof(size_t)) {
    PLOG(ERROR) << "Could not write the length to the fd " << fd;
    return false;
  }

  bytes_written = sendto(fd, serialized.data(), len, 0, addr, addr_len);
  if (bytes_written != static_cast<ssize_t>(len)) {
    PLOG(ERROR) << "Could not write the serialized message to the fd";
    return false;
  }

  return true;
}

bool ReceiveMessageFrom(int fd, google::protobuf::Message *m,
                        struct sockaddr *addr, socklen_t *addr_len) {
  // TODO(kwalsh) better handling of addr, addrlen, and recvfrom
  if (m == nullptr) {
    LOG(ERROR) << "null message";
    return false;
  }

  size_t len = 0;
  struct sockaddr_un first_addr;
  socklen_t first_addr_len = *addr_len;  // whatever size it should be
  ssize_t bytes_recvd =
      recvfrom(fd, &len, sizeof(len), 0, (struct sockaddr *)&first_addr,
               &first_addr_len);
  if (bytes_recvd == -1) {
    PLOG(ERROR) << "Could not receive any bytes on the channel";
    return false;
  }

  if (len > MaxChannelMessage) {
    LOG(ERROR) << "The length of the message on fd " << fd
               << " was too large to be reasonable: " << len;
    return false;
  }

  // Read this many bytes as the message.
  scoped_array<char> bytes(new char[len]);
  bytes_recvd = recvfrom(fd, bytes.get(), len, 0, addr, addr_len);
  if (bytes_recvd == -1) {
    PLOG(ERROR) << "Could not receive the actual message on fd " << fd;
    return false;
  }

  if (*addr_len != first_addr_len) {
    LOG(ERROR) << "Sock type mismatch";
    return false;
  }

  if (memcmp(&first_addr, addr, *addr_len) != 0) {
    LOG(ERROR) << "Receive message pieces from two different clients";
    return false;
  }

  string serialized(bytes.get(), len);
  return m->ParseFromString(serialized);
}

// TODO(kwalsh) move cloudproxy ReceivePartialData functions here and use them
bool ReceiveMessage(int fd, google::protobuf::Message *m, bool *eof) {
  if (m == nullptr) {
    LOG(ERROR) << "null message";
    return false;
  }

  *eof = false;

  // Some channels don't return all the bytes you request when you request them.
  // TODO(tmroeder): change this implementation to support select better so it
  // isn't subject to denial of service attacks by parties sending messages.
  size_t len = 0;
  ssize_t bytes_read = 0;
  while (static_cast<size_t>(bytes_read) < sizeof(len)) {
    ssize_t rv = read(fd, (reinterpret_cast<char *>(&len)) + bytes_read,
                      sizeof(len) - bytes_read);
    if (rv < 0) {
      if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
        continue;
      } else {
        PLOG(ERROR) << "Could not get an integer: expected " << sizeof(size_t)
                    << " bytes but only received " << bytes_read;
        return false;
      }
    }

    if (rv == 0) {
      // end of file, which can happen on some fds
      LOG(INFO) << "Got an end-of-file message on the fd";
      *eof = true;
      return true;
    }

    bytes_read += rv;
  }

  if (len > MaxChannelMessage) {
    LOG(ERROR) << "The length of the message on fd " << fd
               << " was too large to be reasonable: " << len;
    return false;
  }

  // Read this many bytes as the message.
  bytes_read = 0;
  scoped_array<char> bytes(new char[len]);
  while (bytes_read < static_cast<ssize_t>(len)) {
    int rv = read(fd, bytes.get() + bytes_read,
                  len - static_cast<size_t>(bytes_read));
    if (rv < 0) {
      if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
        continue;
      } else {
        PLOG(ERROR) << "Could not read enough bytes from the stream: "
                    << "expected " << static_cast<int>(len)
                    << " but received only " << bytes_read;
        return false;
      }
    }

    if (rv == 0) {
      // end of file, which can happen on some fds
      LOG(ERROR) << "Got an end-of-file message on the fd";
      return false;
    }

    bytes_read += rv;
  }

  string serialized(bytes.get(), len);
  return m->ParseFromString(serialized);
}

bool OpenUnixDomainSocket(const string &path, int *sock) {
  // The unix domain socket is used to listen for CreateHostedProgram requests.
  *sock = socket(AF_UNIX, SOCK_STREAM, 0);
  if (*sock == -1) {
    LOG(ERROR) << "Could not create unix domain socket to listen for messages";
    return false;
  }

  // Make sure the socket won't block if there's no data available, or not
  // enough data available.
  int fcntl_err = fcntl(*sock, F_SETFL, O_NONBLOCK);
  if (fcntl_err == -1) {
    PLOG(ERROR) << "Could not set the socket to be non-blocking";
    return false;
  }

  // Make sure there isn't already a file there.
  if (unlink(path.c_str()) == -1) {
    if (errno != ENOENT) {
      PLOG(ERROR) << "Could not remove the old socket at " << path;
      return false;
    }
  }

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  if (path.size() + 1 > sizeof(addr.sun_path)) {
    LOG(ERROR) << "The path " << path << " was too long to use";
    return false;
  }

  strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path));
  int len = strlen(addr.sun_path) + sizeof(addr.sun_family);
  int bind_err = bind(*sock, (struct sockaddr *)&addr, len);
  if (bind_err == -1) {
    PLOG(ERROR) << "Could not bind the address " << path << " to the socket";
    return false;
  }

  int listen_err = listen(*sock, 128 /* max completed connections */);
  if (listen_err == -1) {
    PLOG(ERROR) << "Could not set the socket up for listening";
    return false;
  }

  return true;
}

bool ConnectToUnixDomainSocket(const string &path, int *sock) {
  if (!sock) {
    LOG(ERROR) << "Null sock parameter";
    return false;
  }

  *sock = socket(PF_UNIX, SOCK_STREAM, 0);
  if (*sock == -1) {
    PLOG(ERROR) << "Could not create a unix domain socket";
    return false;
  }

  struct sockaddr_un addr;
  addr.sun_family = AF_UNIX;
  if (path.size() + 1 > sizeof(addr.sun_path)) {
    LOG(ERROR) << "This socket name is too large to use";
    close(*sock);
    return false;
  }

  strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path));
  int len = strlen(addr.sun_path) + sizeof(addr.sun_family);
  int conn_err = connect(*sock, (struct sockaddr *)&addr, len);
  if (conn_err == -1) {
    PLOG(ERROR) << "Could not connect to the socket";
    return false;
  }

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

bool CreateTempACLsDomain(ScopedTempDir *temp_dir,
                          scoped_ptr<TaoDomain> *admin) {
  // lax log messages: this is a top level function only used for unit testing
  if (!CreateTempDir("admin_domain", temp_dir)) return false;
  string path = **temp_dir + "/tao.config";
  string config = TaoDomain::ExampleACLGuardDomain;
  admin->reset(TaoDomain::Create(config, path, "temppass"));
  if (admin->get() == nullptr) return false;
  return true;
}

/* bool CreateTempRootDomain(ScopedTempDir *temp_dir,
                          scoped_ptr<TaoDomain> *admin) {
  // lax log messages: this is a top level function only used for unit testing
  if (!CreateTempDir("admin_domain", temp_dir)) return false;
  string path = **temp_dir + "/tao.config";
  string config = TaoDomain::ExampleRootAuthDomain;
  admin->reset(TaoDomain::Create(config, path, "temppass"));
  if (admin->get() == nullptr) return false;
  return true;
} */

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
  stringstream out;
  string hex = "0123456789abcdef";
  if (s.length() <= 20) {
    for (auto &c : s) out << hex[(c >> 4) & 0xf] << hex[(c >> 4) & 0xf];
  } else {
    for (unsigned int i = 0; i < 5; i++)
      out << hex[(s[i] >> 4) & 0xf] << hex[(s[i] >> 4) & 0xf];
    out << "...";
    for (unsigned int i = s.size() - 5; i < s.size(); i++)
      out << hex[(s[i] >> 4) & 0xf] << hex[(s[i] >> 4) & 0xf];
  }
  return out.str();
}
}  // namespace tao
