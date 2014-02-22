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
#include <ftw.h>
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
#include <vector>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/base/base64w.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base/json_reader.h>
#include <keyczar/base/json_writer.h>
#include <keyczar/base/values.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/keyczar.h>
#include <keyczar/rw/keyset_encrypted_file_reader.h>
#include <keyczar/rw/keyset_encrypted_file_writer.h>
#include <keyczar/rw/keyset_file_reader.h>
#include <keyczar/rw/keyset_file_writer.h>
#include <keyczar/rw/keyset_writer.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include "tao/kvm_unix_tao_child_channel.h"
#include "tao/pipe_tao_child_channel.h"
#include "tao/signature.pb.h"
#include "tao/tao_domain.h"

using std::mutex;
using std::shared_ptr;
using std::vector;

using keyczar::CryptoFactory;
using keyczar::Signer;
using keyczar::base::Base64WEncode;
using keyczar::base::CreateDirectory;
using keyczar::base::PathExists;
using keyczar::base::ReadFileToString;
using keyczar::base::WriteStringToFile;

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
    if (!keyczar::base::Delete(FilePath(*dir), true /* recursive */))
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

bool Sha256FileHash(const string &path, string *hash) {
  string contents;
  if (!ReadFileToString(path, &contents)) {
    LOG(ERROR) << "Can't read " << path;
    return false;
  }

  if (!CryptoFactory::SHA256()->Digest(contents, hash)) {
    LOG(ERROR) << "Can't compute hash of " << path;
    return false;
  }

  return true;
}

bool HashVM(const string &vm_template_path, const string &name,
            const string &kernel_file_path, const string &initrd_file_path,
            string *hash) {
  // TODO(tmroeder): take in the right hash type and use it here. For
  // now, we just assume that it's SHA256

  string template_hash;
  if (!Sha256FileHash(vm_template_path, &template_hash)) return false;

  string name_hash;
  if (!CryptoFactory::SHA256()->Digest(name, &name_hash)) {
    LOG(ERROR) << "Could not compute the has of the name";
    return false;
  }

  string kernel_hash;
  if (!Sha256FileHash(kernel_file_path, &kernel_hash)) return false;

  string initrd_hash;
  if (!Sha256FileHash(initrd_file_path, &initrd_hash)) return false;

  // Concatenate the hashes
  string hash_input;
  hash_input.append(template_hash);
  hash_input.append(name_hash);
  hash_input.append(kernel_hash);
  hash_input.append(initrd_hash);

  string composite_hash;
  if (!CryptoFactory::SHA256()->Digest(hash_input, &composite_hash)) {
    LOG(ERROR) << "Could not compute the composite hash\n";
    return false;
  }

  return Base64WEncode(composite_hash, hash);
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
  // glog bug workaround: stderrthreshold default should come from env
  char *s = getenv("GLOG_stderrthreshold");
  if (s && '0' <= s[0] && s[0] <= '9') FLAGS_stderrthreshold = atoi(s);
  // FLAGS_alsologtostderr = true;
  google::ParseCommandLineFlags(argc, argv, remove_args);
  google::InitGoogleLogging((*argv)[0]);
  google::InstallFailureSignalHandler();
  return InitializeOpenSSL();
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
  if (info_err == -1) {
    PLOG(ERROR) << "Could not get address information for " << host << ":"
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

bool MakeSealedSecret(const TaoChildChannel &t, const string &path,
                      int secret_size, string *secret) {
  if (secret == nullptr) {
    LOG(ERROR) << "Could not seal null secret";
    return false;
  }
  if (!t.GetRandomBytes(secret_size, secret)) {
    LOG(ERROR) << "Could not generate a random secret to seal";
    return false;
  }
  string sealed_secret;
  if (!t.Seal(*secret, &sealed_secret)) {
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
  if (!t.Unseal(sealed_secret, secret)) {
    LOG(ERROR) << "Can't unseal the secret";
    return false;
  }
  VLOG(2) << "Unsealed a secret of size " << secret->size();
  return true;
}

// TODO(kwalsh) Remove this function
bool SealOrUnsealSecret(const TaoChildChannel &t, const string &path,
                        string *secret) {
  if (PathExists(FilePath(path))) {
    return GetSealedSecret(t, path, secret);
  } else {
    const int SecretSize = 16;
    return MakeSealedSecret(t, path, SecretSize, secret);
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
                   struct ::sockaddr *addr, socklen_t addr_len) {
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
bool ReceiveMessage(int fd, google::protobuf::Message *m) {
  if (m == nullptr) {
    LOG(ERROR) << "null message";
    return false;
  }

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
      LOG(ERROR) << "Got an end-of-file message on the fd";
      return false;
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
  *sock = socket(AF_UNIX, SOCK_DGRAM, 0);
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

  return true;
}

bool ConnectToUnixDomainSocket(const string &path, int *sock) {
  if (!sock) {
    LOG(ERROR) << "Null sock parameter";
    return false;
  }

  *sock = socket(PF_UNIX, SOCK_DGRAM, 0);
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

bool GenerateAttestation(const Signer *signer, const string &cert,
                         Statement *statement, Attestation *attestation) {
  if (signer == nullptr) {
    LOG(ERROR) << "Can't sign with null key";
    return false;
  }
  if (statement == nullptr) {
    LOG(ERROR) << "Can't sign null statement";
    return false;
  }
  if (!statement->has_data()) {
    LOG(ERROR) << "Can't sign empty statement";
    return false;
  }
  if (attestation == nullptr) {
    LOG(ERROR) << "Can't sign null attestation";
    return false;
  }
  if (statement->hash().empty() != statement->hash_alg().empty()) {
    LOG(ERROR) << "Statement hash and hash_alg are inconsistent";
    return false;
  }
  // Fill in missing timestamp and expiration
  if (!statement->has_time()) {
    time_t cur_time;
    time(&cur_time);
    statement->set_time(cur_time);
  }
  if (!statement->has_expiration()) {
    statement->set_expiration(statement->time() +
                              Tao::DefaultAttestationTimeout);
  }
  // Sign the statement.
  string stmt, sig;
  if (!statement->SerializeToString(&stmt)) {
    LOG(ERROR) << "Could not serialize statement";
    return false;
  }
  if (!SignData(*signer, stmt, Tao::AttestationSigningContext, &sig)) {
    LOG(ERROR) << "Could not sign the statement";
    return false;
  }
  attestation->set_type(cert.empty() ? tao::ROOT : tao::INTERMEDIATE);
  attestation->set_serialized_statement(stmt);
  attestation->set_signature(sig);
  if (!cert.empty()) {
    attestation->set_cert(cert);
  } else {
    attestation->clear_cert();
  }

  VLOG(5) << "Generated " << (cert.empty() ? "ROOT" : "INTERMEDIATE")
          << "attestation"
          << "\n  with key named " << signer->keyset()->metadata()->name()
          << "\n  with Attestation = " << attestation->DebugString()
          << "\n  with Statement = " << statement->DebugString()
          << "\n  with cert = " << cert;

  return true;
}

bool GenerateAttestation(const Signer *signer, const string &cert,
                         Statement *statement, string *attestation) {
  Attestation a;
  if (!GenerateAttestation(signer, cert, statement, &a))
    return false;  // Plenty of log messages in the above call
  if (!a.SerializeToString(attestation)) {
    LOG(ERROR) << "Could not serialize attestation";
    return false;
  }
  return true;
}

bool CreateTempWhitelistDomain(ScopedTempDir *temp_dir,
                               scoped_ptr<TaoDomain> *admin) {
  // lax log messages: this is a top level function only used for unit testing
  if (!CreateTempDir("admin_domain", temp_dir)) return false;
  string path = **temp_dir + "/tao.config";
  string config = TaoDomain::ExampleWhitelistAuthDomain;
  admin->reset(TaoDomain::Create(config, path, "temppass"));
  if (admin->get() == nullptr) return false;
  return true;
}

bool CreateTempRootDomain(ScopedTempDir *temp_dir,
                          scoped_ptr<TaoDomain> *admin) {
  // lax log messages: this is a top level function only used for unit testing
  if (!CreateTempDir("admin_domain", temp_dir)) return false;
  string path = **temp_dir + "/tao.config";
  string config = TaoDomain::ExampleRootAuthDomain;
  admin->reset(TaoDomain::Create(config, path, "temppass"));
  if (admin->get() == nullptr) return false;
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

bool AuthorizeProgram(const string &path, TaoDomain *admin) {
  string program_name = FilePath(path).BaseName().value();
  string program_sha;
  if (!Sha256FileHash(path, &program_sha)) return false;

  string program_hash;
  if (!Base64WEncode(program_sha, &program_hash)) return false;

  return admin->Authorize(program_hash, TaoAuth::Sha256, program_name);
}

bool SerializeX509(X509 *x509, string *serialized_x509) {
  if (x509 == nullptr) {
    LOG(ERROR) << "null x509";
    return false;
  }

  int len = i2d_X509(x509, nullptr);
  if (!OpenSSLSuccess() || len < 0) {
    LOG(ERROR) << "Could not get the length of an X.509 certificate";
    return false;
  }

  unsigned char *serialization = nullptr;
  len = i2d_X509(x509, &serialization);
  scoped_ptr_malloc<unsigned char> der_x509(serialization);
  if (!OpenSSLSuccess() || len < 0) {
    LOG(ERROR) << "Could not encode an X.509 certificate in DER";
    return false;
  }

  serialized_x509->assign(reinterpret_cast<char *>(der_x509.get()), len);
  return true;
}

}  // namespace tao
