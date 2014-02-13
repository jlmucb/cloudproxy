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

#include <fstream>  // NOLINT TODO(kwalsh) use keyczar file utils
#include <memory>
#include <mutex>
#include <sstream>  // NOLINT TODO(kwalsh) use keyczar file utils
#include <vector>

#include <keyczar/base/base64w.h>
#include <keyczar/base/file_util.h>
#include <keyczar/base/json_reader.h>
#include <keyczar/base/json_writer.h>
#include <keyczar/base/values.h>
#include <keyczar/crypto_factory.h>
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

using std::ifstream;
using std::ios;
using std::mutex;
using std::ofstream;
using std::shared_ptr;
using std::stringstream;
using std::vector;

using keyczar::Crypter;
using keyczar::CryptoFactory;
using keyczar::Key;
using keyczar::KeyPurpose;
using keyczar::KeyStatus;
using keyczar::KeyType;
using keyczar::Keyset;
using keyczar::KeysetMetadata;
using keyczar::MessageDigestImpl;
using keyczar::Signer;
using keyczar::Verifier;
using keyczar::base::Base64WDecode;
using keyczar::base::Base64WEncode;
using keyczar::base::CreateDirectory;
using keyczar::base::PathExists;
using keyczar::base::ReadFileToString;
using keyczar::rw::KeysetEncryptedJSONFileReader;
using keyczar::rw::KeysetEncryptedJSONFileWriter;
using keyczar::rw::KeysetJSONFileReader;
using keyczar::rw::KeysetJSONFileWriter;
using keyczar::rw::KeysetPBEJSONFileReader;
using keyczar::rw::KeysetPBEJSONFileWriter;
using keyczar::rw::KeysetReader;
using keyczar::rw::KeysetWriter;

int remove_entry(const char *path, const struct stat *sb, int tflag,
                 struct FTW *ftwbuf) {
  switch (tflag) {
    case FTW_DP:
      // DP means the directory's children have all been processed.
      if (rmdir(path) < 0) {
        PLOG(ERROR) << "Could not remove the directory " << path;
        return 1;
      }
      break;
    case FTW_F:
    case FTW_SL:
      if (unlink(path) < 0) {
        PLOG(ERROR) << "Could not unlink the file " << path;
        return 1;
      }
      break;
    default:
      LOG(ERROR) << "Error in handling directory or file. Could not completely "
                 << "delete the directory";
  }

  return 0;
}

namespace tao {

/// 20 MB is the maximum allowed message on our channel implementations.
static size_t MaxChannelMessage = 20 * 1024 * 1024;

void fd_close(int *fd) {
  if (fd) {
    if (*fd >= 0) {
      if (close(*fd) < 0) {
        PLOG(ERROR) << "Could not close file descriptor " << *fd;
      }
    }

    delete fd;
  }

  return;
}

void file_close(FILE *file) {
  if (file) fclose(file);
}

// TODO(kwalsh): Use keyczar's file utils instead
void temp_file_cleaner(string *dir) {
  if (dir) {
    if (nftw(dir->c_str(), remove_entry, 10 /* nopenfd */, FTW_DEPTH) < 0) {
      PLOG(ERROR) << "Could not remove temp directory " << *dir;
    }

    delete dir;
  }
}

vector<shared_ptr<mutex> > locks;

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

bool DeserializePublicKey(const KeyczarPublicKey &kpk,
                          scoped_ptr<Verifier> *key) {
  if (key == nullptr) {
    LOG(ERROR) << "null key";
    return false;
  }

  char tempdir[] = "/tmp/public_key_XXXXXX";
  if (mkdtemp(tempdir) == nullptr) {
    LOG(ERROR) << "Could not create a temp directory for public key export";
    return false;
  }

  ScopedTempDir temp_dir(new string(tempdir));

  // write the files to the temp directory and make sure they close
  {
    // write the metadata
    string metadata_file_name = *temp_dir + string("/meta");
    ofstream meta_file(metadata_file_name.c_str(), ofstream::out | ios::binary);
    meta_file.write(kpk.metadata().data(), kpk.metadata().size());

    // iterate over the public keys and write each one to disk
    int key_count = kpk.files_size();
    for (int i = 0; i < key_count; i++) {
      const KeyczarPublicKey::KeyFile &kf = kpk.files(i);
      stringstream ss;
      ss << *temp_dir << "/" << kf.name();
      ofstream file(ss.str().c_str(), ofstream::out | ios::binary);
      file.write(kf.data().data(), kf.data().size());
    }
  }

  if (!LoadVerifierKey(*temp_dir, key)) {
    LOG(ERROR) << "Could not deserialize the key";
    return false;
  }

  return true;
}

string SerializePublicKey(const Signer &key) {
  KeyczarPublicKey kpk;
  if (!SerializePublicKey(key, &kpk)) {
    LOG(ERROR) << "Could not serialize the public key for signing";
    return "";
  }
  string serialized_pub_key;
  if (!kpk.SerializeToString(&serialized_pub_key)) {
    LOG(ERROR) << "Could not serialize the key to a string";
    return "";
  }
  return serialized_pub_key;
}

bool SerializePublicKey(const Signer &key, KeyczarPublicKey *kpk) {
  if (kpk == nullptr) {
    LOG(ERROR) << "Could not serialize to a null public key structure";
    return false;
  }

  char tempdir[] = "/tmp/public_key_XXXXXX";
  if (mkdtemp(tempdir) == nullptr) {
    LOG(ERROR) << "Could not create a temp directory for public key export";
    return false;
  }

  ScopedTempDir temp_dir(new string(tempdir));

  scoped_ptr<KeysetWriter> writer(new KeysetJSONFileWriter(*temp_dir));
  if (writer.get() == nullptr) {
    return false;
  }

  const Keyset *keyset = key.keyset();
  if (!keyset->PublicKeyExport(*writer)) {
    LOG(ERROR) << "Could not export the public key";
    return false;
  }

  return SerializeKeyset(key.keyset(), tempdir, kpk);
}

bool SerializeKeyset(const Keyset *keyset, const string &path,
                     KeyczarPublicKey *kpk) {
  // now iterate over the files in the directory and add them to the public key
  string meta_file_name = path + string("/meta");
  ifstream meta_file(meta_file_name.c_str(), ifstream::in | ios::binary);
  stringstream meta_stream;
  meta_stream << meta_file.rdbuf();
  kpk->set_metadata(meta_stream.str());

  KeysetMetadata::const_iterator version_iterator = keyset->metadata()->Begin();
  for (; version_iterator != keyset->metadata()->End(); ++version_iterator) {
    int v = version_iterator->first;
    stringstream file_name_stream;
    file_name_stream << path << "/" << v;
    ifstream file(file_name_stream.str().c_str(), ifstream::in | ios::binary);
    stringstream file_buf;
    file_buf << file.rdbuf();

    KeyczarPublicKey::KeyFile *kf = kpk->add_files();
    kf->set_name(v);
    kf->set_data(file_buf.str());
  }

  return true;
}

bool SignData(const string &data, const string &context, string *signature,
              const Signer *key) {
  if (context.empty()) {
    LOG(ERROR) << "Cannot sign a message with an empty context";
    return false;
  }

  SignedData s;
  s.set_context(context);
  s.set_data(data);
  string serialized;
  if (!s.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the message and context together";
    return false;
  }

  if (!key->Sign(serialized, signature)) {
    LOG(ERROR) << "Could not sign the data";
    return false;
  }

  return true;
}

bool VerifySignature(const string &data, const string &context,
                     const string &signature, const keyczar::Verifier *key) {
  if (context.empty()) {
    LOG(ERROR) << "Cannot sign a message with an empty context";
    return false;
  }

  SignedData s;
  s.set_context(context);
  s.set_data(data);
  string serialized;
  if (!s.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the message and context together";
    return false;
  }

  if (!key->Verify(serialized, signature)) {
    LOG(ERROR) << "Verify failed";
    return false;
  }

  return true;
}

// Debug code for dumping a keyczar keyset primary key:
// {
//   const Keyset *keyset = key.keyset();
//   const keyczar::Key *primary_key = keyset->primary_key();
//   scoped_ptr<Value> v(primary_key->GetValue());
//   string json;
//   keyczar::base::JSONWriter::Write(v.get(), true /* pretty print */, &json);
//   VLOG(0) << "json for keyset is:\n" << json;
// }

/// Make a (deep) copy of a Keyset.
/// @param keyset The keyset to be copied.
/// @param[out] copy The keyset to fill with the copy.
bool CopyKeyset(const Keyset &keyset, scoped_ptr<Keyset> *copy) {
  if (copy == nullptr) {
    LOG(ERROR) << "null keyset";
    return false;
  }
  scoped_ptr<Value> meta_value(
      keyset.metadata()->GetValue(true /* "immutable" copy of keyset */));
  if (meta_value.get() == nullptr) {
    LOG(ERROR) << "Could not serialize keyset metadata";
    return false;
  }
  scoped_ptr<Keyset> ks(new Keyset());
  ks->set_metadata(KeysetMetadata::CreateFromValue(meta_value.get()));
  if (ks->metadata() == nullptr) {
    LOG(ERROR) << "Could not deserialize keyset metadata";
    return false;
  }
  KeyType::Type key_type = ks->metadata()->key_type();
  for (auto it = ks->metadata()->Begin(); it != ks->metadata()->End(); ++it) {
    int version = it->first;
    const Key *oldkey = keyset.GetKey(version);
    if (oldkey == nullptr) {
      LOG(ERROR) << "Missing key version " << version;
      return false;
    }
    scoped_ptr<Value> key_value(oldkey->GetValue());
    if (key_value.get() == nullptr) {
      LOG(ERROR) << "Could not serialize key version " << version;
      return false;
    }
    scoped_ptr<Key> newkey(Key::CreateFromValue(key_type, *key_value));
    if (!ks->AddKey(newkey.release(), version)) {
      LOG(ERROR) << "Could not add copied key version " << version;
      return false;
    }
  }
  // We can't cleanly copy keyset metadata because the primary key status is
  // tracked in twice: in the metadata (KeysetMetadata::KeyVersion::key_status_)
  // and also in the keyset (Keyset::primary_key_version_number_). These get out
  // of sync. Ideally, Keyset::set_metadata() would update
  // Keyset::primary_key_version_number_.
  // Workaround: demote the primary key then re-promote it.
  int primary_key = keyset.primary_key_version_number();
  if (primary_key > 0) {
    ks->DemoteKey(primary_key);
    ks->PromoteKey(primary_key);
  }
  copy->reset(ks.release());
  return true;
}

bool CopySigningKey(const Signer &key, scoped_ptr<Signer> *copy) {
  scoped_ptr<Keyset> keyset;
  if (!CopyKeyset(*key.keyset(), &keyset)) {
    LOG(ERROR) << "Could not copy Signer keyset";
    return false;
  }
  copy->reset(new Signer(keyset.release()));
  if (copy->get() == nullptr) {
    LOG(ERROR) << "Could not construct Signer copy";
    return false;
  }
  (*copy)->set_encoding(Signer::NO_ENCODING);
  return true;
}

bool CopyVerifierKey(const Verifier &key, scoped_ptr<Verifier> *copy) {
  scoped_ptr<Keyset> keyset;
  if (!CopyKeyset(*key.keyset(), &keyset)) {
    LOG(ERROR) << "Could not copy Verifier keyset";
    return false;
  }
  copy->reset(new Verifier(keyset.release()));
  if (copy->get() == nullptr) {
    LOG(ERROR) << "Could not construct Verifier copy";
    return false;
  }
  (*copy)->set_encoding(Verifier::NO_ENCODING);
  return true;
}

bool CopyCryptingKey(const Crypter &key, scoped_ptr<Crypter> *copy) {
  scoped_ptr<Keyset> keyset;
  if (!CopyKeyset(*key.keyset(), &keyset)) {
    LOG(ERROR) << "Could not copy Crypter keyset";
    return false;
  }
  copy->reset(new Crypter(keyset.release()));
  if (copy->get() == nullptr) {
    LOG(ERROR) << "Could not construct Crypter copy";
    return false;
  }
  (*copy)->set_encoding(Crypter::NO_ENCODING);
  return true;
}

// TODO(kwalsh) dup with linux_tao. Version in linux_tao.cc is better.
bool SealOrUnsealSecret(const TaoChildChannel &t, const string &sealed_path,
                        string *secret) {
  // create or unseal a secret from the Tao
  FilePath fp(sealed_path);
  if (PathExists(fp)) {
    // Unseal it
    ifstream sealed_file(sealed_path.c_str(), ifstream::in | ios::binary);
    stringstream sealed_buf;
    sealed_buf << sealed_file.rdbuf();

    if (!t.Unseal(sealed_buf.str(), secret)) {
      LOG(ERROR) << "Could not unseal the secret from " << sealed_path;
      return false;
    }

  } else {
    // create and seal the secret
    const int SecretSize = 16;
    if (!t.GetRandomBytes(SecretSize, secret)) {
      LOG(ERROR) << "Could not get a random secret from the Tao";
      return false;
    }

    // seal it and write the result to the specified file
    string sealed_secret;
    if (!t.Seal(*secret, &sealed_secret)) {
      LOG(ERROR) << "Could not seal the secret";
      return false;
    }

    ofstream sealed_file(sealed_path.c_str(), ofstream::out | ios::binary);
    sealed_file.write(sealed_secret.data(), sealed_secret.size());
  }

  return true;
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

bool LoadCryptingKey(const string &path, const string &password,
                     scoped_ptr<Crypter> *key) {
  scoped_ptr<Crypter> crypter;
  if (password.empty()) {
    LOG(ERROR) << "Empty password is not allowed";
    return false;
  }

  // keyczar does a CHECK fail if the path does not exist. To avoid that, we
  // check the existence of the path first.
  if (!PathExists(FilePath(path))) {
    LOG(ERROR) << "Could not initialize crypter from " << path
               << ": directory does not exist";
    return false;
  }

  key->reset(Crypter::Read(KeysetPBEJSONFileReader(path, password)));
  if (key->get() == nullptr) {
    LOG(ERROR) << "Could not initialize the crypter from " << path;
    return false;
  }
  (*key)->set_encoding(Crypter::NO_ENCODING);
  return true;
}

bool LoadSigningKey(const string &path, const string &password,
                    scoped_ptr<Signer> *key) {
  if (password.empty()) {
    LOG(ERROR) << "Empty password is not allowed";
    return false;
  }

  // keyczar does a CHECK fail if the path does not exist. To avoid that, we
  // check the existence of the path first.
  if (!PathExists(FilePath(path))) {
    LOG(ERROR) << "Could not initialize signer from " << path
               << ": directory does not exist";
    return false;
  }

  key->reset(Signer::Read(KeysetPBEJSONFileReader(path, password)));
  if (key->get() == nullptr) {
    LOG(ERROR) << "Could not initialize the signer from " << path;
    return false;
  }
  (*key)->set_encoding(Signer::NO_ENCODING);
  return true;
}

bool LoadEncryptedSigningKey(const string &path, const string &crypter_path,
                             const string &crypter_password,
                             scoped_ptr<Signer> *key) {
  // load the crypting key used for decrypting the private key
  scoped_ptr<Crypter> crypter;
  if (!LoadCryptingKey(crypter_path, crypter_password, &crypter)) return false;

  // keyczar does a CHECK fail if the path does not exist. To avoid that, we
  // check the existence of the path first.
  if (!PathExists(FilePath(path))) {
    LOG(ERROR) << "Could not initialize signer from " << path
               << ": directory does not exist";
    return false;
  }

  key->reset(
      Signer::Read(KeysetEncryptedJSONFileReader(path, crypter.release())));
  if (key->get() == nullptr) {
    LOG(ERROR) << "Could not initialize the signer from " << path;
    return false;
  }
  (*key)->set_encoding(Crypter::NO_ENCODING);
  return true;
}

bool LoadVerifierKey(const string &path, scoped_ptr<Verifier> *key) {
  // keyczar does a CHECK fail if the path does not exist. To avoid that, we
  // check the existence of the path first.
  if (!PathExists(FilePath(path))) {
    LOG(ERROR) << "Could not initialize verifier from " << path
               << ": directory does not exist";
    return false;
  }

  key->reset(Verifier::Read(path));
  if (key->get() == nullptr) {
    LOG(ERROR) << "Could not initialize the verifier from " << path;
    return false;
  }
  (*key)->set_encoding(Verifier::NO_ENCODING);
  return true;
}

/// Prepare a KeysetWriter using either cleartext, PBE, or crypter-encryption.
/// @param path The location for the writer to write. The directory will be
/// created if needed.
/// @param crypter A crypter for crypter-encryption, or nullptr.
/// @param password A password for PBE, or emptystring.
/// @return The keyset writer, or nullptr on error.
static KeysetJSONFileWriter *PrepareKeysetWriter(const string &path,
                                                 scoped_ptr<Crypter> *crypter,
                                                 const string &password) {
  if (!CreateDirectory(FilePath(path))) {
    LOG(ERROR) << "Can't create key directory " << path;
    return nullptr;
  }

  scoped_ptr<KeysetJSONFileWriter> writer;
  if (crypter)
    writer.reset(new KeysetEncryptedJSONFileWriter(path, crypter->release()));
  else if (!password.empty())
    writer.reset(new KeysetPBEJSONFileWriter(path, password));
  else
    writer.reset(new KeysetJSONFileWriter(path));  // used for public keys

  if (writer.get() == nullptr) {
    LOG(ERROR) << "Can't write to key directory " << path;
    return nullptr;
  }

  return writer.release();
}

/// Generate a signing key using the given writers. This takes ownership of both
/// writers (if given).
/// @param key_type The type of key, e.g. RSA_PRIV, ECDSA_PRIV, HMAC, HMAC_SHA1.
/// @param private_writer A writer to write the private key, or nullptr.
/// @param public_writer A writer to write the public key, or nullptr.
/// @param name A name for the new key.
/// @param key[out] The new key.
static bool GenerateSigningKeyWithWriters(KeyType::Type key_type,
                                          KeysetJSONFileWriter *private_writer,
                                          KeysetJSONFileWriter *public_writer,
                                          const string &name,
                                          scoped_ptr<Signer> *key) {
  if (key == nullptr) {
    LOG(ERROR) << "null key";
    return false;
  }

  scoped_ptr<KeysetJSONFileWriter> priv_writer(private_writer);
  scoped_ptr<KeysetJSONFileWriter> pub_writer(public_writer);
  private_writer = public_writer = nullptr;

  scoped_ptr<Keyset> keyset(new Keyset());
  if (priv_writer.get() != nullptr) keyset->AddObserver(priv_writer.get());
  keyset->set_encrypted(true);

  keyset->set_metadata(
      new KeysetMetadata(name, key_type, KeyPurpose::SIGN_AND_VERIFY,
                         true /*encrypted (unused?)*/, 1 /*next key version*/));

  keyset->GenerateDefaultKeySize(KeyStatus::PRIMARY);

  // We still own the writer, need to RemoveObserver before end of function.
  if (priv_writer.get() != nullptr) keyset->RemoveObserver(priv_writer.get());

  if (pub_writer.get() != nullptr) {
    if (!keyset->PublicKeyExport(*pub_writer)) {
      LOG(ERROR) << "Can't write public key to directory "
                 << pub_writer->dirname().value();
      // Keyczar is evil and runs EVP_cleanup(), which removes all the symbols.
      // So, they need to be added again. Typical error is:
      // * 336236785:SSL routines:SSL_CTX_new:unable to load ssl2 md5 routines
      // This needs to be done as close after PBE operations as possible,
      // and we need to reset anything that might be holding a PBE
      // object to force it to destruct and EVP_cleanup.
      keyset.reset();       // reset to force PBE object destruction
      priv_writer.reset();  // reset to force PBE object destruction
      pub_writer.reset();   // reset to force PBE object destruction
      OpenSSL_add_all_algorithms();
      return false;
    }
  }

  key->reset(new Signer(keyset.release()));
  (*key)->set_encoding(Signer::NO_ENCODING);

  // Keyczar is evil and runs EVP_cleanup(), which removes all the symbols.
  // So, they need to be added again. Typical error is:
  // * 336236785:SSL routines:SSL_CTX_new:unable to load ssl2 md5 routines
  // This needs to be done as close after PBE operations as possible,
  // and we need to reset anything that might be holding a PBE
  // object to force it to destruct and EVP_cleanup.
  priv_writer.reset();  // reset to force PBE object destruction
  pub_writer.reset();   // reset to force PBE object destruction
  OpenSSL_add_all_algorithms();

  return true;
}

bool CreateTempDir(const string &prefix, ScopedTempDir *dir) {
  // Get a temporary directory to use for the files.
  string dir_template = string("/tmp/") + prefix + string("_XXXXXX");
  scoped_array<char> temp_name(new char[dir_template.size() + 1]);
  memcpy(temp_name.get(), dir_template.data(), dir_template.size() + 1);

  if (!mkdtemp(temp_name.get())) {
    LOG(ERROR) << "Could not create the temporary directory";
    return false;
  }

  dir->reset(new string(temp_name.get()));
  return true;
}

bool GenerateCryptingKey(KeyType::Type key_type, const string &path,
                         const string &name, const string &password,
                         scoped_ptr<Crypter> *key) {
  scoped_ptr<Keyset> keyset(new Keyset());

  scoped_ptr<KeysetJSONFileWriter> writer;  // retain until end of function
  if (!path.empty()) {
    if (password.empty()) {
      LOG(ERROR) << "Empty password is not allowed";
      return false;
    }
    writer.reset(PrepareKeysetWriter(path, nullptr /* no crypter */, password));
    if (writer.get() == nullptr) return false;
    keyset->AddObserver(writer.get());
  }

  keyset->set_encrypted(true);
  keyset->set_metadata(
      new KeysetMetadata(name, key_type, KeyPurpose::DECRYPT_AND_ENCRYPT,
                         true /*encrypted (unused?)*/, 1 /*next key version*/));

  keyset->GenerateDefaultKeySize(KeyStatus::PRIMARY);

  // We still own the writer, need to RemoveObserver before end of function.
  if (writer.get() != nullptr) keyset->RemoveObserver(writer.get());

  key->reset(new Crypter(keyset.release()));
  (*key)->set_encoding(Crypter::NO_ENCODING);
  // Keyczar is evil and runs EVP_cleanup(), which removes all the symbols.
  // So, they need to be added again. Typical error is:
  // * 336236785:SSL routines:SSL_CTX_new:unable to load ssl2 md5 routines
  // This needs to be done as close after PBE operations as possible,
  // and we need to reset anything that might be holding a PBE
  // object to force it to destruct and EVP_cleanup.
  writer.reset();  // release to force PBE object destruction
  OpenSSL_add_all_algorithms();
  return true;
}

bool GenerateSigningKey(KeyType::Type key_type, const string &private_path,
                        const string &public_path, const string &name,
                        const string &password, scoped_ptr<Signer> *key) {
  scoped_ptr<KeysetJSONFileWriter> private_writer;
  if (!private_path.empty()) {
    if (password.empty()) {
      LOG(ERROR) << "Empty password is not allowed";
      return false;
    }
    private_writer.reset(
        PrepareKeysetWriter(private_path, nullptr /* no crypter */, password));
    if (private_writer.get() == nullptr) return false;
  }

  scoped_ptr<KeysetJSONFileWriter> public_writer;
  if (!public_path.empty()) {
    public_writer.reset(PrepareKeysetWriter(
        public_path, nullptr /* no crypter */, "" /* no pass */));
    if (public_writer.get() == nullptr) return false;
  }

  return GenerateSigningKeyWithWriters(key_type, private_writer.release(),
                                       public_writer.release(), name, key);
}

bool GenerateEncryptedSigningKey(KeyType::Type key_type,
                                 const string &private_path,
                                 const string &public_path, const string &name,
                                 const string &crypter_path,
                                 const string &crypter_password,
                                 scoped_ptr<Signer> *key) {
  // load the crypting key used for encrypting the private key
  scoped_ptr<Crypter> crypter;
  if (!LoadCryptingKey(crypter_path, crypter_password, &crypter)) return false;

  scoped_ptr<KeysetJSONFileWriter> private_writer;
  private_writer.reset(
      PrepareKeysetWriter(private_path, &crypter, "" /* no pass */));
  if (private_writer.get() == nullptr) return false;

  scoped_ptr<KeysetJSONFileWriter> public_writer;
  if (!public_path.empty()) {
    public_writer.reset(PrepareKeysetWriter(
        public_path, nullptr /* no crypter */, "" /* no pass */));
    if (public_writer.get() == nullptr) return false;
  }

  return GenerateSigningKeyWithWriters(key_type, private_writer.release(),
                                       public_writer.release(), name, key);
}

bool GenerateAttestation(const Signer *signer, const string &cert,
                         Statement *statement, Attestation *attestation) {
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
  if (!SignData(stmt, Tao::AttestationSigningContext, &sig, signer)) {
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
  if (!CreateTempDir("temp_admin_domain", temp_dir)) return false;
  string path = **temp_dir + "/tao.config";
  string config = TaoDomain::ExampleWhitelistAuthDomain;
  admin->reset(TaoDomain::Create(config, path, "temppass"));
  if (admin->get() == nullptr) return false;
  return true;
}

bool CreateTempRootDomain(ScopedTempDir *temp_dir,
                          scoped_ptr<TaoDomain> *admin) {
  // lax log messages: this is a top level function only used for unit testing
  if (!CreateTempDir("temp_admin_domain", temp_dir)) return false;
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
    PLOG(ERROR) << "Could not connect to the TCCA";
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

typedef scoped_ptr_malloc<
    BIGNUM, keyczar::openssl::OSSLDestroyer<BIGNUM, BN_clear_free> >
    ScopedSecretBIGNUM;

bool ExportKeyToOpenSSL(const Verifier *key, ScopedEvpPkey *pem_key) {
  // Note: Much of this function is adapted from code in
  // keyczar::openssl::ECDSAOpenSSL::Create().
  if (key == nullptr || pem_key == nullptr) {
    LOG(ERROR) << "null key or pem_key";
    return false;
  }
  // TODO(kwalsh) Implement this function for RSA, other types
  KeyType::Type key_type = key->keyset()->metadata()->key_type();
  if (key_type != KeyType::ECDSA_PUB && key_type != KeyType::ECDSA_PRIV) {
    LOG(ERROR) << "ExportKeyToOpenSSL only implemented for ECDSA so far";
    return false;
  }
  // Get raw key data out of keyczar
  // see also: GetPublicKeyValue()
  scoped_ptr<Value> value(key->keyset()->primary_key()->GetValue());
  CHECK(value->IsType(Value::TYPE_DICTIONARY));
  DictionaryValue *dict = static_cast<DictionaryValue *>(value.get());
  string curve_name, public_curve_name;
  string private_base64, public_base64, private_bytes, public_bytes;
  bool has_private = dict->HasKey("privateKey");
  if (has_private) {
    if (!dict->GetString("namedCurve", &curve_name) ||
        !dict->GetString("privateKey", &private_base64) ||
        !dict->GetString("publicKey.namedCurve", &public_curve_name) ||
        !dict->GetString("publicKey.publicBytes", &public_base64)) {
      LOG(ERROR) << "Keyczar key missing expected values";
      return false;
    }
    if (public_curve_name != curve_name) {
      LOG(ERROR) << "Keyczar key curve mismatch";
      return false;
    }
  } else {
    if (!dict->GetString("namedCurve", &curve_name) ||
        !dict->GetString("publicBytes", &public_base64)) {
      LOG(ERROR) << "Keyczar key missing expected values";
      return false;
    }
  }
  if (!Base64WDecode(public_base64, &public_bytes)) {
    LOG(ERROR) << "Could not decode keyczar public key data";
    return false;
  }
  if (has_private && !Base64WDecode(private_base64, &private_bytes)) {
    LOG(ERROR) << "Could not decode keyczar private key data";
    return false;
  }
  // check curve name
  int curve_nid = OBJ_sn2nid(curve_name.c_str());  // txt2nid
  if (!OpenSSLSuccess() || curve_nid == NID_undef) {
    LOG(ERROR) << "Keyczar key uses unrecognized ec curve " << curve_name;
    return false;
  }
  ScopedECKey ec_key(EC_KEY_new_by_curve_name(curve_nid));
  if (!OpenSSLSuccess() || ec_key.get() == NULL) {
    LOG(ERROR) << "Could not allocate EC_KEY";
    return false;
  }
  // Make sure the ASN1 will have curve OID should this EC_KEY be exported.
  EC_KEY_set_asn1_flag(ec_key.get(), OPENSSL_EC_NAMED_CURVE);
  // public_key
  EC_KEY *key_tmp = ec_key.get();
  const unsigned char *public_key_bytes =
      reinterpret_cast<const unsigned char *>(public_bytes.data());
  if (!o2i_ECPublicKey(&key_tmp, &public_key_bytes, public_bytes.length())) {
    OpenSSLSuccess();  // print errors
    LOG(ERROR) << "Could not convert keyczar public key to openssl";
    return false;
  }
  // private_key
  const unsigned char *private_key_bytes =
      reinterpret_cast<const unsigned char *>(private_bytes.data());
  ScopedSecretBIGNUM bn(
      BN_bin2bn(private_key_bytes, private_bytes.length(), nullptr));
  if (!OpenSSLSuccess() || bn.get() == NULL) {
    LOG(ERROR) << "Could not parse keyczar private key data";
    return false;
  }
  if (!EC_KEY_set_private_key(ec_key.get(), bn.get())) {
    OpenSSLSuccess();  // print errors
    LOG(ERROR) << "Could not convert keyczar private key to openssl";
    return false;
  }
  bn.reset();
  // final sanity check
  if (!EC_KEY_check_key(ec_key.get())) {
    OpenSSLSuccess();  // print errors
    LOG(ERROR) << "Converted OpenSSL key fails checks";
    return false;
  }
  // Move EC_KEY into EVP_PKEY
  ScopedEvpPkey evp_key(EVP_PKEY_new());
  if (!OpenSSLSuccess() || evp_key.get() == NULL) {
    LOG(ERROR) << "Could not allocate EVP_PKEY";
    return false;
  }
  if (!EVP_PKEY_set1_EC_KEY(evp_key.get(), ec_key.get())) {
    LOG(ERROR) << "Could not convert EC_KEY to EVP_PKEY";
    return false;
  }

  pem_key->reset(evp_key.release());

  return true;
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

/// Set one detail for an openssl x509 name structure.
/// @param name The x509 name structure to modify. Must be non-null.
/// @param key The country code, e.g. "US"
/// @param id The detail id, e.g. "C" for country or "CN' for common name
/// @param val The value to be set
static void SetX509NameDetail(X509_NAME *name, const string &id,
                              const string &val) {
  X509_NAME_add_entry_by_txt(
      name, id.c_str(), MBSTRING_ASC,
      reinterpret_cast<unsigned char *>(const_cast<char *>(val.c_str())), -1,
      -1, 0);
  if (!OpenSSLSuccess())
    LOG(WARNING) << "Could not set x509 " << id << " detail";
}

/// Set the details for an openssl x509 name structure.
/// @param name The x509 name structure to modify. Must be non-null.
/// @param c The country code, e.g. "US".
/// @param o The organization code, e.g. "Google"
/// @param st The state code, e.g. "Washington"
/// @param cn The common name, e.g. "Example Tao CA Service" or "localhost"
static void SetX509NameDetails(X509_NAME *name, const string &c,
                               const string &o, const string &st,
                               const string &cn) {
  SetX509NameDetail(name, "C", c);
  SetX509NameDetail(name, "ST", st);
  SetX509NameDetail(name, "O", o);
  SetX509NameDetail(name, "CN", cn);
}

/// Add an extension to an openssl x509 structure.
/// @param x509 The certificate to modify. Must be non-null.
/// @param nid The NID_* constant for this extension.
/// @param val The string value to be added.
bool PrepareX509(X509 *x509, int version, int serial, EVP_PKEY *subject_key) {
  X509_set_version(x509, version);

  ASN1_INTEGER_set(X509_get_serialNumber(x509), serial);

  // set notBefore and notAfter to get a reasonable validity period
  X509_gmtime_adj(X509_get_notBefore(x509), 0);
  X509_gmtime_adj(X509_get_notAfter(x509), Tao::DefaultAttestationTimeout);

  // This method allocates a new public key for x509, and it doesn't take
  // ownership of the key passed in the second parameter.
  X509_set_pubkey(x509, subject_key);
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Could not add the public key to the X.509 structure";
    return false;
  }

  return true;
}

/// Add an extension to an openssl x509 structure.
/// @param x509 The certificate to modify. Must be non-null.
/// @param nid The NID_* constant for this extension.
/// @param val The string value to be added.
static void AddX509Extension(X509 *x509, int nid, const string &val) {
  X509V3_CTX ctx;
  X509V3_set_ctx_nodb(&ctx);
  X509V3_set_ctx(&ctx, x509, x509, nullptr, nullptr, 0);

  char *data = const_cast<char *>(val.c_str());
  X509_EXTENSION *ex = X509V3_EXT_conf_nid(nullptr, &ctx, nid, data);
  if (!OpenSSLSuccess() || ex == nullptr) {
    LOG(WARNING) << "Could not add x509 extension";
    return;
  }
  X509_add_ext(x509, ex, -1);
  X509_EXTENSION_free(ex);
}

/// Write an openssl X509 structure to a file in PEM format.
/// @param x509 The certificate to write. Must be non-null.
/// @param path The location to write the PEM data.
static bool WriteX509File(X509 *x509, const string &path) {
  if (!CreateDirectory(FilePath(path).DirName())) {
    LOG(ERROR) << "Could not create directory for " << path;
    return false;
  }

  ScopedFile cert_file(fopen(path.c_str(), "wb"));
  if (cert_file.get() == nullptr) {
    PLOG(ERROR) << "Could not open file " << path << " for writing";
    return false;
  }

  PEM_write_X509(cert_file.get(), x509);
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Could not write the X.509 certificate to " << path;
    return false;
  }

  return true;
}

bool CreateSelfSignedX509(const Signer *key, const string &country,
                          const string &state, const string &org,
                          const string &cn, const string &public_cert_path) {
  // we need an openssl version of the key to create and sign the x509 cert
  ScopedEvpPkey pem_key;
  if (!ExportKeyToOpenSSL(key, &pem_key)) return false;

  // create the x509 structure
  ScopedX509Ctx x509(X509_new());
  int version = 2;  // self sign uses version=2 (which is x509v3)
  int serial = 1;   // self sign can always use serial 1
  PrepareX509(x509.get(), version, serial, pem_key.get());

  // set up the subject and issuer details to be the same
  X509_NAME *subject = X509_get_subject_name(x509.get());
  SetX509NameDetails(subject, country, org, state, cn);

  X509_NAME *issuer = X509_get_issuer_name(x509.get());
  SetX509NameDetails(issuer, country, org, state, cn);

  AddX509Extension(x509.get(), NID_basic_constraints, "critical,CA:TRUE");
  AddX509Extension(x509.get(), NID_subject_key_identifier, "hash");
  AddX509Extension(x509.get(), NID_authority_key_identifier, "keyid:always");

  X509_sign(x509.get(), pem_key.get(), EVP_sha1());
  if (!OpenSSLSuccess()) {
    LOG(ERROR) << "Could not perform self-signing on the X.509 cert";
    return false;
  }

  return WriteX509File(x509.get(), public_cert_path);
}
}  // namespace tao
