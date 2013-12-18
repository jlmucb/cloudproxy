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
#include <ftw.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <vector>

#include <keyczar/base/base64w.h>
#include <keyczar/base/json_reader.h>
#include <keyczar/base/json_writer.h>
#include <keyczar/base/file_util.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/rw/keyset_file_writer.h>
#include <keyczar/rw/keyset_file_reader.h>
#include <keyczar/rw/keyset_writer.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include "tao/pipe_tao_child_channel.h"
#include "tao/kvm_unix_tao_child_channel.h"

using keyczar::base::Base64WEncode;
using keyczar::Crypter;
using keyczar::CryptoFactory;
using keyczar::Keyczar;
using keyczar::KeyPurpose;
using keyczar::KeyType;
using keyczar::Keyset;
using keyczar::KeysetMetadata;
using keyczar::KeyStatus;
using keyczar::MessageDigestImpl;
using keyczar::Signer;
using keyczar::base::PathExists;
using keyczar::base::ScopedSafeString;
using keyczar::rw::KeysetJSONFileReader;
using keyczar::rw::KeysetJSONFileWriter;
using keyczar::rw::KeysetReader;
using keyczar::rw::KeysetWriter;

using std::ifstream;
using std::ios;
using std::mutex;
using std::ofstream;
using std::shared_ptr;
using std::stringstream;
using std::vector;

int remove_entry(const char *path, const struct stat *sb,
                 int tflag, struct FTW *ftwbuf) {
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
vector<shared_ptr<mutex> > locks;

void locking_function(int mode, int n, const char *file, int line) {
  if (mode & CRYPTO_LOCK) {
    locks[n]->lock();
  } else {
    locks[n]->unlock();
  }
}

bool HashVM(const string &vm_template, const string &name,
	    const string &kernel_file, const string &initrd_file,
	    string *hash) {
  // TODO(tmroeder): take in the right hash type and use it here. For
  // now, we just assume that it's SHA256
  MessageDigestImpl *sha256 = CryptoFactory::SHA256();

  string template_hash;
  if (!sha256->Digest(vm_template, &template_hash)) {
    LOG(ERROR) << "Could not compute the hash of the template";
    return false;
  }

  string template_digest;
  if (!Base64WEncode(template_hash, &template_digest)) {
    LOG(ERROR) << "Could not encode the template digest";
    return false;
  }

  LOG(INFO) << "The template had hash: " << template_digest;

  string name_hash;
  if (!sha256->Digest(name, &name_hash)) {
    LOG(ERROR) << "Could not compute the has of the name";
    return false;
  }

  string kernel_hash;
  if (!sha256->Digest(kernel_file, &kernel_hash)) {
    LOG(ERROR) << "Could not compute the hash of the kernel";
    return false;
  }

  string initrd_hash;
  if (!sha256->Digest(initrd_file, &initrd_hash)) {
    LOG(ERROR) << "Could not compute the hash of initrd";
    return false;
  }

  // Concatenate the hashes
  string hash_input;
  hash_input.append(template_hash);
  hash_input.append(name_hash);
  hash_input.append(kernel_hash);
  hash_input.append(initrd_hash);

  string composite_hash;
  if (!sha256->Digest(hash_input, &composite_hash)) {
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

bool OpenTCPSocket(short port, int *sock) {
  if (sock == NULL) {
    LOG(ERROR) << "null socket parameter";
    return false;
  }

  *sock = socket(AF_INET, SOCK_STREAM, 0);
  if (*sock == -1) {
    PLOG(ERROR) << "Could not create a socket for tcca to listen on";
    return false;
  }

  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(struct sockaddr_in));
  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_ANY);
  addr.sin_port = htons(port);

  int bind_err =
      bind(*sock, (struct sockaddr *)&addr, sizeof(struct sockaddr_in));
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


bool CreateKey(KeysetWriter *writer, KeyType::Type key_type,
               KeyPurpose::Type key_purpose, const string &key_name,
               scoped_ptr<Keyczar> *key) {
  CHECK_NOTNULL(writer);
  CHECK_NOTNULL(key);

  scoped_ptr<Keyset> k(new Keyset());
  k->AddObserver(writer);
  k->set_encrypted(true);

  KeysetMetadata *metadata = nullptr;
  metadata = new KeysetMetadata(key_name, key_type, key_purpose, true, 1);
  CHECK_NOTNULL(metadata);
  k->set_metadata(metadata);
  k->GenerateDefaultKeySize(KeyStatus::PRIMARY);

  switch (key_purpose) {
    case KeyPurpose::SIGN_AND_VERIFY:
      key->reset(new Signer(k.release()));
      break;
    case KeyPurpose::DECRYPT_AND_ENCRYPT:
      key->reset(new Crypter(k.release()));
      break;
    default:
      LOG(ERROR) << "Unsupported key type " << key_purpose;
      return false;
  }

  return true;
}

bool DeserializePublicKey(const KeyczarPublicKey &kpk, Keyset **keyset) {
  if (keyset == nullptr) {
    LOG(ERROR) << "null keyset";
    return false;
  }

  char tempdir[] = "/tmp/public_key_XXXXXX";
  if (mkdtemp(tempdir) == nullptr) {
    LOG(ERROR) << "Could not create a temp directory for public key export";
    return false;
  }

  string destination(tempdir);

  // write the files to the temp directory and make sure they close
  {
    // write the metadata
    string metadata_file_name = destination + string("/meta");
    ofstream meta_file(metadata_file_name.c_str(), ofstream::out | ios::binary);
    meta_file.write(kpk.metadata().data(), kpk.metadata().size());

    // iterate over the public keys and write each one to disk
    int key_count = kpk.files_size();
    for (int i = 0; i < key_count; i++) {
      const KeyczarPublicKey::KeyFile &kf = kpk.files(i);
      stringstream ss;
      ss << destination << "/" << kf.name();
      ofstream file(ss.str().c_str(), ofstream::out | ios::binary);
      file.write(kf.data().data(), kf.data().size());
    }
  }

  // read the data from the directory
  scoped_ptr<KeysetReader> reader(new KeysetJSONFileReader(destination));
  if (reader.get() == NULL) {
    return false;
  }

  *keyset = Keyset::Read(*reader, true);

  // clean up the directory
  if (nftw(tempdir, remove_entry, 10 /* nopenfd */, FTW_DEPTH) < 0) {
    PLOG(ERROR) << "Could not remove the directory";
    return false;
  }

  return true;
}

bool SerializePublicKey(const Keyczar &key, KeyczarPublicKey *kpk) {
  char tempdir[] = "/tmp/public_key_XXXXXX";
  if (kpk == nullptr) {
    LOG(ERROR) << "Could not serialize to a null public key structure";
    return false;
  }

  if (mkdtemp(tempdir) == nullptr) {
    LOG(ERROR) << "Could not create a temp directory for public key export";
    return false;
  }

  string destination(tempdir);

  scoped_ptr<KeysetWriter> writer(new KeysetJSONFileWriter(destination));
  if (writer.get() == NULL) {
    return false;
  }

  const Keyset *keyset = key.keyset();
  if (!keyset->PublicKeyExport(*writer)) {
    LOG(ERROR) << "Could not export the public key";
    return false;
  }

  LOG(INFO) << "Exported the public key to " << destination;

  // now iterate over the files in the directory and add them to the public key
  string meta_file_name = destination + string("/meta");
  ifstream meta_file(meta_file_name.c_str(), ifstream::in | ios::binary);
  stringstream meta_stream;
  meta_stream << meta_file.rdbuf();
  kpk->set_metadata(meta_stream.str());

  KeysetMetadata::const_iterator version_iterator = keyset->metadata()->Begin();
  for (; version_iterator != keyset->metadata()->End(); ++version_iterator) {
    int v = version_iterator->first;
    stringstream file_name_stream;
    file_name_stream << destination << "/" << v;
    ifstream file(file_name_stream.str().c_str(), ifstream::in | ios::binary);
    stringstream file_buf;
    file_buf << file.rdbuf();

    KeyczarPublicKey::KeyFile *kf = kpk->add_files();
    kf->set_name(v);
    kf->set_data(file_buf.str());
  }

  // clean up the directory
  if (nftw(tempdir, remove_entry, 10 /* nopenfd */, FTW_DEPTH) < 0) {
    PLOG(ERROR) << "Could not remove the directory";
    return false;
  }


  return true;
}

bool SignData(const string &data, string *signature, Keyczar *key) {
  if (!key->Sign(data, signature)) {
    LOG(ERROR) << "Could not sign the data";
    return false;
  }

  return true;
}

bool VerifySignature(const string &data, const string &signature,
                     keyczar::Keyczar *key) {
  if (!key->Verify(data, signature)) {
    LOG(ERROR) << "Verify failed";
    return false;
  }

  return true;
}

bool CopyPublicKeyset(const keyczar::Keyczar &public_key,
                      keyczar::Keyset **keyset) {
  CHECK(keyset) << "null keyset";

  KeyczarPublicKey kpk;
  if (!SerializePublicKey(public_key, &kpk)) {
    LOG(ERROR) << "Could not serialize the public key";
    return false;
  }

  if (!DeserializePublicKey(kpk, keyset)) {
    LOG(ERROR) << "Could not deserialize the public key";
    return false;
  }

  return true;
}

bool SealOrUnsealSecret(const TaoChildChannel &t, const string &sealed_path,
                        string *secret) {
  LOG(INFO) << "In SealOrUnsealSecret, with path " << sealed_path;
  // create or unseal a secret from the Tao
  FilePath fp(sealed_path);
  if (PathExists(fp)) {
    LOG(INFO) << "Found the path";
    // Unseal it
    ifstream sealed_file(sealed_path.c_str(), ifstream::in | ios::binary);
    stringstream sealed_buf;
    sealed_buf << sealed_file.rdbuf();

    if (!t.Unseal(sealed_buf.str(), secret)) {
      LOG(ERROR) << "Could not unseal the secret from " << sealed_path;
      return false;
    }

  } else {
    LOG(INFO) << "Didn't find the path";
    // create and seal the secret
    const int SecretSize = 16;
    if (!t.GetRandomBytes(SecretSize, secret)) {
      LOG(ERROR) << "Could not get a random secret from the Tao";
      return false;
    }

    LOG(INFO) << "Got random bytes";
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

bool ReceiveMessage(int fd, google::protobuf::Message *m) {
  if (m == NULL) {
    LOG(ERROR) << "null message";
    return false;
  }

  // Loop in case the channel underlying the fd doesn't guarantee that all bytes
  // are delivered at once (I'm looking at you, AF_UNIX/SOCK_STREAM).
  size_t len = 0;
  ssize_t bytes_read = 0;
  while(static_cast<size_t>(bytes_read) < sizeof(size_t)) {
    int rv = read(fd, ((char *)&len) + bytes_read,
        sizeof(size_t) - bytes_read);

    if (rv < 0) {
      if ((rv == EAGAIN) || (rv == EWOULDBLOCK)) {
        LOG(WARNING) << "Got an EAGAIN or EWOULDBLOCK";
        continue;
      } else {
        PLOG(ERROR) << "Could not receive a size on the channel";
        return false;
      }
    }

    bytes_read += rv;
  }

  LOG(INFO) << "Got a length " << (int)len;

  // then read this many bytes as the message
  scoped_array<char> bytes(new char[len]);
  bytes_read = 0;
  while(static_cast<size_t>(bytes_read) < len) {
    int rv = read(fd, bytes.get() + bytes_read, len - bytes_read);

    // TODO(tmroeder): add safe integer library
    if (rv < 0) {
      if ((rv == EAGAIN) || (rv == EWOULDBLOCK)) {
        LOG(WARNING) << "Got an EAGAIN or EWOULDBLOCK";
        continue;
      } else {
        PLOG(ERROR) << "Could not read the right number of bytes from the fd";
        return false;
      }
    }

    bytes_read += rv;
  }

  LOG(INFO) << "Received a message of length " << len;
  string serialized(bytes.get(), len);
  return m->ParseFromString(serialized);

}
}  // namespace tao
