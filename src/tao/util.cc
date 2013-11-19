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

#include <fstream>
#include <sstream>

#include <keyczar/base/json_reader.h>
#include <keyczar/base/json_writer.h>
#include <keyczar/base/file_util.h>
#include <keyczar/rw/keyset_writer.h>
#include <keyczar/rw/keyset_file_writer.h>
#include <keyczar/rw/keyset_file_reader.h>

using keyczar::Crypter;
using keyczar::Keyczar;
using keyczar::KeyPurpose;
using keyczar::KeyType;
using keyczar::Keyset;
using keyczar::KeysetMetadata;
using keyczar::KeyStatus;
using keyczar::Signer;
using keyczar::base::PathExists;
using keyczar::base::ScopedSafeString;
using keyczar::rw::KeysetJSONFileReader;
using keyczar::rw::KeysetJSONFileWriter;
using keyczar::rw::KeysetReader;
using keyczar::rw::KeysetWriter;

using std::ifstream;
using std::ios;
using std::ofstream;
using std::stringstream;

namespace tao {
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
}  // namespace tao
