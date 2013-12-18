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

#ifndef TAO_UTIL_TAO_H_
#define TAO_UTIL_TAO_H_

#include <glog/logging.h>
#include <keyczar/keyczar.h>
#include <keyczar/openssl/util.h>
#include <openssl/x509.h>

#include "tao/keyczar_public_key.pb.h"
#include "tao/tao.h"
#include "tao/tao_child_channel.h"
#include "tao/tao_child_channel_registry.h"

int remove_entry(const char *path, const struct stat *sb,
                 int tflag, struct FTW *ftwbuf);
namespace tao {

typedef scoped_ptr_malloc<RSA, keyczar::openssl::OSSLDestroyer<RSA, RSA_free> >
    ScopedRsa;

bool HashVM(const string &vm_template, const string &name,
            const string &kernel, const string &initrd, string *hash);

bool RegisterKnownChannels(TaoChildChannelRegistry *registry);

bool InitializeOpenSSL();

bool OpenTCPSocket(short port, int *sock);

bool CreateKey(keyczar::rw::KeysetWriter *writer,
               keyczar::KeyType::Type key_type,
               keyczar::KeyPurpose::Type key_purpose, const string &key_name,
               scoped_ptr<keyczar::Keyczar> *key);

bool DeserializePublicKey(const KeyczarPublicKey &kpk,
                          keyczar::Keyset **keyset);
bool SerializePublicKey(const keyczar::Keyczar &key, KeyczarPublicKey *kpk);

bool SignData(const string &data, string *signature, keyczar::Keyczar *key);

bool VerifySignature(const string &data, const string &signature,
                     keyczar::Keyczar *key);

bool CopyPublicKeyset(const keyczar::Keyczar &public_key,
                      keyczar::Keyset **keyset);

bool SealOrUnsealSecret(const TaoChildChannel &t, const string &sealed_path,
                        string *secret);

bool ReceiveMessage(int fd, google::protobuf::Message *m);

bool SendMessage(int fd, const google::protobuf::Message &m);

}  // namespace tao

#endif  // TAO_UTIL_TAO_H_
