//
// Copyright 2016, Google Corporation , All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// or in the the file LICENSE-2.0.txt in the top level sourcedirectory
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License
// Project: New Cloudproxy Crypto
// File: client_test.cc

#include "gtest/gtest.h"

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include <string>

#include "helpers.h"


int main(int an, char** av) {
  SslChannel channel;
  string path;

  string key_path("/Domains/test_keys");
  string ca_cert_string;
  string client_cert_string;
  string server_cert_string;
  string ca_key_string;
  string client_key_string;
  string server_key_string;
  string ca_key_type;
  string server_key_type;
  string client_key_type;

  // CA
  string ca_cert_file_name = key_path + "/ca_cert";
  string ca_key_file_name = key_path + "/ca_key";
  if(!ReadFile(ca_cert_file_name, &ca_cert_string)) {
    printf("can't read ca_cert.\n");
    return 1;
  }
  if(!ReadFile(ca_key_file_name, &ca_key_string)) {
    printf("can't read ca key.\n");
    return 1;
  }
  byte* ca_ptr = (byte*)ca_cert_string.data();
  X509* ca_cert = d2i_X509(nullptr, (const byte**)&ca_ptr,
        ca_cert_string.size());

  // client cert and keys
  string client_cert_file_name = key_path + "/client_cert";
  string client_key_file_name = key_path + "/client_key";
  if(!ReadFile(client_cert_file_name, &client_cert_string)) {
    printf("can't read client_cert.\n");
    return 1;
  }
  if(!ReadFile(client_key_file_name, &client_key_string)) {
    printf("Can't read client key.\n");
    return 1;
  }
  byte* client_ptr = (byte*)client_cert_string.data();
  X509* client_cert = d2i_X509(nullptr, (const byte**)&client_ptr,
        client_cert_string.size());
  if (client_cert == nullptr) {
    printf("client_cert doesnt translate.\n");
    return 1;
  }

  EVP_PKEY* client_key = nullptr;

  if (!DeserializePrivateKey(client_key_string, &client_key_type, &client_key)) {
    printf("Can't deserialize client key\n");
    return 1;
  }

  string network("tcp");
  string address("127.0.0.1");
  string port("2015");
  string key_type;

  printf("Calling InitClientSslChannel\n");
  if (!channel.InitClientSslChannel(network, address, port, ca_cert,
                                    client_cert, key_type, client_key, true)) {
    printf("Can't InitClientSslChannel\n");
    return 1;
  }

  int size_send_buf = 4096;
  byte send_buf[4096];
  int size_get_buf = 4096;
  byte get_buf[4096];
  int msg_num = 1;

  // write/read
  printf("Client transcript\n\n");
  sprintf((char*)send_buf, "Client message %d\n", msg_num++);
  size_send_buf = channel.Write(strlen((const char*)send_buf) + 1, send_buf);
  size_get_buf = channel.Read(4096, get_buf);
  printf("server reply %d, %s\n", size_get_buf, (const char*)get_buf);
  sprintf((char*)send_buf, "Client message %d\n", msg_num++);
  size_send_buf = channel.Write(strlen((const char*)send_buf) + 1, send_buf);
  size_get_buf = channel.Read(4096, get_buf);
  printf("server reply %d, %s\n", size_get_buf, (const char*)get_buf);

  return 0;
}

