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
// File: simple_server_test.cc

#include "gtest/gtest.h"

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include <string>

#include "helpers.h"

bool ProcessRequest (int request_number, int request_size, byte* request,
                     int* reply_size, byte* reply) {
  printf("\nProcessRequest %s\n", (const char*)request);
  memset(reply, 0, *reply_size);
  sprintf((char*)reply, "This is a stupid reply %d\n", request_number);
  *reply_size = strlen((const char*)reply) + 1;
  if (request_number > 2)
    return false;
  return true;
}

void HandleConnection(SslChannel* channel,  SSL* ssl, int client) {
  byte request[4096];
  int request_size = 0;
  byte reply[4096];
  int reply_size;
  bool fContinue;
  int request_number = 0;

  printf("\nHandleConnection\n");
  for (;;) {
    memset(request, 0, 4096);
    request_size = SSL_read(ssl, request, 4096);
    printf("request %d: %s\n", request_size, (const char*)request);

    reply_size = 4096;
    fContinue = ProcessRequest(request_number++, request_size, request,
                     &reply_size, reply);
    SSL_write(ssl, reply, reply_size);
    if (!fContinue)
      break;
  }
  // SSL_free(ssl);
  // close(client);
}

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

  // server cert and keys
  string server_cert_file_name = key_path + "/server_cert";
  string server_key_file_name = key_path + "/server_key";
  if(!ReadFile(server_cert_file_name, &server_cert_string)) {
    printf("can't read server_cert.\n");
    return 1;
  }
  if(!ReadFile(server_key_file_name, &server_key_string)) {
    printf("Can't read server key.\n");
    return 1;
  }
  byte* server_ptr = (byte*)server_cert_string.data();
  X509* server_cert = d2i_X509(nullptr, (const byte**)&server_ptr,
        server_cert_string.size());
  if (server_cert == nullptr) {
    printf("server_cert doesnt translate.\n");
    return 1;
  }

  EVP_PKEY* server_key = nullptr;

  if (!DeserializePrivateKey(server_key_string, &server_key_type, &server_key)) {
    printf("Can't deserialize server key\n");
    return 1;
  }

  string network("tcp");
  string address("127.0.0.1");
  string port("2015");

  printf("Calling InitServerSslChannel %s key\n", server_key_type.c_str());
  if (!channel.InitServerSslChannel(network, address, port, ca_cert,
                                    server_cert, server_key_type, server_key, false)) {
    printf("Can't InitServerSslChannel\n");
    return 1;
  }
  printf("Calling ServerLoop\n\n");
  channel.ServerLoop(&HandleConnection);
  return 0;
}

