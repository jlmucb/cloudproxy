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

#if 0
// For testing.

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
void FakeServer(string& network, string& address, string& port) {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in dest_addr;
  uint16_t s_port = atoi(port.c_str());
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(s_port);
  inet_aton(address.c_str(), &dest_addr.sin_addr);

  if (bind(sockfd, (struct sockaddr*)&dest_addr, sizeof(dest_addr)) < 0) {
    printf("Unable to bind\n");
    return;
  }

  if (listen(sockfd, 1) < 0) {
    printf("Unable to listen\n");
    return;
  }

  byte request[4096];
  byte reply[4096];

  struct sockaddr_in addr;
  uint len = sizeof(addr);

  int client = accept(sockfd, (struct sockaddr*)&addr, &len);
  if (client < 0) {
    printf("Unable to accept\n");
  }
  for(;;) {
    int in_size = read(client, request, 4096);
    if (in_size <= 0) {
      printf("server read failed\n");
      return;
    }
    printf("Server received: %s\n", (const char*)request);
    const char* r = "This is a stupid reply";
    memcpy(reply, r, strlen(r) + 1);
    printf("Server sending: %s\n", (const char*)reply);
    write(client, reply, strlen(r) + 1);
    break;
  }
}
#endif

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

DEFINE_string(key_type, "ECC", "key type for generated keys");

int main(int an, char** av) {
  SslChannel channel;
  string path;
  string policy_cert_file_name(
      "/Domains/domain.simpleexample/policy_keys/cert");
  string policy_cert;
  string network("tcp");
  string address("127.0.0.1");
  string port("2015");

  google::ParseCommandLineFlags(&an, &av, true);

  // key type
  string key_type;
  int key_size;
  if(FLAGS_key_type == "ECC") {
    key_type = "ECC";
    key_size = 256;
  } else if (FLAGS_key_type == "RSA") {
    key_type = "RSA";
    key_size = 2048;
  } else {
    printf("Invalid key type\n");
    return 1;
  }
  printf("Key type is %s\n", key_type.c_str()); 

  // Self signed cert.
  X509_REQ* req = X509_REQ_new();;
  X509* cert = X509_new();
  string common_name("Fred");
  string issuer("Fred");
  string keyUsage("critical,digitalSignature,keyEncipherment,keyAgreement,keyCertSign");
  string extendedKeyUsage("serverAuth,clientAuth");

  EVP_PKEY* self = GenerateKey(key_type, key_size);
  if (!GenerateX509CertificateRequest(key_type, common_name, self,
          false, req)) {
    printf("Can't generate x509 request\n");
    return 1;
  }

  // EC_KEY_METHOD* meth = EC_KEY_get_method(EVP_PKEY_get1_EC_KEY(self));

  if (!SignX509Certificate(self, true, true, issuer, keyUsage,
                           extendedKeyUsage, 86400,
                           self, req, false, cert)) {
    printf("Can't sign x509 request\n");
    return 1;
  }

  printf("Calling InitServerSslChannel\n");
  if (!channel.InitServerSslChannel(network, address, port, cert,
                                    cert, key_type, self,
                                    SSL_NO_SERVER_VERIFY_NO_CLIENT_AUTH)) {
    printf("Can't InitServerSslChannel\n");
    return 1;
  }
  printf("Calling ServerLoop\n\n");
  channel.ServerLoop(&HandleConnection);
  return 0;
}

