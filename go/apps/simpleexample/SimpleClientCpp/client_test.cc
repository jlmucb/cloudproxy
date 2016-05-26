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
// File: support_test.cc

#include "gtest/gtest.h"

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include <string>

#include "helpers.h"


#if 0
// for testing
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
void FakeClient(string& network, string& address, string& port) {
  int sockfd = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in dest_addr;
  uint16_t s_port = atoi(port.c_str());
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(s_port);
  inet_aton(address.c_str(), &dest_addr.sin_addr);

  if (connect(sockfd, (struct sockaddr *) &dest_addr,
              sizeof(struct sockaddr)) == -1) {
    printf("Error: Cannot connect to host\n");
    return;
  }

  byte request[4096];
  byte reply[4096];
  const char* r = "this is a request\n";
  memcpy(request, (byte*)r, strlen(r) + 1);

  printf("Client sending %s\n", (const char*)request);
  if (write(sockfd, request, strlen(r) + 1) <= 0) {
    printf("client write failed\n");
  }
  if (read(sockfd, reply, 4096) <= 0) {
    printf("client read failed\n");
  }
  printf("client received: %s\n", (const char*)reply);
}
#endif


int main(int an, char** av) {
  SslChannel channel;
  string path;
  string policy_cert_file_name;
  string policy_cert;
  string network("tcp");
  string address("127.0.0.1");
  string port("2015");

#if 0
  // Read and parse policy cert.
  if (!ReadFile(policy_cert, &policy_cert)) {
    printf("Can't read policy cert.\n");
    return 1;
  }
  byte* pc = (byte*)policy_cert.data();
  X509* policyCertificate = d2i_X509(nullptr, (const byte**)&pc,
        policy_cert.size());
  if (policyCertificate == nullptr) {
    printf("Policy certificate is null.\n");
    return 1;
  }
#endif

  // Self signed cert.
  X509_REQ* req = X509_REQ_new();;
  X509* cert = X509_new();
  string key_type("ECC");
  int key_size = 256;
  string common_name("Fred");
  string issuer("Fred");
  string purpose("signing");

  EVP_PKEY* self = GenerateKey(key_type, key_size);
  if (!GenerateX509CertificateRequest(key_type, common_name, self, false, req)) {
    printf("Can't generate x509 request\n");
    return 1;
  }
  if (!SignX509Certificate(self, true, true, issuer, purpose, 86400,
                         self, req, false, cert)) {
    printf("Can't sign x509 request\n");
    return 1;
  }

#if 0
  if (!channel.InitClientSslChannel(network, address, port, policyCertificate,
                                    cert, key_type, self, false)) {
#else
  printf("Calling InitClientSslChannel\n");
  if (!channel.InitClientSslChannel(network, address, port, cert,
                                    cert, key_type, self, false)) {
#endif
    printf("Can't InitClientSslChannel\n");
    return 1;
  }

  int size_send_buf = 4096;
  byte send_buf[4096];
  int size_get_buf = 4096;
  byte get_buf[4096];
  int msg_num = 1;

  // write/read
  printf("Client read/write\n");
  sprintf((char*)send_buf, "Client message %d\n", msg_num++);
  size_send_buf = channel.Write(strlen((const char*)send_buf) + 1, send_buf);
  size_get_buf = channel.Read(4096, get_buf);
  sprintf((char*)send_buf, "Client message %d\n", msg_num++);
  size_send_buf = channel.Write(strlen((const char*)send_buf) + 1, send_buf);
  size_get_buf = channel.Read(4096, get_buf);

  return 0;
}

