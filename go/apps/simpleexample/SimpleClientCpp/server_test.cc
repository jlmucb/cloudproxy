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
// File: server_test.cc

#include "gtest/gtest.h"

#include <gtest/gtest.h>
#include <gflags/gflags.h>
#include <stdio.h>
#include <string>

#include "helpers.h"


int main(int an, char** av) {
  SslChannel channel;
  string path;
  string policy_cert_file_name;
  string policy_cert;
  string network;
  string address;
  string port;

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

  // Self signed cert.
  X509* tmpChannelCert = nullptr;
  X509_REQ* req = X509_REQ_new();;
  X509* cert = X509_new();
  EVP_PKEY* self = new EVP_PKEY();
  string key_type("ECC");
  string common_name("Fred");
  string issuer("Self");
  string purpose("signing");

#if 0
  EVP_PKEY* self = GenerateKey(string& keyType, int keySize)
  if (!GenerateX509CertificateRequest(key_type, common_name, self, false, req)) {
    printf("Can't generate x509 request\n");
    return 1;
  }
  if (!SignX509Certificate(tmpChannelKey, true, true, issuer, purpose, 86400,
                         self, req, false, cert)) {
    printf("Can't sign x509 request\n");
    return 1;
  }
#endif

  if (!channel.InitServerSslChannel(network, address, port, policyCertificate,
                                    cert, keyType, key, false)) {
    printf("Can't InitServerSslChannel\n");
    return 1;
  }
  channel.ServerLoop();
  return 0;
}

