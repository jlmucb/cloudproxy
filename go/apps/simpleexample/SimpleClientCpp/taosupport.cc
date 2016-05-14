//  Copyright (c) 2014, Google Inc.  All rights reserved.
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
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "tao/fd_message_channel.h"
#include "tao/tao_rpc.h"
#include "tao/util.h"

using std::string;
using std::unique_ptr;

using tao::Base64WDecode;
using tao::Base64WEncode;
using tao::FDMessageChannel;
using tao::InitializeApp;
using tao::MarshalSpeaksfor;
using tao::Tao;
using tao::TaoRPC;

#include "helpers.h"
#include "taosupport.h"
#include <taosupport.pb.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

void PrintBytes(int n, byte* in) {
  for (int i = 0; i < n; i++) printf("%02x", in[i]);
}

TaoChannel::TaoChannel() {
  fd_ = 0;
}

TaoChannel::~TaoChannel() {
  fd_ = 0;
}

bool TaoChannel::OpenTaoChannel(TaoProgramData& client_program_data,
                    string& serverAddress) {

  // Parse policy cert and make it root of chain.

  // Open TLS channel with Program cert.

  // Get peer name from organizational unit.

  return false;
}

void TaoChannel::CloseTaoChannel() {
  if (fd_ > 0)
    close(fd_);
  fd_ = 0;
}

bool TaoChannel::SendRequest(taosupport::SimpleMessage& out) {
  return false;
}

bool TaoChannel::GetRequest(taosupport::SimpleMessage* in) {
  return false;
}

TaoProgramData::TaoProgramData() {
  initialized_ = false;
}

TaoProgramData::~TaoProgramData() {
  ClearProgramData();
}

void TaoProgramData::ClearProgramData() {
  initialized_ = false;
  tao_name_.clear();
  free(policy_cert_);
  size_policy_cert_ = 0;

  // clear private key

  memset(program_sym_key_, 0, size_program_sym_key_);
  free(program_sym_key_);
  size_program_sym_key_ = 0;
  free(policy_cert_);
  size_policy_cert_ = 0;
  program_file_path_.clear();
}

bool TaoProgramData::InitTao(FDMessageChannel* msg, Tao* tao, string& cfg, string& path) {

  // Load domain

  // Get policy cert.

  // Extend principal name, hash of policy cert identifies policy extension.

  // Retrieve extended name.
  if (!tao->GetTaoName(&tao_name_)) {
    return false;
  }

  // Get (or initialize) my symmetric keys.
  if (!InitializeSymmetricKeys(path, 32)) {
    return false;
  }

  // Get (or initialize) my program key.
  if (!InitializeProgramKey(path, 2048)) {
    return false;
  }
  return true;
}

void TaoProgramData::Print() {
  if (!initialized_) {
    printf("Program object is NOT initialized\n");
    return;
  }
  printf("Program object is NOT initialized\n");
  printf("Tao name: %s\n", tao_name_.c_str());
  printf("Policy cert: ");PrintBytes(size_policy_cert_, policy_cert_);printf("\n");
  printf("Program key: "); printf("TODO"); printf("\n");
  printf("Sym key: ");PrintBytes(size_program_sym_key_, program_sym_key_);printf("\n");
  printf("Program cert: ");PrintBytes(size_program_cert_, program_cert_);printf("\n");
  printf("Program path: %s\n", program_file_path_.c_str());
}

void TaoChannel::Print() {
  printf("fd: %d\n", fd_);
  printf("Server name: %s\n", server_name_.c_str());
}

bool TaoProgramData::Attest(string& to_attest, string* attested) {
  return tao_->Attest(to_attest, attested);
}

bool TaoProgramData::Seal(string& to_seal, string* sealed) {
  // string encodedBytes;
  // if (!Base64WEncode(to_seal, &encodedBytes)) { }
  return tao_->Seal(to_seal, Tao::SealPolicyDefault, sealed);
}

bool TaoProgramData::Unseal(string& sealed, string* unsealed) {
  string policy;
  return tao_->Unseal(sealed, unsealed, &policy);
  //if (unsealed->compare(bytes) != 0) { }
}

bool TaoProgramData::RequestDomainServiceCert(string& network, string& address, RSA* myKey,
                              RSA* verifyKey, int* size_cert, byte* cert) {
  return true;
}

bool TaoProgramData::InitializeSymmetricKeys(string& path, int keysize) {
  return true;
}

bool TaoProgramData::InitializeProgramKey(string& path, int keysize) {
/*
  string taoName;
  if (!MarshalSpeaksfor(fakeKey, taoName, &msf)) {
    return false;
  }
 */
  // RSA* program_key_ = RSA_new();
  return true;
}

