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

include "taosupport.h"
#include <taosupport.pb.h>

void PrintBytes(int n, byte* in) {
  for (int i = 0; i < n; i++) printf("%02x", in[i]);
}

TaoChannel::TaoChannel() {
  fd_ = 0;
}

TaoChannel::~TaoChannel() {
  fd_ = 0;
}

bool TaoChannel::OpenTaoChannel(FDMessageChannel& msg, Tao& tao,
       TaoProgramData& client_program_data, string& serverAddress) {
  return false;
}

void TaoChannel::CloseTaoChannel() {
  if (fd_ > 0)
    close(fd_);
  fd_ = 0;
}

bool TaoChannel::SendRequest(SimpleMessage& out) {
  return false;
}

bool TaoChannel::GetRequest(SimpleMessage* in) {
  return false;
}

TaoProgramData::TaoProgramData() {
  initialized_ = false;
}

TaoProgramData::~TaoProgramData() {
  ClearProgramData();
}

TaoProgramData::ClearProgramData() {
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

bool TaoProgramData::InitTao(FDMessageChannel& msg, Tao& tao, string&, string&) {
  return false;
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

/*

  string bytes;
  if (!tao->GetRandomBytes(10, &bytes)) {
    LOG(FATAL) << "Couldn't get 10 bytes from the Tao RPC channel";
  }

  if (bytes.size() == 10) {
    LOG(INFO) << "Got 10 bytes from the Tao RPC channel";
  } else {
    LOG(FATAL) << "Got " << bytes.size() << " bytes from the channel, but "
                                            "expected 10";
  }

  string encodedBytes;
  if (!Base64WEncode(bytes, &encodedBytes)) {
    LOG(FATAL) << "Couldn't encode 10 bytes in Base64W";
  }
  LOG(INFO) << "Encoded bytes: " << encodedBytes;

  string sealed;
  if (!tao->Seal(bytes, Tao::SealPolicyDefault, &sealed)) {
    LOG(FATAL) << "Couldn't seal bytes across the channel";
  }

  string encodedSealed;
  if (!Base64WEncode(sealed, &encodedSealed)) {
    LOG(FATAL) << "Couldn't encode the sealed bytes";
  }
  LOG(INFO) << "Encoded sealed bytes: " << encodedSealed;

  string unsealed;
  string policy;
  if (!tao->Unseal(sealed, &unsealed, &policy)) {
    LOG(FATAL) << "Couldn't unseal the tao-sealed data";
  }
  LOG(INFO) << "Got a seal policy '" << policy << "'";

  if (policy.compare(Tao::SealPolicyDefault) != 0) {
    LOG(FATAL) << "The policy returned by Unseal didn't match the Seal policy";
  }

  if (unsealed.compare(bytes) != 0) {
    LOG(FATAL) << "The unsealed data didn't match the sealed data";
  }

  string encodedUnsealed;
  if (!Base64WEncode(unsealed, &encodedUnsealed)) {
    LOG(FATAL) << "Couldn't encoded the unsealed bytes";
  }

  LOG(INFO) << "Encoded unsealed bytes: " << encodedUnsealed;

  // Set up a fake attestation using a fake key.
  string taoName;
  if (!tao->GetTaoName(&taoName)) {
    LOG(FATAL) << "Couldn't get the name of the Tao";
  }

  string fakeKey("This is a fake key");
  string msf;
  if (!MarshalSpeaksfor(fakeKey, taoName, &msf)) {
    LOG(FATAL) << "Couldn't marshal a speaksfor statement";
  }

  string attest;
  if (!tao->Attest(msf, &attest)) {
    LOG(FATAL) << "Couldn't attest to a fake key delegation";
  }

  string encodedAttest;
  if (!Base64WEncode(attest, &encodedAttest)) {
    LOG(FATAL) << "Couldn't encode the attestation";
  }

  LOG(INFO) << "Got attestation " << encodedAttest;

  LOG(INFO) << "All Go Tao tests pass";
 */
