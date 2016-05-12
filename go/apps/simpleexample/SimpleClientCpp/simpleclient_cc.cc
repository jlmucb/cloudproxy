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

int main(int argc, char **argv) {
  InitializeApp(&argc, &argv, false);

  // This code expects fd 3 and 4 to be the pipes from and to the Tao, so it
  // doesn't need to take any parameters. It will establish a Tao Child Channel
  // directly with these fds.
  unique_ptr<FDMessageChannel> msg(new FDMessageChannel(3, 4));
  unique_ptr<Tao> tao(new TaoRPC(msg.release()));
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
  return 0;
}
