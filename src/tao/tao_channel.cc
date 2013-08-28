//  File: tao_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: High-level implementation of Tao communication that
//  can function over any subclass that implements the pure virtual
//  functions in TaoChannel
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



#include <tao/tao_channel.h>
#include <glog/logging.h>

namespace tao {

bool TaoChannel::Listen(Tao *t) const {
  TaoChannelRPC rpc;
  while (GetRPC(&rpc)) {
    // switch on the type of RPC and pass it to the tao function
    TaoChannelResponse resp;
    resp.set_rpc(rpc.rpc());

    string result_data;
    bool result = false;
    GetRandomBytesArgs *grba = nullptr;
    switch (rpc.rpc()) {
      case INIT:
        result = t->Init();
        break;
      case DESTROY:
        result = t->Destroy();
        break;
      case START_HOSTED_PROGRAM:
        // TODO(tmroeder): unpack the arguments and set this up
        break;
      case GET_RANDOM_BYTES:
        if (!rpc.has_random()) {
          LOG(ERROR) << "Invalid RPC: must supply arguments for GetRandomBytes";
          break;
        }

        grba = rpc.mutable_random();
        result = t->GetRandomBytes(grba->size(), &result_data);
        resp.set_data(result_data);
        break;
      case SEAL:
        if (!rpc.has_data()) {
          LOG(ERROR) << "Invalid RPC: must supply data for Seal";
          break;
        }

        result = t->Seal(rpc.data(), &result_data);
        resp.set_data(result_data);
        break;
      case UNSEAL:
        if (!rpc.has_data()) {
          LOG(ERROR) << "Invalid RPC: must supply sealed data for Unseal";
          break;
        }

        result = t->Unseal(rpc.data(), &result_data);
        resp.set_data(result_data);
        break;
      case ATTEST:
        result = t->Attest(rpc.data(), &result_data);
        resp.set_data(result_data);
        break;
      case VERIFY_ATTESTATION:
        if (!rpc.has_data()) {
          LOG(ERROR) << "Invald RPC: must supply data for VerifyAttest";
          break;
        }

        result = t->VerifyAttestation(rpc.data(), rpc.signature());
        break;
      default:
        LOG(ERROR) << "Unknown RPC " << rpc.rpc();
        break;
    }

    resp.set_success(result);

    SendResponse(resp);
  }

  return true;
}

bool TaoChannel::StartHostedProgram(const string &path, int argc, char **argv) {
  TaoChannelRPC rpc;
  rpc.set_rpc(START_HOSTED_PROGRAM);

  StartHostedProgramArgs *shpa = rpc.mutable_start();
  shpa->set_path(path);
  shpa->set_argc(argc);
  for (int i = 0; i < argc; i++) {
    string *cur = shpa->add_argv();
    cur->assign(argv[i], strlen(argv[i]) + 1);
  }

  SendRPC(rpc);

  // wait for a response to the message
  TaoChannelResponse resp;
  GetResponse(&resp);

  return resp.success();
}

bool TaoChannel::GetRandomBytes(size_t size, string *bytes) const {
  TaoChannelRPC rpc;
  rpc.set_rpc(GET_RANDOM_BYTES);
  GetRandomBytesArgs *grba = rpc.mutable_random();
  grba->set_size(size);

  SendRPC(rpc);

  // wait for a response
  TaoChannelResponse resp;
  GetResponse(&resp);

  if (resp.success()) {
    if (!resp.has_data()) {
      LOG(ERROR) << "The successful GetRandomBytes did not contain data";
      return false;
    }

    bytes->assign(resp.data().data(), resp.data().size());
  }

  return resp.success();
}

bool TaoChannel::SendAndReceiveData(const string &in, string *out,
                                    RPC rpc_type) const {
  CHECK_NOTNULL(out);

  TaoChannelRPC rpc;
  rpc.set_rpc(rpc_type);
  rpc.set_data(in);

  SendRPC(rpc);

  TaoChannelResponse resp;
  GetResponse(&resp);

  if (resp.success()) {
    if (!resp.has_data()) {
      LOG(ERROR) << "A successful call did not return data";
      return false;
    }

    out->assign(resp.data().data(), resp.data().size());
  }

  return resp.success();
}

bool TaoChannel::Seal(const string &data, string *sealed) const {
  return SendAndReceiveData(data, sealed, SEAL);
}

bool TaoChannel::Unseal(const string &sealed, string *data) const {
  return SendAndReceiveData(sealed, data, UNSEAL);
}

bool TaoChannel::Attest(const string &data, string *attestation) const {
  TaoChannelRPC rpc;
  rpc.set_rpc(ATTEST);
  rpc.set_data(data);
  SendRPC(rpc);

  TaoChannelResponse resp;
  GetResponse(&resp);

  if (resp.success()) {
    if (!resp.has_data()) {
      LOG(ERROR) << "A successful Attest did not return data";
      return false;
    }

    attestation->assign(resp.data().data(), resp.data().size());
  }

  return resp.success();
}

bool TaoChannel::VerifyAttestation(const string &data, const string &attestation) const {
  TaoChannelRPC rpc;
  rpc.set_rpc(VERIFY_ATTESTATION);
  rpc.set_data(data);
  rpc.set_signature(attestation);
  SendRPC(rpc);

  TaoChannelResponse resp;
  GetResponse(&resp);

  return resp.success();
}

bool TaoChannel::GetRPC(TaoChannelRPC *rpc) const {
  CHECK_NOTNULL(rpc);
  return ReceiveMessage(rpc);
}

bool TaoChannel::SendRPC(const TaoChannelRPC &rpc) const {
  return SendMessage(rpc);
}

bool TaoChannel::GetResponse(TaoChannelResponse *resp) const {
  CHECK_NOTNULL(resp);
  return ReceiveMessage(resp);
}

bool TaoChannel::SendResponse(const TaoChannelResponse &resp) const {
  return SendMessage(resp);
}
}  // namespace tao
