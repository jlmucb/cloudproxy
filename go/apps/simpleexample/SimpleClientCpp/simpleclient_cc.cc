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

#include "helpers.h"

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

// localhost is 127.0.0.1
DEFINE_string(config_file, "/Domains/domain.simpleexample/tao.config",
              "path to tao configuration");
DEFINE_string(client_path, "/Domains/domain.simpleexample/SimpleClientCpp",
              "path to SimpleClient files");
DEFINE_string(server_host, "localhost", "address for client/server");
DEFINE_string(server_port, "8123", "port for client/server");
DEFINE_string(domain_server_host, "localhost", "address for domain service");
DEFINE_string(domain_server_port, "8124", "port for domain service");
DEFINE_bool(test_rollback, false, "Test rollback protection");


int main(int argc, char **argv) {

  // Parse flags, signal handlers, openssl init.
  InitializeApp(&argc, &argv, false);

  // This code expects fd 3 and 4 to be the pipes from and to the Tao, so it
  // doesn't need to take any parameters. It will establish a Tao Child Channel
  // directly with these fds.
  unique_ptr<FDMessageChannel> msg(new FDMessageChannel(3, 4));
  unique_ptr<Tao> tao(new TaoRPC(msg.release()));

  TaoProgramData client_program_data;
  TaoChannel client_channel;

  client_program_data.ClearProgramData();

  string tcp("tcp");
  if (!client_program_data.InitTao(msg.get(), tao.get(), FLAGS_config_file,
            FLAGS_client_path, tcp, FLAGS_domain_server_host,
            FLAGS_domain_server_port)) {
    printf("client_program_data.InitTao failed\n");
    return 1;
  }

  string my_tao_name;
  if (!client_program_data.GetTaoName(&my_tao_name)) {
    printf("client_program_data.GetTaoName failed\n");
    return 1;
  }
  printf("simpleclientcpp: Simple client name: %s\n",
         my_tao_name.c_str());

  // Open the Tao Channel using the Program key.  This program does all the
  // standard channel negotiation and presents the secure server name after
  // negotiation is complete.
  if (!client_channel.OpenTaoChannel(client_program_data, FLAGS_server_host,
         FLAGS_server_port)) {
    printf("client_channel.OpenTaoChannel failed\n");
    return 1;
  }
  printf("simpleclient: established Tao Channel with %s\n",
         client_channel.peer_name_.c_str()) ;

  // Send a simple request and get response.
  taosupport::SimpleMessage req_message;
  taosupport::SimpleMessage resp_message;
  req_message.set_message_type(taosupport::REQUEST);
  req_message.set_request_type("SecretRequest");
  if (!client_channel.SendRequest(req_message)) {
    printf("simpleclient: Error in response to SendRequest\n");
  }
  printf("Sent request\n");
  if (!client_channel.GetRequest(&resp_message)) {
    printf("\nsimpleclient: Error in response to GetRequest\n");
  } else {
    const char* secret = (const char*) resp_message.data(0).data();
    printf("\nsimpleclient: secret is %s, done\n", secret);
  }

  if (FLAGS_test_rollback) {
    // Put Rollback protection tests here
    byte data[] = { 
      0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5,
      0,1,2,3,4,5,6,7,8,9,0,1,2,3,4,5
    };
    string label("label");
    string data_to_seal;
    string sealed_data;
    string recovered_data;
    string policy;
    int64_t counter = 2LL;
    int64_t initial_counter = 5LL;
    data_to_seal.assign((const char *)data, sizeof(data));

    if (client_program_data.InitCounter(label, initial_counter)) {
      printf("InitCounter succeeded 0\n");
    } else {
      printf("InitCounter failed 0\n");
    }
    if (client_program_data.GetCounter(label, &counter)) {
      printf("GetCounter (1) succeeded %lld\n", counter);
    } else {
      printf("GetCounter (1) failed\n");
    }
    if (client_program_data.RollbackProtectedSeal(label, data_to_seal, &sealed_data)) {
      printf("RollbackProtectedSeal succeeded\n");
      printf("data to seal: "); PrintBytes(data_to_seal.size(), (byte*)data_to_seal.data()); printf("\n");
    } else {
      printf("RollbackProtectedSeal failed\n");
    }
    if (client_program_data.GetCounter(label, &counter)) {
      printf("GetCounter (1) succeeded %lld\n", counter);
    } else {
      printf("GetCounter (1) failed\n");
    }
    if (client_program_data.RollbackProtectedUnseal(sealed_data, &recovered_data, &policy)) {
      printf("RollbackProtectedUnseal succeeded\n");
      printf("unsealed data: "); PrintBytes(recovered_data.size(),
             (byte*)recovered_data.data()); printf("\n");
    } else {
      printf("RollbackProtectedUnseal failed\n");
    }
    if (client_program_data.GetCounter(label, &counter)) {
      printf("GetCounter (2) succeeded %lld\n", counter);
    } else {
      printf("GetCounter (2) failed\n");
    }
  }
  return 0;
}
