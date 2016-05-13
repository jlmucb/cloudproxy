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

DEFINE_string(config_file, "/Domains/domain.simpleexample/tao.config",
              "path to tao configuration");
DEFINE_string(client_path, "/Domains/domain.simpleexample/SimpleClient",
              "path to SimpleClient files");
DEFINE_string(server_host, "localhost", "address for client/server");
DEFINE_string(server_port, "8123", "port for client/server");

int main(int argc, char **argv) {
  InitializeApp(&argc, &argv, false);

  // This code expects fd 3 and 4 to be the pipes from and to the Tao, so it
  // doesn't need to take any parameters. It will establish a Tao Child Channel
  // directly with these fds.
  unique_ptr<FDMessageChannel> msg(new FDMessageChannel(3, 4));
  unique_ptr<Tao> tao(new TaoRPC(msg.release()));

  // Did InitializeApp parse the flags?
  GFLAGS_NS::ParseCommandLineFlags(&argc, &argv, true);

  TaoProgramData client_program_data;
  TaoChannel client_channel;
  string serverAddr = FLAGS_server_host + ":" + FLAGS_server_port;

  client_program_data.ClearTaoProgramData();

  if (!client_program_data.InitTao(*FLAGS_config_file, *FLAGS_client_path)) {
  }
  printf("Simple client name: %s\n", client_program_data.tao_name_.c_str());

  // Open the Tao Channel using the Program key.  This program does all the
  // standard channel negotiation and presents the secure server name after
  // negotiation is complete.
  if (!client_channel.OpenTaoChannel(client_program_data, serverAdd)) {
  }
        log.Printf("simpleclient: establish Tao Channel with %s, %s\n",
                serverAddr, serverName)
  printf("simpleclient: established Tao Channel with %s\n",
         client_channel.server_name_.c_str()) ;


  // Send a simple request and get response.
  taosupport::SimpleMessage req_message;
  taosupport::SimpleMessage resp_message;
  req_message.message_type = REQUEST;
  req_message.request_type = "SecretRequest";
  if (!client_channel.SendRequest(req_message)) {
    printf("simpleclient: Error in response to SendRequest\n")
  }
  if (!client_channel.GetRequest(resp_message)) {
    printf("simpleclient: Error in response to GetRequest\n")
  }
  printf("simpleclient: secret is %s, done\n", resp_message.data())

  return 0;
}
