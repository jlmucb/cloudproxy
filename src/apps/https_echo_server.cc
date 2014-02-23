//  File: sheserver.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: An example https echo server application using HttpsEchoServer
//
//  Copyright (c) 2013, Kevin Walsh.  All rights reserved.
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

#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/base/base64w.h>

#include "cloudproxy/https_echo_server.h"
#include "cloudproxy/util.h"
#include "tao/pipe_tao_child_channel.h"
#include "tao/tao_child_channel_registry.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using std::string;

using keyczar::base::Base64WDecode;

using tao::InitializeApp;
using tao::TaoChildChannel;
using tao::TaoChildChannelRegistry;
using tao::TaoDomain;

DEFINE_string(config_path, "tao.config", "Location of tao configuration");

DEFINE_string(server_keys, "./https_keys", "Directory for keys and TLS files");
DEFINE_string(address, "localhost", "The address to listen on");
DEFINE_string(port, "8443", "The port to listen on");

int main(int argc, char **argv) {
  InitializeApp(&argc, &argv, true);

  // the last argument should be the parameters for channel establishment
  if (argc < 2) {
    LOG(ERROR) << "Too few arguments to server";
    return 1;
  }

  string encoded_params(argv[argc - 1]);
  string params;
  if (!Base64WDecode(encoded_params, &params)) {
    LOG(ERROR) << "Could not decode the encoded params " << encoded_params;
    return 1;
  }

  TaoChildChannelRegistry registry;
  tao::RegisterKnownChannels(&registry);

  scoped_ptr<TaoChildChannel> channel(registry.Create(params));
  CHECK(channel->Init()) << "Could not initialize the child channel";

  scoped_ptr<TaoDomain> admin(TaoDomain::Load(FLAGS_config_path));
  if (admin.get() == nullptr) return 1;

  cloudproxy::HttpsEchoServer shes(FLAGS_server_keys, FLAGS_address, FLAGS_port,
                                   channel.release(), admin.release());

  LOG(INFO) << "HttpsEchoServer listening on " << FLAGS_address << ":"
            << FLAGS_port;
  CHECK(shes.Listen(false /* not single channel */))
      << "Could not listen for https connections";
  return 0;
}
