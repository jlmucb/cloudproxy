//  File: fserver.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An example file server application using FileServer
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

#include <memory>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <openssl/crypto.h>
#include <openssl/ssl.h>

#include "cloudproxy/cloud_auth.h"
#include "cloudproxy/cloud_user_manager.h"
#include "cloudproxy/file_server.h"
#include "tao/tao_child_channel.h"
#include "tao/tao_child_channel_registry.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using std::string;

using tao::Base64WDecode;
using tao::InitializeApp;
using tao::TaoChildChannel;
using tao::TaoChildChannelRegistry;
using tao::TaoDomain;

DEFINE_string(config_path, "tao.config", "Location of tao configuration");
DEFINE_string(file_path, "file_server_files",
              "The path used by the file server to store files");
DEFINE_string(meta_path, "file_server_meta",
              "The path used by the file server to store metadata");
DEFINE_string(server_keys, "./fserver_keys",
              "Directory for server keys and TLS files");
DEFINE_string(acls, "./acls_sig",
              "A file containing a SignedACL signed by"
              " the public policy key (e.g., using sign_acls)");
DEFINE_string(address, "localhost", "The address to listen on");
DEFINE_string(port, "11235", "The port to listen on");

int main(int argc, char **argv) {
  InitializeApp(&argc, &argv, true);

  // The convention is that the last argument in a process-based hosted program
  // is the child channel params encoded as Base64W.
  string encoded_params(argv[argc - 1]);
  string params;
  if (!Base64WDecode(encoded_params, &params)) {
    LOG(ERROR) << "Could not decode the encoded params " << encoded_params;
    return 1;
  }

  TaoChildChannelRegistry registry;
  tao::RegisterKnownChannels(&registry);

  unique_ptr<TaoChildChannel> channel(registry.Create(params));
  CHECK(channel->Init()) << "Could not initialize the child channel";

  unique_ptr<TaoDomain> admin(TaoDomain::Load(FLAGS_config_path));
  CHECK(admin.get() != nullptr) << "Could not load configuration";

  int policy = 0;  // TODO(kwalsh) chose policy here
  cloudproxy::FileServer fs(FLAGS_file_path, FLAGS_meta_path, FLAGS_server_keys,
                            FLAGS_acls, FLAGS_address, FLAGS_port,
                            channel.release(), policy, admin.release());
  CHECK(fs.Init());

  LOG(INFO) << "FileServer listening";
  CHECK(fs.Listen(false /* not single channel */))
      << "Could not listen for client connections";
  return 0;
}
