//  File: fclient.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An example client application using FileClient
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
#include <cstdio>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <openssl/ssl.h>

#include "cloudproxy/cloud_user_manager.h"
#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/file_client.h"
#include "tao/keys.h"
#include "tao/tao_child_channel.h"
#include "tao/tao_child_channel_registry.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using std::string;

using cloudproxy::CloudUserManager;
using cloudproxy::FileClient;
using cloudproxy::ScopedSSL;
using tao::Base64WDecode;
using tao::InitializeApp;
using tao::Keys;
using tao::TaoChildChannel;
using tao::TaoChildChannelRegistry;
using tao::TaoDomain;

DEFINE_string(config_path, "tao.config", "Location of tao configuration");
DEFINE_string(file_path, "file_client_files",
              "The path used by the file server to store files");
DEFINE_string(client_keys, "./fclient_keys",
              "Directory for client keys and TLS files");
DEFINE_string(user, "tmroeder", "Name of user to authenticate");
DEFINE_string(user_keys, "./user_keys", "Location of user keys");
DEFINE_string(address, "localhost", "The address of the local server");
DEFINE_string(port, "11235", "The server port to connect to");

int main(int argc, char** argv) {
  InitializeApp(&argc, &argv, false);

  // the last argument should be the parameters for channel establishment
  if (argc < 2) {
    LOG(ERROR) << "Too few arguments to fclient";
    return 1;
  }

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
  cloudproxy::FileClient fc(FLAGS_file_path, FLAGS_client_keys,
                            channel.release(), policy, admin.release());
  CHECK(fc.Init());

  ScopedSSL ssl;
  CHECK(fc.Connect(FLAGS_address, FLAGS_port, &ssl))
      << "Could not connect to the server at " << FLAGS_address << ":"
      << FLAGS_port;

  string name("test");

  unique_ptr<Keys> key;
  string user = FLAGS_user;
  string password = FLAGS_user;
  CHECK(CloudUserManager::LoadUser(FLAGS_user_keys, user, password, &key));
  CHECK(fc.AddUser(user, *key->Signer())) << "Could not add the user key";
  CHECK(fc.Authenticate(ssl.get(), user,
                        key->GetPath(CloudUserManager::UserDelegationSuffix)))
      << "Could not authenticate user with the server";
  LOG(INFO) << "Authenticated to the server for " << user;
  CHECK(fc.Create(ssl.get(), user, name)) << "Could not create object"
                                          << "'" << name << "' on the server";
  CHECK(fc.Write(ssl.get(), user, name, name)) << "Could not write the object";

  string temp_file = name + ".out";
  CHECK(fc.Read(ssl.get(), "tmroeder", name, temp_file))
      << "Could not read the file from the server for comparison";
  LOG(INFO) << "Created, Wrote, and Read the file " << temp_file;

  CHECK(fc.Close(ssl.get(), false)) << "Could not close the channel";

  printf("Test succeeded\n");

  return 0;
}
