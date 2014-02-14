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

#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/base/base64w.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/keyczar.h>
#include <openssl/ssl.h>

#include "cloudproxy/cloud_auth.h"
#include "cloudproxy/cloud_user_manager.h"
#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/file_client.h"
#include "tao/tao_child_channel.h"
#include "tao/tao_child_channel_registry.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using std::string;

using keyczar::base::Base64WDecode;

using cloudproxy::FileClient;
using cloudproxy::ScopedSSL;
using tao::TaoChildChannel;
using tao::TaoChildChannelRegistry;
using tao::TaoDomain;

DEFINE_string(config_path, "tao.config", "Location of tao configuration");
DEFINE_string(file_path, "file_client_files",
              "The path used by the file server to store files");
DEFINE_string(client_keys, "./client_key",
              "Directory for client keys and TLS files");

DEFINE_string(address, "localhost", "The address of the local server");
DEFINE_string(port, "11235", "The server port to connect to");

int main(int argc, char** argv) {
  GOOGLE_PROTOBUF_VERIFY_VERSION;

  google::ParseCommandLineFlags(&argc, &argv, false);

  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);
  tao::InitializeOpenSSL();

  // the last argument should be the parameters for channel establishment
  if (argc < 2) {
    LOG(ERROR) << "Too few arguments too fclient";
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

  scoped_ptr<TaoChildChannel> channel(registry.Create(params));
  CHECK(channel->Init()) << "Could not initialize the child channel";

  scoped_ptr<TaoDomain> admin(TaoDomain::Load(FLAGS_config_path));
  CHECK(admin.get() != nullptr) << "Could not load configuration";

  cloudproxy::FileClient fc(FLAGS_file_path, FLAGS_client_keys,
                            channel.release(), admin.release());

  ScopedSSL ssl;
  CHECK(fc.Connect(FLAGS_address, FLAGS_port, &ssl))
      << "Could not connect to the server at " << FLAGS_address << ":"
      << FLAGS_port;

  // create a random object name to write
  //    keyczar::RandImpl *rand = keyczar::CryptoFactory::Rand();
  //    string name_bytes;
  //    CHECK(rand->RandBytes(6, &name_bytes)) << "Could not get random bytes
  // for a name";
  //
  //    // Base64 encode the bytes to get a printable name
  //    string name;
  //    CHECK(keyczar::base::Base64WEncode(name_bytes, &name)) << "Could not
  // encode"
  //      " name";

  string name("test");
  CHECK(fc.AddUser("tmroeder", "./keys/tmroeder", "tmroeder"))
      << "Could not"
         " add the user credential from its keyczar path";
  CHECK(fc.Authenticate(ssl.get(), "tmroeder", "./keys/tmroeder_pub_signed"))
      << "Could"
         " not authenticate tmroeder with the server";
  LOG(INFO) << "Authenticated to the server for tmroeder";
  CHECK(fc.Create(ssl.get(), "tmroeder", name)) << "Could not create the object"
                                                << "'" << name
                                                << "' on the server";
  CHECK(fc.Write(ssl.get(), "tmroeder", name, name))
      << "Could not write the file to the server";

  string temp_file = name + ".out";
  CHECK(fc.Read(ssl.get(), "tmroeder", name, temp_file))
      << "Could not read the file from the"
         " server for comparison";
  LOG(INFO) << "Created, Wrote, and Read the file " << temp_file;

  // CHECK(fc.Destroy("tmroeder", name)) << "Could not destroy the object";
  // LOG(INFO) << "Destroyed the object " << name;

  CHECK(fc.Close(ssl.get(), false)) << "Could not close the channel";

  LOG(INFO) << "Test succeeded";

  return 0;
}
