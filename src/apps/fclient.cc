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
#include <openssl/ssl.h>
#include <keyczar/keyczar.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/base/base64w.h>

#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/cloud_auth.h"
#include "cloudproxy/cloud_user_manager.h"
#include "cloudproxy/file_client.h"
#include "tao/tao_child_channel.h"
#include "tao/tao_child_channel_registry.h"
#include "tao/util.h"
#include "tao/whitelist_auth.h"

using std::string;

using keyczar::base::Base64WDecode;

using cloudproxy::FileClient;
using cloudproxy::ScopedSSL;
using tao::TaoChildChannel;
using tao::TaoChildChannelRegistry;
using tao::WhitelistAuth;

DEFINE_string(file_path, "file_client_files",
              "The path used by the file server to store files");
DEFINE_string(client_cert, "./openssl_keys/client/client.crt",
              "The PEM certificate for the client to use for TLS");
DEFINE_string(client_key, "./openssl_keys/client/client.key",
              "The private key file for the client for TLS");

// this will be removed when get this password released by the TPM
DEFINE_string(client_password, "cpclient",
              "The private key file for the client for TLS");
DEFINE_string(policy_key, "./policy_public_key", "The keyczar public"
                                                 " policy key");
DEFINE_string(pem_policy_key, "./openssl_keys/policy/policy.crt",
              "The PEM public policy cert");
DEFINE_string(whitelist_path, "./signed_whitelist",
              "The path to the signed whitelist");
DEFINE_string(address, "localhost", "The address of the local server");
DEFINE_string(port, "11235", "The server port to connect to");

DEFINE_string(aik_cert, "./HW/aik.crt",
              "A certificate for the AIK, signed by the public policy key");

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

  scoped_ptr<WhitelistAuth> whitelist_auth(
      new WhitelistAuth(FLAGS_whitelist_path, FLAGS_policy_key));
  CHECK(whitelist_auth->Init()) << "Could not initialize the WhitelistAuth";

  LOG(INFO) << "About to create a client";
  cloudproxy::FileClient fc(FLAGS_file_path, FLAGS_client_cert,
                            FLAGS_client_key, FLAGS_client_password,
                            FLAGS_policy_key, FLAGS_pem_policy_key,
                            whitelist_auth.release());

  LOG(INFO) << "Created a client";
  ScopedSSL ssl;
  CHECK(fc.Connect(*channel, FLAGS_address, FLAGS_port, &ssl))
      << "Could not connect to the server at " << FLAGS_address << ":"
      << FLAGS_port;
  LOG(INFO) << "Connected to the server";

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
  LOG(INFO) << "Added credentials for the user tmroeder";
  CHECK(fc.Authenticate(ssl.get(), "tmroeder", "./keys/tmroeder_pub_signed"))
      << "Could"
         " not authenticate tmroeder with the server";
  LOG(INFO) << "Authenticated to the server for tmroeder";
  CHECK(fc.Create(ssl.get(), "tmroeder", name)) << "Could not create the object"
                                                << "'" << name
                                                << "' on the server";
  LOG(INFO) << "Created the object " << name;
  CHECK(fc.Write(ssl.get(), "tmroeder", name, name))
      << "Could not write the file to the server";
  LOG(INFO) << "Wrote the object " << name;

  string temp_file = name + ".out";
  CHECK(fc.Read(ssl.get(), "tmroeder", name, temp_file))
      << "Could not read the file from the"
         " server for comparison";
  LOG(INFO) << "Read the file";

  // CHECK(fc.Destroy("tmroeder", name)) << "Could not destroy the object";
  // LOG(INFO) << "Destroyed the object " << name;

  CHECK(fc.Close(ssl.get(), false)) << "Could not close the channel";

  LOG(INFO) << "Test succeeded";

  return 0;
}
