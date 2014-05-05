//  File: file_client.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: Implementation of the FileClient class that interacts
// with FileServer
//
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

#include <glog/logging.h>
#include <keyczar/keyczar.h>

#include "cloudproxy/cloud_auth.h"
#include "cloudproxy/cloud_user_manager.h"
#include "cloudproxy/file_client.h"
#include "tao/tao_auth.h"

using std::string;

namespace cloudproxy {

FileClient::FileClient(const string &file_path,
                       const string &client_config_path,
                       tao::TaoChildChannel *channel, tao::TaoDomain *admin)
    : CloudClient(client_config_path, channel, admin), file_path_(file_path) {}

bool FileClient::Init() {
  if (!CloudClient::Init()) {
    LOG(ERROR) << "Could not initialize file cloud client";
    return false;
  }
  struct stat st;
  if (stat(file_path_.c_str(), &st) != 0) {
    LOG(ERROR) << file_path_ << " does not exist";
    return false;
  }
  if (!S_ISDIR(st.st_mode)) {
    LOG(ERROR) << file_path_ << " is not a directory";
    return false;
  }
  return true;
}

bool FileClient::Create(SSL *ssl, const string &owner,
                        const string &object_name) {
  // defer to the CloudClient implementation to get this created, since there's
  // nothing else to do with the file
  return CloudClient::Create(ssl, owner, object_name);
}

bool FileClient::Destroy(SSL *ssl, const string &owner,
                         const string &object_name) {
  // defer to the CloudClient implementation to get this destroyed, since
  // there's nothing else to do with the file
  return CloudClient::Destroy(ssl, owner, object_name);
}

bool FileClient::Read(SSL *ssl, const string &requestor,
                      const string &object_name, const string &output_name) {
  // make the call to get permission for the operation, and it that succeeds,
  // start to receive the bits
  CHECK(CloudClient::Read(ssl, requestor, object_name, output_name))
      << "Could not get permission to READ " << object_name;

  string path = file_path_ + string("/") + output_name;
  CHECK(ReceiveStreamData(ssl, path)) << "Error while reading the"
                                      << " file and writing it to disk";
  return HandleReply(ssl);
}

bool FileClient::Write(SSL *ssl, const string &requestor,
                       const string &input_name, const string &object_name) {
  // look up the file to get its length and make sure there is such a file
  string path = file_path_ + string("/") + input_name;
  struct stat st;
  CHECK_EQ(stat(path.c_str(), &st), 0) << "Could not stat the file " << path;

  // make the call to get permission for the operation, and if that succeeds,
  // then start to write the bits to the network
  CHECK(CloudClient::Write(ssl, requestor, input_name, object_name))
      << "Could not get permission to write to the file";

  VLOG(2) << "Got permission to write the file " << path;

  CHECK(SendStreamData(path, st.st_size, ssl))
      << "Could not send the file data to the server";
  return HandleReply(ssl);
}

}  // namespace cloudproxy
