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

#include "cloudproxy/file_client.h"

namespace cloudproxy {

FileClient::FileClient(const string &file_path, const string &tls_cert,
                       const string &tls_key, const string &tls_password,
                       const string &public_policy_keyczar,
                       const string &public_policy_pem,
                       const string &server_addr, ushort server_port,
		       tao::TaoAuth *auth_manager)
    : CloudClient(tls_cert, tls_key, tls_password, public_policy_keyczar,
                  public_policy_pem, server_addr,
                  server_port, auth_manager),
      file_path_(file_path) {
  struct stat st;
  CHECK_EQ(stat(file_path.c_str(), &st), 0) << file_path << " does not exist";

  CHECK(S_ISDIR(st.st_mode)) << file_path << " is not a directory";
}

bool FileClient::Create(const string &owner, const string &object_name) {
  // defer to the CloudClient implementation to get this created, since there's
  // nothing else to do with the file
  return CloudClient::Create(owner, object_name);
}

bool FileClient::Destroy(const string &owner, const string &object_name) {
  // defer to the CloudClient implementation to get this destroyed, since
  // there's nothing else to do with the file
  return CloudClient::Destroy(owner, object_name);
}

bool FileClient::Read(const string &requestor, const string &object_name,
                      const string &output_name) {
  // make the call to get permission for the operation, and it that succeeds,
  // start to receive the bits
  CHECK(CloudClient::Read(requestor, object_name, output_name))
      << "Could not get permission to READ " << object_name;

  string path = file_path_ + string("/") + output_name;
  CHECK(ReceiveStreamData(bio_.get(), path)) << "Error while reading the"
                                             << " file and writing it to disk";
  return HandleReply();
}

bool FileClient::Write(const string &requestor, const string &input_name,
                       const string &object_name) {
  // look up the file to get its length and make sure there is such a file
  string path = file_path_ + string("/") + input_name;
  struct stat st;
  CHECK_EQ(stat(path.c_str(), &st), 0) << "Could not stat the file " << path;

  LOG(INFO) << "Found the file " << path;

  // make the call to get permission for the operation, and if that succeeds,
  // then start to write the bits to the network
  CHECK(CloudClient::Write(requestor, input_name, object_name))
      << "Could not get permission to write to the file";

  LOG(INFO) << "Got permission to write the file " << path;

  CHECK(SendStreamData(path, st.st_size, bio_.get()))
      << "Could not send the file data to the server";
  return HandleReply();
}

}  // namespace cloudproxy
