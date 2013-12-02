//  File: file_client.h
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: The FileClient class interacts with FileServer
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

#ifndef CLOUDPROXY_FILE_CLIENT_H_
#define CLOUDPROXY_FILE_CLIENT_H_

#include "cloudproxy/cloud_client.h"

namespace cloudproxy {
class FileClient : public CloudClient {
 public:

  FileClient(const string &file_path, const string &tls_cert,
             const string &tls_key, const string &tls_password,
             const string &public_policy_keyczar,
             const string &public_policy_pem, const string &server_addr,
             ushort server_port, tao::TaoAuth *auth_manager);

  virtual ~FileClient() {}

  // Sends a CREATE request to the attached CloudServer
  virtual bool Create(const string &owner, const string &object_name);

  // Sends a DESTROY request to the attached CloudServer
  virtual bool Destroy(const string &owner, const string &object_name);

  // Send a READ request to a CloudServer
  virtual bool Read(const string &requestor, const string &object_name,
                    const string &output_name);

  // Sends a WRITE request to a CloudServer
  virtual bool Write(const string &requestor, const string &input_name,
                     const string &object_name);

 private:

  // the base path for files that are read from and written to the server
  string file_path_;

  DISALLOW_COPY_AND_ASSIGN(FileClient);
};
}

#endif  // CLOUDPROXY_FILE_CLIENT_H_
