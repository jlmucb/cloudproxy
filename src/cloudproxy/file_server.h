//  File: file_server.h
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: The FileServer class manages files for FileClient
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

#ifndef CLOUDPROXY_FILE_SERVER_H_
#define CLOUDPROXY_FILE_SERVER_H_

#include <string>

#include "cloudproxy/cloud_server.h"

using std::string;

namespace cloudproxy {
/// An implementation of CloudServer that manages files for remote FileClients.
/// It keeps each file encrypted and with integrity protection.
class FileServer : public CloudServer {
 public:
  /// Create a FileServer. All the parameters except the first two have the same
  /// semantics as for CloudServer.
  /// @param file_path The path at which to keep files sent from FileClients.
  /// @param meta_path The path at which to keep metadata about files sent from
  /// FileClients.
  /// @param server_config_path A directory to use for keys and TLS files.
  /// @param acl_location The path to a signed ACL giving permissions for
  /// operations on the server.
  /// @param host The name or IP address of the host to bind the server to.
  /// @param port The port to bind the server to.
  /// @param channel A connection to the host Tao. Ownership is taken.
  /// @param admin The configuration for this administrative domain. Ownership
  /// is taken
  FileServer(const string &file_path, const string &meta_path,
             const string &server_config_path, const string &acl_location,
             const string &host, const string &port,
             tao::TaoChildChannel *channel, tao::TaoDomain *admin);
  virtual bool Init();
  virtual ~FileServer() {}

  constexpr static auto ObjectMetadataSigningContext =
      "FileServer cloudproxy::HmacObjectMetadata Version 1";

 protected:
  /// @{
  /// Check a file action and perform the operation it requests.
  /// @param action The action requested by a FileClient.
  /// @param ssl A channel for communication with the requesting client.
  /// @param[out] reason A string to fill with an error message if the action is
  /// not authorized.
  /// @param[out] reply Indicates success or failure of the action.
  /// @param cstd A context parameter for the thread.
  /// @return A value that indicates whether or not the action was performed
  /// without errors.
  virtual bool HandleCreate(const Action &action, SSL *ssl, string *reason,
                            bool *reply,
                            CloudServerThreadData &cstd);  // NOLINT
  virtual bool HandleDestroy(const Action &action, SSL *ssl, string *reason,
                             bool *reply,
                             CloudServerThreadData &cstd);  // NOLINT
  virtual bool HandleWrite(const Action &action, SSL *ssl, string *reason,
                           bool *reply, CloudServerThreadData &cstd);  // NOLINT
  virtual bool HandleRead(const Action &action, SSL *ssl, string *reason,
                          bool *reply, CloudServerThreadData &cstd);  // NOLINT
                                                                      /// @}

 private:
  /// A key for deriving keys for encryption and integrity protection.
  scoped_ptr<tao::Keys> main_key_;

  /// A key to use for file encryption.
  keyczar::base::ScopedSafeString enc_key_;

  /// A key to use for integrity protection.
  keyczar::base::ScopedSafeString hmac_key_;

  /// The path to which we write incoming files.
  string file_path_;

  /// The path to which we write file metadata.
  string meta_path_;

  DISALLOW_COPY_AND_ASSIGN(FileServer);
};
}  // namespace cloudproxy

#endif  // CLOUDPROXY_FILE_SERVER_H_
