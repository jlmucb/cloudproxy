//  File: cloud_client.h
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: The CloudClient class is used to communicate with
// CloudServer instances
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

#ifndef CLOUDPROXY_CLOUD_CLIENT_H_
#define CLOUDPROXY_CLOUD_CLIENT_H_

#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <string>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN
#include <openssl/ssl.h>

#include "cloudproxy/cloud_user_manager.h"
#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/util.h"
#include "tao/tao_child_channel.h"
#include "tao/tao_domain.h"

using std::string;

namespace cloudproxy {

/// A client that can establish a secure connection with a CloudServer and
/// manage simple operations between the client and the server. See
/// cloudproxy.proto for the details of the messages exchanged between
/// CloudClient and CloudServer, as well as the (related) format of ACLs stored
/// on the server. These ACLs are used by CloudServer to check if actions
/// requested by the CloudClient are authorized by CloudProxy policy.
/// Sample usage: see apps/client.cc
class CloudClient {
 public:
  /// Create a CloudClient. If the directory contains keys and certificates,
  /// then the client will try to open these files and decrypt them with the
  /// secret. Otherwise, they keys and certificates will be created and
  /// encrypted to this directory.
  /// @param client_config_path A directory to use for keys and TLS files.
  /// @param secret A string to use for a encrypting private keys.
  /// @param admin The configuration for this administrative domain. Ownership
  /// is taken.
  /// TODO(kwalsh) This description used to say the secret was tao-sealed
  /// against this client, but the code was not so. External code that
  /// seals the secret should be moved here.
  CloudClient(const string &client_config_path, const string &secret,
              tao::TaoDomain *admin);

  virtual ~CloudClient() {}

  /// Connect to a server.
  /// @param t The host Tao connection (used to generate attestations).
  /// @param server The server to connect to.
  /// @param port The port to connect to on the server.
  /// @param[out] ssl An established SSL connection to the server.
  bool Connect(const tao::TaoChildChannel &t, const string &server,
               const string &port, ScopedSSL *ssl);

  /// Associate keys with a user name.
  /// @param user The user to add.
  /// @param key_path The path to the Keyczar key for this user.
  /// @param password A password used to unlock the keys.
  bool AddUser(const string &user, const string &key_path,
               const string &password);

  /// Authenticate a subject to a connected CloudServer. There must be a
  /// directory under key_location that has a name matching the parameter.
  /// @param ssl The server connection to use.
  /// @param subject The subject to authenticate. This subject must have already
  /// been added.
  /// @param binding_file A SignedSpeaksFor file that maps the subject to a
  /// given public key.
  bool Authenticate(SSL *ssl, const string &subject,
                    const string &binding_file);

  /// Send a CREATE request to the attached CloudServer.
  /// @param ssl The server connection to use.
  /// @param owner A subject who is allowed to create this object.
  /// @param object_name The object to create.
  virtual bool Create(SSL *ssl, const string &owner, const string &object_name);

  /// Send a DESTROY request to the attached CloudServer.
  /// @param ssl The server connection to use.
  /// @param owner A subject who is allowed to destroy this object.
  /// @param object_name The object to destroy.
  virtual bool Destroy(SSL *ssl, const string &owner,
                       const string &object_name);

  /// Send a READ request to a CloudServer.
  /// @param ssl The server connection to use.
  /// @param requestor A subject who is allowed to read this object.
  /// @param object_name The name of an object to read.
  /// @param output_name The name to output to. The interpretation of this name
  /// depends on the implementation of CloudClient. In the basic implementation,
  /// output_name isn't used.
  virtual bool Read(SSL *ssl, const string &requestor,
                    const string &object_name, const string &output_name);

  /// Send a WRITE request to a CloudServer.
  /// @param ssl The server connection to use.
  /// @param requestor A subject who is allowed to write to this object.
  /// @param input_name A name representing input. The interpretation of this
  /// name depends on the implementation. The basic CloudClient writes this
  /// string to the object.
  /// @param object_name The name of the remote object to write to.
  virtual bool Write(SSL *ssl, const string &requestor,
                     const string &input_name, const string &object_name);

  /// Close the connection to the server
  /// @param ssl The server connection to close.
  /// @param error Whether or not this close operation is due to an error.
  bool Close(SSL *ssl, bool error);

  constexpr static auto ChallengeSigningContext =
      "CloudClient cloudproxy::Challenge Version 1";

 protected:
  /// A helper method to send an action to the server and handle the reply, if
  /// necessary.
  /// @param ssl The server connection to use.
  /// @param subject The subject of the action.
  /// @param object The object of the action.
  /// @param op The operation to perform in the action.
  /// @param handle_reply Whether or not to expect and handle a reply from the
  /// server.
  bool SendAction(SSL *ssl, const string &subject, const string &object, Op op,
                  bool handle_reply);

  /// Wait for a reply and handle it.
  /// @param ssl The server connection to use.
  bool HandleReply(SSL *ssl);

 private:
  /// Configuration for this administrative domain.
  scoped_ptr<tao::TaoDomain> admin_;

  /// Handle the client side of a challenge-response protocol with a server.
  /// @param ssl The server connection to use.
  /// @param chall The challenge to handle.
  bool HandleChallenge(SSL *ssl, const Challenge &chall);

  /// A context for TLS connections to servers.
  ScopedSSLCtx context_;

  /// Principals that have been authenticated on this connection, and the keys
  /// for each user.
  scoped_ptr<CloudUserManager> users_;

  DISALLOW_COPY_AND_ASSIGN(CloudClient);
};
}  // namespace cloudproxy

#endif  // CLOUDPROXY_CLOUD_CLIENT_H_
