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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include <set>
#include <string>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN
#include <openssl/ssl.h>

#include "cloudproxy/cloudproxy.pb.h"
#include "cloudproxy/util.h"
#include "tao/tao_child_channel.h"
#include "tao/whitelist_auth.h"

using std::set;
using std::string;

namespace keyczar {
class Keyczar;
}  // namespace keyczar

namespace tao {
class TaoAuth;
class TaoChildChannel;
}  // namespace tao

namespace cloudproxy {

class CloudUserManager;

/// A client that can establish a secure connection with a CloudServer and
/// manage
/// simple operations between the client and the server. See cloudproxy.proto
/// for
/// the details of the messages exchanged between CloudClient and CloudServer,
/// as
/// well as the (related) format of ACLs stored on the server. These ACLs are
/// used by CloudServer to check if actions requested by the CloudClient are
/// authorized by CloudProxy policy.
///
/// Sample usage: see apps/client.cc
class CloudClient {
 public:
  /// Create a CloudClient. If the TLS paths refer to existing files, then the
  /// client will try to open these files and decrypt them with the secret.
  /// Otherwise, it will generate and seal a new secret and use this secret to
  /// encrypt a new TLS public/private key pair.
  /// @param tls_cert The path to a TLS certificate (or the location to write
  /// one).
  /// @param tls_key The path to a TLS private key (or the location to write
  /// one).
  /// @param secret The path to a Tao-sealed secret (or the location to write
  /// one).
  /// @param public_policy_keyczar The path to the public policy key.
  /// @param public_policy_pem The path to an OpenSSL representation of the
  /// public policy key.
  /// @param server_addr The name or IP address of an instance of CloudServer.
  /// @param server_port The port used by the CloudServer instance at the
  /// address named in server_addr.
  /// @param auth_manager An instance of TaoAuth that can be used to verify
  /// attestations.
  CloudClient(const string &tls_cert, const string &tls_key,
              const string &secret, const string &public_policy_keyczar,
              const string &public_policy_pem, const string &server_addr,
              ushort server_port, tao::TaoAuth *auth_manager);

  virtual ~CloudClient() {}

  /// Connect to a server.
  /// @param t The host Tao connection (used to generate attestations).
  bool Connect(const tao::TaoChildChannel &t);

  /// Associate keys with a user name.
  /// @param user The user to add.
  /// @param key_path The path to the Keyczar key for this user.
  /// @param password A password used to unlock the keys.
  bool AddUser(const string &user, const string &key_path,
               const string &password);

  /// Authenticate a subject to a connected CloudServer. There must be a
  /// directory under key_location that has a name matching the parameter.
  /// @param subject The subject to authenticate. This subject must have already
  /// been added.
  /// @param binding_file A SignedSpeaksFor file that maps the subject to a
  /// given public key.
  bool Authenticate(const string &subject, const string &binding_file);

  /// Send a CREATE request to the attached CloudServer.
  /// @param owner A subject who is allowed to create this object.
  /// @param object_name The object to create.
  virtual bool Create(const string &owner, const string &object_name);

  /// Send a DESTROY request to the attached CloudServer.
  /// @param owner A subject who is allowed to destroy this object.
  /// @param object_name The object to destroy.
  virtual bool Destroy(const string &owner, const string &object_name);

  /// Send a READ request to a CloudServer.
  /// @param requestor A subject who is allowed to read this object.
  /// @param object_name The name of an object to read.
  /// @param output_name The name to output to. The interpretation of this name
  /// depends on the implementation of CloudClient. In the basic implementation,
  /// output_name isn't used.
  virtual bool Read(const string &requestor, const string &object_name,
                    const string &output_name);

  /// Send a WRITE request to a CloudServer.
  /// @param requestor A subject who is allowed to write to this object.
  /// @param input_name A name representing input. The interpretation of this
  /// name depends on the implementation. The basic CloudClient writes this
  /// string to the object.
  virtual bool Write(const string &requestor, const string &input_name,
                     const string &object_name);

  /// Close the connection to the server
  /// @param error Whether or not this close operation is due to an error.
  bool Close(bool error);

 protected:
  /// A helper method to send an action to the server and handle the reply, if
  /// necessary.
  /// @param subject The subject of the action.
  /// @param object The object of the action.
  /// @param op The operation to perform in the action.
  /// @param handle_reply Whether or not to expect and handle a reply from the
  /// server.
  bool SendAction(const string &subject, const string &object, Op op,
                  bool handle_reply);

  /// Wait for a reply and handle it.
  bool HandleReply();

  // The BIO used to communicate over the TLS channel
  keyczar::openssl::ScopedBIO bio_;

 private:
  /// Handle the client side of a challenge-response protocol with a server.
  /// @param chall The challenge to handle.
  bool HandleChallenge(const Challenge &chall);

  // The public policy key for this connection.
  scoped_ptr<keyczar::Keyczar> public_policy_key_;

  // A TLS connection to the server.
  ScopedSSLCtx context_;

  // Principals that have been authenticated on this connection, and the keys
  // for each user.
  scoped_ptr<CloudUserManager> users_;

  // A way to check that a given hash corresponds to an authorized program.
  scoped_ptr<tao::TaoAuth> auth_manager_;

  DISALLOW_COPY_AND_ASSIGN(CloudClient);
};
}

#endif  // CLOUDPROXY_CLOUD_CLIENT_H_
