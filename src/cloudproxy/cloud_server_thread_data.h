//  File: cloud_server_thread_data.h
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: The CloudServerThreadData class is used to store
// thread-local data for the CloudServer class
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

#ifndef CLOUDPROXY_CLOUD_SERVER_THREAD_DATA_H_
#define CLOUDPROXY_CLOUD_SERVER_THREAD_DATA_H_

#include <map>
#include <set>
#include <string>

#include <keyczar/base/basictypes.h>  // DISALLOW_COPY_AND_ASSIGN
#include <openssl/ssl.h>

using std::map;
using std::set;
using std::string;

namespace cloudproxy {

/// A class for managing thread data: outstanding challenges and user
/// authentication information.
class CloudServerThreadData {
 public:
  /// Create a new object.
  /// @param peer_cert The certificate of the peer in the communication
  /// (needn't already be authenticated by the caller).
  /// @param self_cert The certificate of the server.
  CloudServerThreadData(const string &peer_cert, const string &self_cert)
      : serialized_peer_cert_(peer_cert),
        serialized_self_cert_(self_cert),
        cert_validated_(false),
        auth_() {}
  virtual ~CloudServerThreadData() {}

  /// Gets the challenge associated with a user.
  /// @param user The user to look up.
  /// @param[out] chall The challenge associated with this user, if any.
  bool GetChallenge(const string &user, string *chall);

  /// Store a new challenge for a user.
  /// @param user The user to add this challenge for.
  /// @param chall The challenge to add.
  bool AddChallenge(const string &user, const string &chall);

  /// Remove all challenges associated with a user.
  /// @param user The user to remove.
  bool RemoveChallenge(const string &user);

  /// Record that a user has been authenticated by the server.
  /// @param user The user to record.
  bool SetAuthenticated(const string &user);

  /// Check if a user has been authenticated by the server.
  /// @param user The user to check.
  bool IsAuthenticated(const string &user);

  /// Set the user as no longer being authenticated.
  /// @param user The user to set as non-authenticated.
  bool RemoveAuthenticated(const string &user);

  /// Note that the peer certificate has been validated.
  bool SetCertValidated();

  /// Check whether the peer certificate has been validated.
  bool GetCertValidated();

  /// Get the peer certificate. This does not guarantee that the certificate has
  /// been validated.
  /// @return A serialized peer certificate.
  string GetPeerCert() { return serialized_peer_cert_; }

  /// Gets the server certificate.
  /// @return A serialized server certificate.
  string GetSelfCert() { return serialized_self_cert_; }

 private:
  // The peer certificate, stored as serialized X.509.
  string serialized_peer_cert_;

  // The self certificate, stored as serialized X.509.
  string serialized_self_cert_;

  // Whether or not the certificate used for this connection has been validated.
  bool cert_validated_;

  // The set of outstanding challenges on this channel.
  map<string, string> challenges_;

  // The set of users that have successfully authenticated on this channel.
  set<string> auth_;

  DISALLOW_COPY_AND_ASSIGN(CloudServerThreadData);
};
}  // namespace cloudproxy

#endif  // CLOUDPROXY_CLOUD_SERVER_THREAD_DATA_H_
