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

#include <set>
#include <string>
#include <map>

#include <keyczar/base/basictypes.h> // DISALLOW_COPY_AND_ASSIGN
#include <openssl/ssl.h>

using std::set;
using std::string;
using std::map;

namespace cloudproxy {

// a class for managing thread data: outstanding challenges and user
// authentication information
class CloudServerThreadData {
 public:
  CloudServerThreadData(const string &peer_cert, const string &self_cert)
      : serialized_peer_cert_(peer_cert),
        serialized_self_cert_(self_cert),
        cert_validated_(false),
        auth_() {}
  virtual ~CloudServerThreadData() {}

  bool GetChallenge(const string &user, string *chall);
  bool AddChallenge(const string &user, const string &chall);
  bool RemoveChallenge(const string &user);

  bool SetAuthenticated(const string &user);
  bool IsAuthenticated(const string &user);
  bool RemoveAuthenticated(const string &user);

  bool SetCertValidated();
  bool GetCertValidated();

  string GetPeerCert() { return serialized_peer_cert_; }
  string GetSelfCert() { return serialized_self_cert_; }

 private:
  string serialized_peer_cert_;

  string serialized_self_cert_;

  // whether or not the certificate used for this connection has been validated
  bool cert_validated_;

  // the set of outstanding challenges on this channel
  map<string, string> challenges_;

  // the set of users that have successfully authenticated on this channel
  set<string> auth_;

  DISALLOW_COPY_AND_ASSIGN(CloudServerThreadData);
};
}

#endif  // CLOUDOPROXY_CLOUD_SERVER_THREAD_DATA_H_
