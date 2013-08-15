//  File: cloud_server_thread_data.h
//  Author: Tom Roeder <tmroeder@google.com>
//
// Description: The CloudServerThreadData class is used to store
// thread-local data for the CloudServer class
// 
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
//
// Use, duplication and disclosure of this file and derived works of
// this file are subject to and licensed under the Apache License dated
// January, 2004, (the "License").  This License is contained in the
// top level directory originally provided with the CloudProxy Project.
// Your right to use or distribute this file, or derived works thereof,
// is subject to your being bound by those terms and your use indicates
// consent to those terms.
//
// If you distribute this file (or portions derived therefrom), you must
// include License in or with the file and, in the event you do not include
// the entire License in the file, the file must contain a reference
// to the location of the License.

// ------------------------------------------------------------------------

#ifndef CLOUDPROXY_CLOUD_SERVER_THREAD_DATA_H_
#define CLOUDPROXY_CLOUD_SERVER_THREAD_DATA_H_

#include "cloudproxy/cloud_server_thread_data.h"
#include "cloudproxy/util.h"

#include <keyczar/keyczar.h>
#include <openssl/ssl.h>

#include <set>
#include <string>
#include <map>

using std::set;
using std::string;
using std::map;

namespace cloudproxy {

// a class for managing thread data: outstanding challenges and user
// authentication information
class CloudServerThreadData {
 public:
 CloudServerThreadData(X509 *peer_cert, X509 *self_cert) : peer_cert_(peer_cert), self_cert_(self_cert), cert_validated_(false), auth_() { }
  virtual ~CloudServerThreadData() {}

  bool GetChallenge(const string &user, string *chall);
  bool AddChallenge(const string &user, const string &chall);
  bool RemoveChallenge(const string &user);

  bool SetAuthenticated(const string &user);
  bool IsAuthenticated(const string &user);
  bool RemoveAuthenticated(const string &user);

  bool SetCertValidated();
  bool GetCertValidated();

  X509 *GetPeerCert();
  X509 *GetSelfCert();
 private:
  ScopedX509Ctx peer_cert_;

  ScopedX509Ctx self_cert_;

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
