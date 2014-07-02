//  File: cloud_channel.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: A socket-based MessageChannel authenticated with TLS+Tao.
//
//  Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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
#include "cloudproxy/cloud_channel.h"

#include <arpa/inet.h>

#include <glog/logging.h>
#include <openssl/ssl.h>

#include "cloudproxy/util.h"
#include "tao/attestation.h"
#include "tao/keys.h"

using tao::OpenSSLSuccess;
using tao::Verifier;

namespace cloudproxy {

CloudChannel::CloudChannel(SSL_CTX *tls_ctx, int sock) : chan_(tls_ctx, sock) {}

bool CloudChannel::ValidateDelegation(const string &delegation,
                                         const string &cert, string *name) {
  string delegate, issuer;
  if (!tao::ValidateDelegation(delegation, tao::CurrentTime(), &delegate,
                               &issuer)) {
    LOG(ERROR) << "Delegation is invalid";
    return false;
  }
  scoped_ptr<Verifier> cert_key(Verifier::FromX509(cert));
  if (cert_key.get() == nullptr) {
    LOG(ERROR) << "Could not parse key from x509";
    return false;
  }
  string cert_key_name = cert_key->ToPrincipalName();;
  if (cert_key_name == "") {
    LOG(ERROR) << "Could not get principal name for x509 key";
    return false;
  }

  if (delegate != cert_key_name) {
    LOG(ERROR) << "Delegated key did not match x509 key";
    return false;
  }
  name->assign(issuer);
  return true;
}

bool CloudChannel::TaoHandshake(const string &self_delegation) {
  if (!ValidateDelegation(self_delegation, chan_.GetTLSSelfCert(), &self_name_)) {
    LOG(ERROR) << "Could not initialize Tao self name";
    return false;
  }
  // Exchange Tao delegations.
  string peer_delegation;
  bool eof;
  if (!SendFrame(CLOUD_CHANNEL_FRAME_HANDSHAKE, self_delegation) ||
      !ReceiveFrame(CLOUD_CHANNEL_FRAME_HANDSHAKE, &peer_delegation, &eof)) {
    LOG(ERROR) << "Could not exchange Tao delegations";
    return false;
  }
  if (eof) {
    LOG(ERROR) << "Lost connection while exchanging Tao delegations";
    return false;
  }
  if (!ValidateDelegation(peer_delegation, chan_.GetTLSPeerCert(), &peer_name_)) {
    LOG(ERROR) << "Could not initialize Tao peer name";
    return false;
  }
  return true;
}

bool CloudChannel::SendFrame(CloudChannelFrameTag tag, const string &msg) {
  if (IsClosed()) {
    LOG(ERROR) << "Could not send frame, channel is already closed";
    return false;
  }
  CloudChannelFrame frame;
  frame.set_tag(tag);
  frame.set_data(msg);
  return chan_.SendMessage(frame);
}

bool CloudChannel::SendData(const void *buffer, size_t buffer_len) {
  string s(reinterpret_cast<const char *>(buffer), buffer_len);
  return SendFrame(CLOUD_CHANNEL_FRAME_WRAPPED_BUFFER, s);
}

bool CloudChannel::SendString(const string &s) {
  return SendFrame(CLOUD_CHANNEL_FRAME_WRAPPED_STRING, s);
}

bool CloudChannel::SendMessage(const google::protobuf::Message &m) {
  string serialized;
  if (!m.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the Message to a string";
    return false;
  }
  return SendFrame(CLOUD_CHANNEL_FRAME_WRAPPED_MESSAGE, serialized);
}

bool CloudChannel::ReceiveFrame(CloudChannelFrameTag expected_tag, string *msg,
                                bool *eof) {

  CloudChannelFrame frame;
  if (!chan_.ReceiveMessage(&frame, eof)) {
    LOG(ERROR) << "Could not receive frame";
    return false;
  } else if (*eof) {
    return true;
  }
  switch (frame.tag()) {
    case CLOUD_CHANNEL_FRAME_ABORT:
      LOG(ERROR) << "Connection closed by peer with error: " << frame.data();
      Close();
      *eof = true;
      return true;
    case CLOUD_CHANNEL_FRAME_SHUTDOWN:
      LOG(INFO) << "Connection about to close by peer";
      *eof = true;
      if (!SendFrame(CLOUD_CHANNEL_FRAME_SHUTDOWN_RESPONSE, "" /* empty message */)) {
        LOG(ERROR) << "Could not send disconnect response";
        Close();
        return false;
      }
      Close();
      return true;
    default:
      if (frame.tag() != expected_tag) {
        LOG(INFO) << "Unexpected message tag: " << frame.tag();
        Close();
        return false;
      }
      msg->assign(frame.data());
      return true;
  }
}

bool CloudChannel::ReceiveData(void *buffer, size_t buffer_len, bool *eof) {
  string s;
  if (!ReceiveFrame(CLOUD_CHANNEL_FRAME_WRAPPED_BUFFER, &s, eof)) {
    LOG(ERROR) << "Could not receive wrapped buffer";
    return false;
  } else if (*eof) {
    // LOG(WARNING) << "Connection has unexpectedly closed";
    return true;
  }
  if (s.size() != buffer_len) {
    LOG(ERROR) << "Received incorrect buffer size";
    Close();
    return false;
  }
  s.copy(reinterpret_cast<char *>(buffer), s.size());
  return true;
}

bool CloudChannel::ReceiveString(string *s, bool *eof) {
  if (!ReceiveFrame(CLOUD_CHANNEL_FRAME_WRAPPED_STRING, s, eof)) {
    LOG(ERROR) << "Could not receive wrapped string";
    return false;
  } else if (*eof) {
    // LOG(WARNING) << "Connection has unexpectedly closed";
    return true;
  }
  return true;
}

bool CloudChannel::ReceiveMessage(google::protobuf::Message *m,
                                     bool *eof) {
  string serialized;
  if (!ReceiveFrame(CLOUD_CHANNEL_FRAME_WRAPPED_MESSAGE, &serialized, eof)) {
    LOG(ERROR) << "Could not receive wrapped message";
    return false;
  } else if (*eof) {
    // LOG(WARNING) << "Connection has unexpectedly closed";
    return true;
  }
  if (!m->ParseFromString(serialized)) {
    LOG(ERROR) << "Could not unwrap message";
    Close();
    return false;
  }
  return true;
}

bool CloudChannel::Abort(const string &msg) {
  LOG(INFO) << "Aborting connection";
  bool success = SendFrame(CLOUD_CHANNEL_FRAME_ABORT, msg);
  Close();
  return success;
}

bool CloudChannel::Disconnect() {
  LOG(INFO) << "Disconnecting";
  bool success = SendFrame(CLOUD_CHANNEL_FRAME_SHUTDOWN, "" /* empty message */);
  if (success) {
    string msg;
    bool eof;
    success = ReceiveFrame(CLOUD_CHANNEL_FRAME_SHUTDOWN_RESPONSE, &msg, &eof) && !eof;
  }
  Close();
  return success;
}

}  // namespace cloudproxy
