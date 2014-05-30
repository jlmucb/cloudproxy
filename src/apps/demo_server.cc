//  File: echo_server.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: A demo CloudServer/CloudClient application.
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
#include <cstdio>
#include <sstream>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "apps/demo_server.pb.h"
#include "cloudproxy/cloud_channel.h"
#include "cloudproxy/cloud_client.h"
#include "cloudproxy/cloud_server.h"
#include "tao/tao.h"
#include "tao/trivial_guard.h"
#include "tao/util.h"

using std::string;

using cloudproxy::CloudChannel;
using cloudproxy::CloudClient;
using cloudproxy::CloudServer;
using tao::Tao;
using tao::TrivialGuard;
using tao::elideString;
using tao::quotedString;

DEFINE_bool(raw, false, "Show raw, non-elided output");

DEFINE_bool(client, false, "Run as client instead of server");

string shorten(string s) { return (FLAGS_raw ? s : elideString(s)); }

class DemoServer : public CloudServer {
 public:
  DemoServer()
      : CloudServer("localhost", "7777",
                    new TrivialGuard(TrivialGuard::LiberalPolicy)) {}
  virtual bool HandleAuthenticatedConnection(CloudChannel *chan);

 private:
  DISALLOW_COPY_AND_ASSIGN(DemoServer);
};

bool DemoServer::HandleAuthenticatedConnection(CloudChannel *chan) {
  string peer = shorten(chan->PeerName());
  printf("Authenticated connection from %s\n", peer.c_str());
  for (;;) {
    bool eof;
    DemoServerMessage m;
    if (!chan->ReceiveMessage(&m, &eof)) {
      printf("Lost connection from %s\n", peer.c_str());
      return false;
    }
    if (eof) {
      printf("Closing connection to %s\n", peer.c_str());
      return true;
    }
    printf("Peer %s says %s\n", peer.c_str(), m.msg().c_str());
    m.set_msg("Echo(" + quotedString(m.msg()) + ")");
    if (!chan->SendMessage(m)) printf("Lost connection to %s\n", peer.c_str());
    return false;
  }
}

class DemoClient : public CloudClient {
 public:
  DemoClient() : CloudClient() {}
  virtual bool Send(const string &msg);

 private:
  DISALLOW_COPY_AND_ASSIGN(DemoClient);
};

bool DemoClient::Send(const string &msg) {
  printf("Sending: %s\n", msg.c_str());
  DemoServerMessage m;
  m.set_msg(msg);
  CHECK(Channel()->SendMessage(m));
  bool eof;
  CHECK(Channel()->ReceiveMessage(&m, &eof));
  CHECK(!eof);
  printf("Response: %s\n", m.msg().c_str());
  return true;
}

int main(int argc, char **argv) {
  tao::InitializeApp(&argc, &argv, true);
  Tao *tao = Tao::GetHostTao();
  CHECK(tao != nullptr);

  if (FLAGS_client) {
    CHECK(tao->ExtendTaoName("Mode(\"client\")"));
    string self;
    CHECK(tao->GetTaoName(&self));
    printf("Demo client running as %s\n", shorten(self).c_str());
    DemoClient demo;
    CHECK(demo.Init());
    CHECK(demo.Connect("localhost", "7777"));
    CHECK(demo.Send("Hello World"));
    CHECK(demo.Send("Thanks for all the fish"));
    // CHECK(demo->Channel->Disconnect());
    CHECK(demo.Close());
  } else {
    CHECK(tao->ExtendTaoName("Mode(\"server\")"));
    string self;
    CHECK(tao->GetTaoName(&self));
    printf("Demo server running as %s\n", shorten(self).c_str());
    DemoServer demo;
    CHECK(demo.Init());
    CHECK(demo.Listen());
  }
  return 0;
}
