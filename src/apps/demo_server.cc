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
  printf("demo server: Authenticated connection from %s\n", peer.c_str());
  for (;;) {
    bool eof;
    DemoServerMessage req, resp;
    if (!chan->ReceiveMessage(&req, &eof)) {
      printf("demo server: Lost connection from %s\n", peer.c_str());
      return false;
    }
    if (eof) {
      printf("demo server: Connection closed by %s\n", peer.c_str());
      return true;
    }
    printf("demo server: Peer %s says %s\n", peer.c_str(), req.msg().c_str());
    resp.set_msg("Echo(" + quotedString(req.msg()) + ")");
    if (!chan->SendMessage(resp)) {
      printf("demo server: Lost connection to %s\n", peer.c_str());
      return false;
    }
  }
}

class DemoClient : public CloudClient {
 public:
  DemoClient() : CloudClient() {}
  virtual bool Send(const string &msg);
  virtual bool Goodbye();

 private:
  DISALLOW_COPY_AND_ASSIGN(DemoClient);
};

bool DemoClient::Send(const string &msg) {
  printf("demo client: Sending: %s\n", msg.c_str());
  DemoServerMessage req, resp;
  req.set_msg(msg);
  CHECK(Channel()->SendMessage(req));
  bool eof;
  CHECK(Channel()->ReceiveMessage(&resp, &eof));
  CHECK(!eof);
  printf("demo client: Response: %s\n", resp.msg().c_str());
  return true;
}

bool DemoClient::Goodbye() {
  printf("demo client: Hanging up\n");
  CHECK(Channel()->Disconnect());
  return true;
}

int main(int argc, char **argv) {
  string usage = "Demo client/server for CloudProxy.\nUsage:\n  ";
  google::SetUsageMessage(usage + argv[0] + " [options]");
  tao::InitializeApp(&argc, &argv, true);
  Tao *tao = Tao::GetHostTao();
  CHECK(tao != nullptr);

  if (FLAGS_client) {
    CHECK(tao->ExtendTaoName("Mode(\"client\")"));
    string self;
    CHECK(tao->GetTaoName(&self));
    printf("demo client: Running as %s\n", shorten(self).c_str());
    DemoClient demo;
    CHECK(demo.Init());
    CHECK(demo.Connect("localhost", "7777"));
    CHECK(demo.Send("Hello World"));
    CHECK(demo.Send("Thanks for all the fish"));
    CHECK(demo.Goodbye());
    CHECK(demo.Close());
  } else {
    CHECK(tao->ExtendTaoName("Mode(\"server\")"));
    string self;
    CHECK(tao->GetTaoName(&self));
    printf("demo server: Running as %s\n", shorten(self).c_str());
    DemoServer demo;
    CHECK(demo.Init());
    CHECK(demo.Listen());
  }
  return 0;
}
