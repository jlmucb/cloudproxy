//  File: linux_tao.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A Tao host for Linux that creates child processes.
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
#include <cstdio>
#include <list>
#include <utility>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "tao/linux_admin_rpc.h"
#include "tao/linux_host.h"
#include "tao/tao.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using std::list;
using std::pair;
using std::string;

using tao::InitializeApp;
using tao::LinuxAdminRPC;
using tao::LinuxHost;
using tao::Tao;
using tao::TaoDomain;
using tao::elideString;

DEFINE_string(config_path, "tao.config",
              "Location of tao domain configuration");
DEFINE_string(path, "linux_tao_host", "Location of linux host configuration");
DEFINE_string(pass, "", "Password for unlocking keys if running in root mode");

DEFINE_bool(create, false, "Create a new LinuxHost service.");
DEFINE_bool(show, false, "Show principal name for LinuxHost service.");
DEFINE_bool(service, false, "Start the LinuxHost service.");
DEFINE_bool(shutdown, false, "Shut down the LinuxHost service.");

DEFINE_bool(run, false, "Start a hosted program (path and args follow --).");
DEFINE_bool(list, false, "List hosted programs.");
DEFINE_bool(stop, false, "Stop a hosted program (names follow --) .");
DEFINE_bool(kill, false, "Kill a hosted program (names follow --) .");
DEFINE_bool(name, false, "Show the principal name of running LinuxHost.");

int main(int argc, char **argv) {
  string usage = "Administrative utility for LinuxHost.\nUsage:\n";
  string tab = "  ";
  usage += tab + argv[0] + " [options] --create\n";
  usage += tab + argv[0] + " [options] --show\n";
  usage += tab + argv[0] + " [options] --service\n";
  usage += tab + argv[0] + " [options] --shutdown\n";
  usage += tab + argv[0] + " [options] --run -- program args...\n";
  usage += tab + argv[0] + " [options] --stop -- name...\n";
  usage += tab + argv[0] + " [options] --kill -- name...\n";
  usage += tab + argv[0] + " [options] --list\n";
  usage += tab + argv[0] + " [options] --name";
  google::SetUsageMessage(usage);
  InitializeApp(&argc, &argv, true);

  int ncmds = FLAGS_service + FLAGS_shutdown + FLAGS_name + FLAGS_run +
              FLAGS_list + FLAGS_kill + FLAGS_stop;
  if (ncmds > 1) {
    fprintf(stderr, "Error: Specify one of the command options\n");
    return 1;
  }

  if (FLAGS_create || FLAGS_service || FLAGS_show) {
    scoped_ptr<TaoDomain> admin(TaoDomain::Load(FLAGS_config_path));
    CHECK(admin.get() != nullptr) << "Could not load configuration";

    scoped_ptr<LinuxHost> host(new LinuxHost(admin.release(), FLAGS_path));

    Tao *host_tao = Tao::GetHostTao();
    if (host_tao == nullptr) {
      if (FLAGS_pass.empty()) {
        fprintf(stderr, "Error: Host tao not found, no password specified\n");
        return 1;
      }
      CHECK(host->InitRoot(FLAGS_pass)) << "Could not initialize root Tao host";
    } else {
      CHECK(host->InitStacked(host_tao))
          << "Could not initialize stacked Tao host";
    }

    if (FLAGS_show) {
      printf("export GOOGLE_TAO_LINUX='%s'\n", host->TaoHostName().c_str());
    } else {
      printf("LinuxHost Service: %s\n", host->DebugString().c_str());
    }
    if (FLAGS_service) {
      printf("Linux Tao Service started and waiting for requests\n");
      ;
      CHECK(host->Listen()) << "TaoHost main loop failed";
    }
  } else {
    scoped_ptr<LinuxAdminRPC> host(LinuxHost::Connect(FLAGS_path));
    CHECK(host.get() != nullptr) << "Could not connect to Tao host";

    string name;
    CHECK(host->GetTaoHostName(&name))
        << "Could not get Tao host name: " << host->GetRecentErrorMessage();

    if (FLAGS_shutdown) {
      CHECK(host->Shutdown())
          << "Could not shut down Tao host: " << host->GetRecentErrorMessage();
      printf("Shutdown: %s\n", elideString(name).c_str());
    } else if (FLAGS_run) {
      if (argc < 2) {
        fprintf(stderr, "No path or arguments given");
        return 1;
      }
      string prog = argv[1];
      list<string> args;
      for (int i = 2; i < argc; i++) {
        args.push_back(string(argv[i]));
      }

      string child_name;
      CHECK(host->StartHostedProgram(prog, args, &child_name))
          << "Could not start hosted program: "
          << host->GetRecentErrorMessage();

      printf("Started: %s\n", child_name.c_str());
      printf("LinuxHost: %s\n", elideString(name).c_str());
    } else if (FLAGS_kill || FLAGS_stop) {
      if (argc < 2) {
        fprintf(stderr, "No names given");
        return 1;
      }
      for (int i = 1; i < argc; i++) {
        if (FLAGS_kill) {
          CHECK(host->KillHostedProgram(argv[i]))
              << "Could not kill hosted program: "
              << host->GetRecentErrorMessage();
          printf("Killed: %s\n", argv[i]);
        } else {
          CHECK(host->StopHostedProgram(argv[i]))
              << "Could not stop hosted program: "
              << host->GetRecentErrorMessage();
          printf("Requested stop: %s\n", argv[i]);
        }
      }
    } else if (FLAGS_list) {
      list<pair<string, int>> child_info;
      CHECK(host->ListHostedPrograms(&child_info))
          << "Could not get list of hosted programs: "
          << host->GetRecentErrorMessage();
      printf("LinuxHost: %s\n", elideString(name).c_str());
      printf("Hosts %lu programs:", child_info.size());
      for (auto &info : child_info) {
        printf(" PID %d subprin ::%s\n", info.second, info.first.c_str());
      }
    } else if (FLAGS_name) {
      printf("%s\n", name.c_str());  // show full name here
    } else {
      printf("LinuxHost: %s\n", elideString(name).c_str());
    }
  }

  return 0;
}
