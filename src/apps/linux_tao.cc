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

#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "tao/linux_host.h"
#include "tao/tao.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

using std::string;

using tao::InitializeApp;
using tao::LinuxHost;
using tao::TaoDomain;
using tao::Tao;

static constexpr auto defaultHost = "TPMTao(\"file:tpm/aikblob\", \"17, 18\")";

DEFINE_string(config_path, "tao.config", "Location of tao domain configuration");
DEFINE_string(host_path, "linux_tao_keys", "Location of linux host configuration");
DEFINE_string(tao_host, "",
              "Parameters to connect to host Tao. If empty try env "
              " or use a TPM default instead.");

int main(int argc, char **argv) {
  InitializeApp(&argc, &argv, true);

  if (!FLAGS_tao_host.empty()) {
    setenv(Tao::HostTaoEnvVar, FLAGS_tao_host.c_str(), 1 /* overwrite */);
  } else {
    setenv(Tao::HostTaoEnvVar, defaultHost, 0 /* no overwrite */);
  }

  Tao *tao = Tao::GetHostTao();
  CHECK(tao != nullptr) << "Could not connect to host Tao";

  scoped_ptr<TaoDomain> admin(TaoDomain::Load(FLAGS_config_path));
  CHECK(admin.get() != nullptr) << "Could not load configuration";

  scoped_ptr<LinuxHost> host(new LinuxHost(tao, admin.release(), FLAGS_host_path));
  CHECK(host->Init());

  LOG(INFO) << "LinuxHost Service: " << host->DebugString();
  LOG(INFO) << "Linux Tao Service started and waiting for requests";

  CHECK(host->Listen());

  return 0;
}
