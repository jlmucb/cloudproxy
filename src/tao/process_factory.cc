//  File: process_factory.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An implementation of the hosted program factory that creates
//  processes.
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

#include "tao/process_factory.h"

#include <fstream>
#include <sstream>
#include <vector>

#include <glog/logging.h>
#include <keyczar/base/base64w.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/keyczar.h>

#include "tao/tao_channel.h"

using keyczar::base::Base64WEncode;
using keyczar::CryptoFactory;
using keyczar::MessageDigestImpl;

using std::ifstream;
using std::stringstream;
using std::vector;

namespace tao {
bool ProcessFactory::HashHostedProgram(const string &name,
                                       const list<string> &args,
                                       string *child_hash) const {
  ifstream program_stream(name.c_str());
  stringstream program_buf;
  program_buf << program_stream.rdbuf();

  // TODO(tmroeder): take in the right hash type and use it here. For
  // now, we just assume that it's SHA256
  MessageDigestImpl *sha256 = CryptoFactory::SHA256();
  string digest;
  if (!sha256->Digest(program_buf.str(), &digest)) {
    LOG(ERROR) << "Could not compute the digest over the file";
    return false;
  }

  if (!Base64WEncode(digest, child_hash)) {
    LOG(ERROR) << "Could not encode the digest as Base64W";
    return false;
  }

  return true;
}

bool ProcessFactory::CreateHostedProgram(const string &name,
                                         const list<string> &args,
                                         const string &child_hash,
                                         TaoChannel &parent_channel) const {
  int child_pid = fork();
  if (child_pid == -1) {
    LOG(ERROR) << "Could not fork";
    return false;
  }

  if (child_pid == 0) {
    parent_channel.ChildCleanup(child_hash);

    // one more for the name of the program in argv[0]
    int argc = (int)args.size() + 1;

    // one more for the NULL at the end
    char **argv = new char *[argc + 1];
    argv[0] = strdup(name.c_str());
    int i = 1;
    for (const string &v : args) {
      argv[i++] = strdup(v.c_str());
    }

    argv[i] = NULL;

    int rv = execv(name.c_str(), argv);
    if (rv == -1) {
      LOG(ERROR) << "Could not exec " << name;
      perror("The error was: ");
      return false;
    }
  } else {
    parent_channel.ParentCleanup(child_hash);
  }

  return true;
}

string ProcessFactory::GetFactoryName() const { return "ProcessFactory"; }
}  // namespace tao
