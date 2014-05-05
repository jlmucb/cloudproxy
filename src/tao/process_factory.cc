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

#include <sstream>

#include <glog/logging.h>
#include <keyczar/base/base64w.h>
#include <keyczar/base/file_util.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/keyczar.h>

#include "tao/hosted_programs.pb.h"
#include "tao/tao_channel.h"
#include "tao/util.h"

using std::stringstream;

using keyczar::CryptoFactory;
using keyczar::MessageDigestImpl;
using keyczar::base::Base64WEncode;
using keyczar::base::ReadFileToString;

namespace tao {
bool ProcessFactory::GetHostedProgramTentativeName(
    int id, const string &path, const list<string> &args,
    string *tentative_child_name) const {

  // TODO(kwalsh) Nice toc-tou error here...
  string program_buf;
  if (!ReadFileToString(path, &program_buf)) {
    LOG(ERROR) << "Could not read program " << path;
    return false;
  }

  MessageDigestImpl *sha256 = CryptoFactory::SHA256();
  string prog_digest;
  if (!sha256->Digest(program_buf, &prog_digest)) {
    LOG(ERROR) << "Could not compute the digest over the file";
    return false;
  }

  string prog_hash;
  if (!Base64WEncode(prog_digest, &prog_hash)) {
    LOG(ERROR) << "Could not encode the digest as Base64W";
    return false;
  }

  // TODO(kwalsh) child can do this instead
  HostedProgramArgs argbuf;
  for (const string &arg : args) {
    argbuf.add_args(arg);
  }

  string serialized_args;
  if (!argbuf.SerializeToString(&serialized_args)) {
    LOG(ERROR) << "Could not serialize the arguments";
    return false;
  }

  string args_digest;
  if (!sha256->Digest(serialized_args, &args_digest)) {
    LOG(ERROR) << "Could not compute the digest over the args";
    return false;
  }

  string args_hash;
  if (!Base64WEncode(args_digest, &args_hash)) {
    LOG(ERROR) << "Could not encode the args digest as Base64W";
    return false;
  }

  tentative_child_name->assign(
      CreateChildName(id, path, prog_hash, args_hash, "" /* no pid yet */));

  return true;
}

bool ProcessFactory::CreateHostedProgram(int id, const string &name,
                                         const list<string> &args,
                                         const string &tentative_child_name,
                                         TaoChannel *parent_channel,
                                         string *child_name) const {
  int child_pid = fork();
  if (child_pid == -1) {
    LOG(ERROR) << "Could not fork";
    return false;
  }

  if (child_pid == 0) {
    // one more for the name of the program in argv[0]
    int argc = (int)args.size() + 1;

    // one more for the null at the end
    char **argv = new char *[argc + 1];
    argv[0] = strdup(name.c_str());
    int i = 1;
    for (const string &v : args) {
      argv[i++] = strdup(v.c_str());
    }

    argv[i] = nullptr;

    // clean up handles, and drop privileges by extending name
    stringstream out;
    out << "PID(" << int(getpid()) << ")";
    string subprin = out.str();
    parent_channel->ChildCleanup(argv[argc - 1],
                                 subprin);  // last argv is channel params

    int rv = execv(name.c_str(), argv);
    if (rv == -1) {
      LOG(ERROR) << "Could not exec " << name;
      perror("The error was: ");
      return false;
    }
  } else {
    parent_channel->ParentCleanup(tentative_child_name);
    // Use pid as subprin, child will extend with it after fork, before exec.
    stringstream out;
    out << "PID(" << child_pid << ")";
    string subprin = out.str();
    child_name->assign(tentative_child_name + "::" + subprin);
  }

  return true;
}

string ProcessFactory::GetFactoryName() const { return "ProcessFactory"; }

// TODO(kwalsh) This will be replaced with more generic formula / logic routines
string ProcessFactory::CreateChildName(int id, const string &path,
                                       const string &prog_hash,
                                       const string &arg_hash,
                                       string pid) const {
  stringstream out;
  out << "Program(" << id << ", ";
  out << quotedString(path) << ", ";
  out << quotedString(prog_hash) << ", ";
  out << quotedString(arg_hash) << ")";
  if (!pid.empty()) out << "::PID(" << pid << ")";
  return out.str();
}

bool ProcessFactory::ParseChildName(string child_name, int *id, string *path,
                                    string *prog_hash, string *arg_hash,
                                    string *pid, string *subprin) const {
  stringstream in(child_name);

  skip(in, "Program(");
  in >> *id;
  skip(in, ", ");
  getQuotedString(in, path);
  skip(in, ", ");
  getQuotedString(in, prog_hash);
  skip(in, ", ");
  getQuotedString(in, arg_hash);
  skip(in, ")");

  string remaining;
  if (in && getline(in, remaining, '\0') && in && remaining != "") {
    in.str(remaining);
    skip(in, "::");
    skip(in, "PID(");
    int i;
    in >> i;
    skip(in, ")");
    stringstream out;
    out << i;
    pid->assign(out.str());
  } else {
    pid->assign("");
  }

  if (in && getline(in, remaining, '\0') && in && remaining != "") {
    in.str(remaining);
    skip(in, "::");
    getline(in, remaining, '\0');
    subprin->assign(remaining);
  } else {
    subprin->assign("");
  }

  if (in.bad()) {
    LOG(ERROR) << "Bad child name: " << child_name;
    return false;
  }

  return true;
}

}  // namespace tao
