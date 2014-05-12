//  File: process_factory.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A factory that creates child processes.
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

#include <glog/logging.h>

#include "tao/pipe_factory.h"
#include "tao/util.h"

namespace tao {
bool LinuxProcessFactory::MakeHostedProgramSubprin(int id, const string &path,
                                                   string *subprin) const {
  // TODO(kwalsh) Nice toc-tou error here... maybe copy binary to temp file?
  string prog_digest;
  if (!Sha256FileHash(path, &prog_digest)) {
    LOG(ERROR) << "Could not compute the program digest";
    return false;
  }
  string prog_hash;
  if (!bytesToHex(prog_digest, &prog_hash)) {
    LOG(ERROR) << "Could not encode the digest as Base64W";
    return false;
  }
  subprin->assign(FormatHostedProgramSubprin(id, prog_hash));
  return true;
}

bool LinuxProcessFactory::StarteHostedProgram(
    const PipeFactory &child_channel_factory, const string &path,
    const list<string> &args, const string &subprin,
    scoped_ptr<HostedLinuxProcess> *child) const {

  scoped_ptr<FDMessageChannel> channel_to_parent, channel_to_child;
  if (!child_channel_factory->CreateChannelPair(&channel_to_parent,
                                                &channel_to_child)) {
    LOG(ERROR) << "Could not create channel for hosted program";
    return false;
  }

  string child_channel_params;
  if (!channel_to_parent->SerializeToString(&child_channel_params)) {
    LOG(ERROR) << "Could not encode child channel parameters";
    return false;
  }

  int child_pid = fork();
  if (child_pid == -1) {
    LOG(ERROR) << "Could not fork hosted program";
    return false;
  }

  if (child_pid == 0) {
    int argc = 1 + (int)args.size() + 1;
    char **argv = new char *[argc + 1];  // +1 for null at end
    int i = 0;
    argv[i++] = strdup(path.c_str());
    for (const string &arg : args) {
      argv[i++] = strdup(arg.c_str());
    }
    // TODO(kwalsh) maybe put channel_params in env instead?
    argv[i++] = strdup(child_channel_params.c_str());
    argv[i++] = nullptr;

    channel_to_child->Close();

    close(STDIN_FILENO);
    dup2(open("/dev/null", O_RDONLY), STDIN_FILENO);

    list<int> keep_open;
    if (!channel_to_parent->GetFileDescriptors(&keep-open)) {
      LOG(ERROR) << "Could not get file descriptors for channel to parent";
      exit(1);
      /* never reached */
    }
    keep_open.push_back(STDIN_FILENO);
    keep_open.push_back(STDOUT_FILENO);
    keep_open.push_back(STDERR_FILENO);
    if (!CloseAllFileDescriptorsExcept(keep_open)) {
      LOG(ERROR) << "Could not clean up file descriptors";
      exit(1);
      /* never reached */
    }

    int rv = execv(path.c_str(), argv);
    if (rv == -1) {
      PLOG(ERROR) << "Could not exec " << path;
      exit(1);
    }
    /* never reached */
    CHECK(false);
    return false;
  } else {
    channel_to_parent->Close();

    child->reset(new HostedLinuxProcess);
    child->subprin = subprin;
    child->pid = child_pid;
    child->channel.reset(new TaoRPC(channel_to_child.release()));
    return true;
  }
}

// TODO(kwalsh) Replace this with formula formatting routines
string LinuxProcessFactory::FormatHostedProgramSubprin(int id,
                                                  const string &prog_hash) {
  stringstream out;
  if (id != 0)
    out << "Process(" << id << ", ";
  else
    out << "Program(";
  out << quotedString(prog_hash) << ")";
  return out.str();
}

// TODO(kwalsh) Replace this with formula parsing routines
bool LinuxProcessFactory::ParseHostedProgramSubprin(string subprin, int *id,
                                               string *prog_hash,
                                               string *extension) const {
  stringstream in(subprin);
  if (subprin.substr(0, 8, "Program(")) {
    skip(in, "Program(");
    *id = 0;
    getQuotedString(in, prog_hash);
    skip(in, ")");
  } else {
    skip(in, "Process(");
    in >> *id;
    skip(in, ", ");
    getQuotedString(in, prog_hash);
    skip(in, ")");
  }

  string remaining;
  if (in && getline(in, remaining, '\0') && remaining != "") {
    in.str(remaining);
    skip(in, "::");
    getline(in, remaining, '\0');
    extension->assign(remaining);
  } else {
    extension->assign("");
  }

  if (in.bad()) {
    LOG(ERROR) << "Could not parse hosted program subprincipal: " << subprin;
    return false;
  }

  return true;
}

bool LinuxProcessFactory::CloseAllFileDescriptorsExcept(const list<int> keep_open)
{
  struct rlimit rl;
  int fd;
#ifdef __linux__
  DIR *d;
  assert(except_fds);
  if ((d = opendir("/proc/self/fd"))) {
    struct dirent *de;
        while ((de = readdir(d))) {
          int found;
          long l;
          char *e = NULL;
          int i;
      if (de->d_name[0] == '.') continue;
      errno = 0;
      l = strtol(de->d_name, &e, 10);
      if (errno != 0 || !e || *e) {
        closedir(d);
        errno = EINVAL;
        return -1;
      }
      fd = (int)l;
      if ((long)fd != l) {
        closedir(d);
        errno = EINVAL;
        return -1;
      }
      if (fd < 3) continue;
      if (fd == dirfd(d)) continue;
      found = 0;
      for (i = 0; except_fds[i] >= 0; i++)
        if (except_fds[i] == fd) {
          found = 1;
          break;
        }
      if (found) continue;
      if (close(fd) < 0) {
        int saved_errno;
        saved_errno = errno;
        closedir(d);
        errno = saved_errno;
        return -1;
      }
    }
    closedir(d);
    return 0;
  }
#endif
  if (getrlimit(RLIMIT_NOFILE, &rl) < 0) return -1;
  for (fd = 0; fd < (int)rl.rlim_max; fd++) {
    int i;
    if (fd <= 3) continue;
    for (i = 0; except_fds[i] >= 0; i++)
      if (except_fds[i] == fd) continue;
    if (close(fd) < 0 && errno != EBADF) return -1;
  }
  return 0;
}

}  // namespace tao
