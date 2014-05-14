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
#include "tao/linux_process_factory.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/resource.h>
#include <wait.h>

#include <algorithm>

#include <glog/logging.h>

#include "tao/pipe_factory.h"
#include "tao/tao_rpc.h"
#include "tao/util.h"

namespace tao {
bool LinuxProcessFactory::MakeHostedProgramSubprin(int id, const string &path,
                                                   string *subprin) const {
  // TODO(kwalsh) Nice toc-tou error here... maybe copy binary to temp file?
  string prog_hash;
  if (!Sha256FileHash(path, &prog_hash)) {
    LOG(ERROR) << "Could not compute the program digest";
    return false;
  }
  subprin->assign(FormatHostedProgramSubprin(id, bytesToHex(prog_hash)));
  return true;
}

bool LinuxProcessFactory::StartHostedProgram(
    const PipeFactory &child_channel_factory, const string &path,
    const list<string> &args, const string &subprin,
    scoped_ptr<HostedLinuxProcess> *child) const {

  scoped_ptr<FDMessageChannel> channel_to_parent, channel_to_child;
  if (!child_channel_factory.CreateChannelPair(&channel_to_parent,
                                                &channel_to_child)) {
    LOG(ERROR) << "Could not create channel for hosted program";
    return false;
  }

  string child_channel_params;
  if (!channel_to_parent->SerializeToString(&child_channel_params)) {
    LOG(ERROR) << "Could not encode child channel parameters";
    return false;
  }
  child_channel_params = "tao::TaoRPC+" + child_channel_params;
  VLOG(0) << "Channel to parent is: " << child_channel_params;

  int child_pid = fork();
  if (child_pid == -1) {
    LOG(ERROR) << "Could not fork hosted program";
    return false;
  }

  if (child_pid == 0) {
    int argc = 1 + (int)args.size(); // 1+ for path at start
    char **argv = new char *[argc + 1];  // +1 for null at end
    int i = 0;
    argv[i++] = strdup(path.c_str());
    for (const string &arg : args) {
      argv[i++] = strdup(arg.c_str());
    }
    argv[i++] = nullptr;
    // We couuld put channel params in argv:
    // argv[..] = strdup(child_channel_params.c_str());
    // Instead, put it in environment variable so we can host Tao-oblivious
    // programs without messing up their argv...
    setenv(Tao::HostedProcessChannelEnvVar, child_channel_params.c_str(), 1);

    channel_to_child->Close();

    close(STDIN_FILENO);
    dup2(open("/dev/null", O_RDONLY), STDIN_FILENO);

    list<int> keep_open;
    if (!channel_to_parent->GetFileDescriptors(&keep_open)) {
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

    // Become process group leader.
    setpgrp();

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
    (*child)->subprin = subprin;
    (*child)->pid = child_pid;
    (*child)->rpc_channel.reset(channel_to_child.release());
    LOG(INFO) << "Started PID " << child_pid << "for " << subprin;
    return true;
  }
}

bool LinuxProcessFactory::StopHostedProgram(HostedLinuxProcess *child,
                                            int signum) const {
  if (child->pid <= 0)
    return false;  // already dead or invalid PID
  if (kill(-1 * child->pid, signum) < 0) {
    PLOG(ERROR) << "Could not stop hosted program with PID " << child->pid;
    return false;
  }
  LOG(INFO) << "Sent signal " << signum << " to hosted program with PID "
            << child->pid;
  return true;
}

int LinuxProcessFactory::WaitForHostedProgram() const {
  int status;
  int pid = waitpid(-1, &status, WNOHANG);
  if (pid == 0) {
    // There are children, but they haven't exited.
  } else if (pid == -1) {
    // There are no children.
  } else if (WIFEXITED(status)) {
    LOG(INFO) << "Hosted process with PID " << pid << " has exited";
  } else if (WIFSIGNALED(status)) {
    LOG(INFO) << "Hosted process with PID " << pid << " has been killed";
  } else {
    LOG(INFO) << "Hosted process with PID " << pid
              << " died for unknown reasons";
  }
  return pid;
}

// TODO(kwalsh) Replace this with formula formatting routines
string LinuxProcessFactory::FormatHostedProgramSubprin(
    int id, const string &prog_hash) const {
  stringstream out;
  if (id != 0)
    out << "Process(" << id << ", ";
  else
    out << "Program(";
  out << quotedString(prog_hash) << ")";
  return out.str();
}

// TODO(kwalsh) Replace this with formula parsing routines
bool LinuxProcessFactory::ParseHostedProgramSubprin(const string &subprin,
                                                    int *id, string *prog_hash,
                                                    string *extension) const {
  stringstream in(subprin);
  if (subprin.substr(0, 8) == "Program(") {
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

  string rest;
  if (in && getline(in, rest, '\0') && rest != "") {
    stringstream in_rest(rest);
    skip(in_rest, "::");
    string ext;
    getline(in_rest, ext, '\0');
    extension->assign(ext);
  } else {
    extension->assign("");
  }

  if (in.bad()) {
    LOG(ERROR) << "Could not parse hosted program subprincipal: " << subprin;
    return false;
  }

  return true;
}

static bool CloseExcept(int fd, const list<int> &keep_open) {
  if (std::find(keep_open.begin(), keep_open.end(), fd) != keep_open.end()) {
    return true;
  } else if (close(fd) < 0 && errno != EBADF) {
    PLOG(ERROR) << "Could not close fd " << fd;
    return false;
  } else {
    return true;
  }
}

bool LinuxProcessFactory::CloseAllFileDescriptorsExcept(const list<int> &keep_open)
{
  DIR *dir = opendir("/proc/self/fd");
  int dir_fd = dirfd(dir);
  if (dir != nullptr) {
    struct dirent *entry;
    while ((entry = readdir(dir)) != nullptr) {
      if (entry->d_name[0] == '.') continue;
      char *end = nullptr;
      errno = 0;
      long n = strtol(entry->d_name, &end, 10);
      if (errno != 0) {
        PLOG(ERROR) << "Error enumerating /proc/self/fd";
        closedir(dir);
        return false;
      } else if (end == nullptr || end == entry->d_name || end[0] != '\0' ||
                 n < 0 || n > INT_MAX) {
        LOG(ERROR) << "Error enumerating /proc/self/fd";
        closedir(dir);
        return false;
      }
      int fd = static_cast<int>(n);
      if (fd != dir_fd && !CloseExcept(fd, keep_open)) {
        closedir(dir);
        return false;
      }
    }
    closedir(dir);
    return true;
  } else {
    struct rlimit limits;
    if (getrlimit(RLIMIT_NOFILE, &limits) < 0) {
      LOG(ERROR) << "Could not get rlimits";
      return false;
    }
    for (int fd = 0; fd < static_cast<int>(limits.rlim_max); fd++) {
      if (fd != dir_fd && !CloseExcept(fd, keep_open)) {
        closedir(dir);
        return false;
      }
    }
    return true;
  }
}

}  // namespace tao
