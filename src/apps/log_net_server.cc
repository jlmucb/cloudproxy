//  File: log_server.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Simple TCP-based log sink for google logging.
//
//  Copyright (c) 2014, Google Inc.  All rights reserved.
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
#include <signal.h>

#include <cstdio>
#include <list>
#include <map>
#include <memory>
#include <string>

#include <gflags/gflags.h>

#include "tao/fd_message_channel.h"
#include "tao/log_net.pb.h"
#include "tao/util.h"

using std::list;
using std::map;
using std::string;

using tao::FDMessageChannel;
using tao::FilePath;
using tao::GetSelfPipeSignalFd;
using tao::LogMessage;
using tao::OpenTCPSocket;
using tao::ScopedSelfPipeFd;

DEFINE_string(host, "localhost", "Host to listen at");
DEFINE_string(port, "5514", "Port to listen on");

DEFINE_bool(color, true, "Print in color");
// DEFINE_bool(raw, false, "Print raw messages");

const int MaxMessage = 1000;

const char *colors[] = {"\033[01;32m", "\033[01;33m", "\033[01;36m",
                        "\033[01;35m"};
constexpr auto color_reset = "\033[00m";

void show(int fd, LogMessage msg, map<int, string> *client_names) {
  auto it = client_names->find(fd);
  if (it == client_names->end()) {
    string name = msg.message();
    (*client_names)[fd] = name;
    printf("- %s %s\n", name.c_str(), "start");
    return;
  }
  string name = it->second;
  int severity = msg.severity();
  if (severity < 0)
    severity = 0;
  else if (severity > 3)
    severity = 3;
  string color = (FLAGS_color ? colors[severity] : "");
  string reset = (FLAGS_color ? color_reset : "");
  FilePath path(msg.base_filename());
  string filename = path.DirName().BaseName().Append(path.BaseName()).value();
  printf("%s%c %s%s %02d:%02d:%02d %s:%d %s%s%s\n", color.c_str(),
         "IWEF"[severity], name.c_str(), reset.c_str(), msg.time().tm_hour(),
         msg.time().tm_min(), msg.time().tm_sec(), filename.c_str(), msg.line(),
         color.c_str(), msg.message().c_str(), reset.c_str());
}

void closed(int fd, const string &msg, map<int, string> *client_names) {
  auto it = client_names->find(fd);
  string name;
  if (it == client_names->end()) {
    name = "? ?";
  } else {
    name = it->second;
    client_names->erase(it);
  }
  printf("- %s %s\n", name.c_str(), msg.c_str());
}

int main(int argc, char **argv) {
  string usage = "Listen for google log messages.\nUsage:\n  ";
  google::SetUsageMessage(usage + argv[0] + " [options]");
  google::ParseCommandLineFlags(&argc, &argv, true /* remove args */);

  int sock;
  if (!OpenTCPSocket(FLAGS_host, FLAGS_port, &sock)) {
    fprintf(stderr, "Could not listen at %s:%s\n", FLAGS_host.c_str(),
            FLAGS_port.c_str());
    return 1;
  }

  // When we get SIGTERM, we do a graceful shutdown.
  // Also, restart system calls interrupted by this signal if possible.
  ScopedSelfPipeFd stop_fd(new int(GetSelfPipeSignalFd(SIGTERM, SA_RESTART)));
  if (*stop_fd < 0) {
    fprintf(stderr, "Could not create SIGTERM self-pipe\n");
    return 1;
  }

  list<std::unique_ptr<FDMessageChannel>> clients;
  map<int, string> client_names;

  printf("== log messages for %s:%s ==\n", FLAGS_host.c_str(),
         FLAGS_port.c_str());

  if (FLAGS_color) {
    printf("%sI=INFO %sW=WARNING %sE=ERROR %sF=FATAL%s\n", colors[0], colors[1],
           colors[2], colors[3], color_reset);
  } else {
    printf("I=INFO, W=WARNING, E=ERROR, F=FATAL\n");
  }

  bool graceful_shutdown = false;
  while (!graceful_shutdown) {
    fd_set read_fds;
    FD_ZERO(&read_fds);
    int fd, max_fd = 0;

    fd = *stop_fd;
    FD_SET(fd, &read_fds);
    if (fd > max_fd) max_fd = fd;

    fd = sock;
    FD_SET(fd, &read_fds);
    if (fd > max_fd) max_fd = fd;

    for (auto &client : clients) {
      fd = client->GetReadFileDescriptor();
      FD_SET(fd, &read_fds);
      if (fd > max_fd) max_fd = fd;
    }

    int err = select(max_fd + 1, &read_fds, nullptr, nullptr, nullptr);
    if (err == -1 && errno == EINTR) {
      // Do nothing.
      continue;
    }
    if (err == -1) {
      fprintf(stderr, "Error selecting descriptors\n");
      break;  // Abnormal termination.
    }

    if (FD_ISSET(*stop_fd, &read_fds)) {
      graceful_shutdown = true;
      continue;
    }

    if (FD_ISSET(sock, &read_fds)) {
      fd = accept(sock, nullptr, nullptr);
      clients.push_back(
          std::unique_ptr<FDMessageChannel>(new FDMessageChannel(fd, -1)));
    }

    // Check for messages from clients
    for (auto it = clients.begin(); it != clients.end(); /**/) {
      FDMessageChannel *client = it->get();
      fd = client->GetReadFileDescriptor();
      if (!FD_ISSET(fd, &read_fds)) {
        ++it;
        continue;
      }
      bool eof = false;
      LogMessage msg;
      if (!client->ReceiveMessage(&msg, &eof)) {
        closed(fd, "died", &client_names);
        it = clients.erase(it);
      } else if (eof) {
        closed(fd, "exit", &client_names);
        it = clients.erase(it);
      } else {
        show(fd, msg, &client_names);
        ++it;
      }
    }
  }

  printf("== end messages for %s:%s ==\n", FLAGS_host.c_str(),
         FLAGS_port.c_str());

  return 0;
}
