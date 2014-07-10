//  File: log_net.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Network sink for google logging (glog).
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
#include "tao/log_net.h"

#include "tao/fd_message_channel.h"

using std::lock_guard;
using std::mutex;
using std::string;
using std::thread;
using std::unique_lock;

namespace tao {
bool LogNet::Init(const string& host, const string& port, const string& name) {
  int sock;
  if (!ConnectToTCPServer(host, port, &sock)) {
    LOG(INFO) << "Network log sink " << host << ":" << port << " failed.";
    return false;
  }
  google::AddLogSink(new LogNet(sock));
  // First log message after adding LogNet as sink defines our LogNet nickname
  LOG(INFO) << "[" << FilePath(name).BaseName().value() << " " << getpid()
            << "]";
  return true;
}

LogNet::LogNet(int sock) : sock_(sock) {
  t_.reset(new thread(&LogNet::run, this, sock_));
}

LogNet::~LogNet() {
  unique_ptr<thread> t;
  {
    lock_guard<mutex> l(m_);
    if (sock_ != -1) {
      shutdown(sock_, SHUT_RD);
      sock_ = -1;
    }
    t.reset(t_.release());
  }
  if (t.get() != nullptr) {
    t->join();
    t.reset(nullptr);
  }
}

void LogNet::send(google::LogSeverity severity, const char* full_filename,
                  const char* base_filename, int line,
                  const struct ::tm* tm_time, const char* message,
                  size_t message_len) {
  LogMessage msg;
  msg.set_severity(reinterpret_cast<int>(severity));
  msg.set_full_filename(string(full_filename));
  msg.set_base_filename(string(full_filename));
  msg.set_line(line);
  LogTimestamp* t = msg.mutable_time();
  t->set_tm_sec(tm_time->tm_sec);
  t->set_tm_min(tm_time->tm_min);
  t->set_tm_hour(tm_time->tm_hour);
  t->set_tm_mday(tm_time->tm_mday);
  t->set_tm_mon(tm_time->tm_mon);
  t->set_tm_year(tm_time->tm_year);
  t->set_tm_wday(tm_time->tm_wday);
  t->set_tm_yday(tm_time->tm_yday);
  t->set_tm_isdst(tm_time->tm_isdst);
  msg.set_message(string(message, message_len));
  {
    lock_guard<mutex> l(m_);
    if (sock_ == -1) return;
    q_.push_back(msg);
  }
  cv_.notify_all();
}

void LogNet::WaitTillSent() {
  unique_lock<mutex> l(m_);
  while (sock_ >= 0 && !q_.empty()) cv_.wait(l);
}

void LogNet::run(int sock) {
  FDMessageChannel chan(sock, sock);
  for (;;) {
    LogMessage msg;
    {
      unique_lock<mutex> l(m_);
      while (sock_ >= 0 && q_.empty()) cv_.wait(l);
      if (sock_ == -1) return;  // chan will close the socket
      msg = q_.front();
      q_.pop_front();
    }
    chan.SendMessage(msg);  // ignore errors
    cv_.notify_all();       // wake threads in WaitTillSent()
  }
}
}  // namespace tao
