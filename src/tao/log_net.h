//  File: log_net.h
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
#ifndef TAO_LOG_NET_H_
#define TAO_LOG_NET_H_

#include <condition_variable>
#include <list>
#include <mutex>
#include <string>
#include <thread>

#include <glog/logging.h>

#include "tao/log_net.pb.h"
#include "tao/util.h"

namespace tao {
/// A Google Logging LogSink that sends all log messages over a TCP connection.
/// It silently drops log messages if a connection can not be opened.
class LogNet : public google::LogSink {
 public:
  static bool Init(const string& host, const string& port, const string& name);

  explicit LogNet(int sock);
  virtual ~LogNet();
  virtual void send(google::LogSeverity severity, const char* full_filename,
                    const char* base_filename, int line,
                    const struct ::tm* tm_time, const char* message,
                    size_t message_len);
  virtual void WaitTillSent();
  virtual void run(int sock);

 private:
  int sock_;
  std::list<LogMessage> q_;
  std::mutex m_;
  std::condition_variable cv_;
  unique_ptr<std::thread> t_;
};
}  // namespace tao
#endif  // TAO_LOG_NET_H_
