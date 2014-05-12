//  File: fd_message_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A MessageChannel that communicates over Unix file descriptors.
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
#include "tao/fd_message_channel.h"

#include "tao/util.h"

namespace tao {
bool FDMessageChannel::Close() {
  if (readfd_ != -1) {
    close(readfd_);
  }
  if (writefd_ != -1 && writefd_ != readfd_) {
    close(writefd_);
  }
  readfd_ = writefd_ = -1;
  return true;
}

bool FDMessageChannel::GetFileDescriptors(list<int> *keep_open) const {
  if (readfd_ != -1) {
    keep_open->push_back(readfd_);
  }
  if (writefd_ != -1 && writefd_ != readfd_) {
    keep_open->push_back(writefd_);
  }
  return true;
}

virtual bool SerializeToString(string *s) const {
  stringstream out;
  out << "tao::FDMessageChannel(" << readfd_ << ", " << writefd << ")";
  s->assign(out.str());
  return true;
}

}  // namespace tao
