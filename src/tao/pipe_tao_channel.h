//  File: pipe_tao_channel.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: PipeTaoChannel implements Tao communication over file
//  descriptors
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



#ifndef TAO_PIPE_TAO_CHANNEL_H_
#define TAO_PIPE_TAO_CHANNEL_H_

#include <keyczar/keyczar.h>
#include <tao/tao_channel.h>

namespace tao {
// a TaoChannel that communicates over a pair of file descriptors
// set up with pipe(2)
class PipeTaoChannel : public TaoChannel {
 public:
  // the PipeTaoChannel expects its pipe file descriptors as the
  // last two arguments. It modifies argc and argv to remove these
  // file descriptors from the arguments.
  static bool ExtractPipes(int *argc, char ***argv, int fds[2]);

  PipeTaoChannel(int fds[2]);
  virtual ~PipeTaoChannel();

 protected:
  virtual bool ReceiveMessage(google::protobuf::Message *m) const;
  virtual bool SendMessage(const google::protobuf::Message &m) const;

 private:
  int readfd_;
  int writefd_;

  DISALLOW_COPY_AND_ASSIGN(PipeTaoChannel);
};
}

#endif  // TAO_PIPE_TAO_CHANNEL_H_
