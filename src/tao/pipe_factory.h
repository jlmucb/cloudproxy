//  File: pipe_factory.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A factory for creating FDMessageChannels over pipes.
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
#ifndef TAO_PIPE_FACTORY_H_
#define TAO_PIPE_FACTORY_H_

#include "tao/fd_message_channel.h"
#include "tao/util.h"

namespace tao {
/// A TaoChannel that communicates over file descriptors
/// set up with pipe(2) and listens to multiple connections with select.
class PipeFactory {
 public:
  PipeFactory() {}
  virtual ~PipeFactory() {}

  virtual bool CreateChannelPair(
      unique_ptr<FDMessageChannel> *channel_to_parent,
      unique_ptr<FDMessageChannel> *channel_to_child) const;

 private:
  DISALLOW_COPY_AND_ASSIGN(PipeFactory);
};
}  // namespace tao

#endif  // TAO_PIPE_FACTORY_H_
