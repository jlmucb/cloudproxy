//  File: unix_socket_factory.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: A factory for creating FDMessageChannels over unix domain
//  sockets.
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
#ifndef TAO_UNIX_SOCKET_FACTORY_H_
#define TAO_UNIX_SOCKET_FACTORY_H_

#include <string>

#include "tao/fd_message_channel.h"
#include "tao/util.h"

namespace tao {
/// A factory for creating FDMessageChannels over unix domain sockets.
class UnixSocketFactory {
 public:
  /// Construct UnixSocketFactory.
  /// @param path The path for the unix domain server socket.
  explicit UnixSocketFactory(const string &path)
      : path_(path), listen_fd_(-1) {};
  virtual bool Init();
  virtual ~UnixSocketFactory() { Close(); }

  /// Close the server socket.
  virtual bool Close();

  /// Get the file descriptor for the server socket.
  virtual int GetListenFileDescriptor() { return listen_fd_; }

  virtual FDMessageChannel *AcceptConnection() const;

  static FDMessageChannel *Connect(const string &path);

 protected:
  /// The location of the server socket.
  const string path_;

  /// The server socket.
  int listen_fd_;

 private:
  DISALLOW_COPY_AND_ASSIGN(UnixSocketFactory);
};
}  // namespace tao

#endif  // TAO_UNIX_SOCKET_FACTORY_H_
