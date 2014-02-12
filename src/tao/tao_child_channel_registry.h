//  File: tao_child_channel_registry.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A registry of known TaoChildChannel implementations, along with
//  a function pointer to a Create method that takes a TaoChildChannelParams
//  implementation and produces a TaoChannel of the appropriate type.
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

#ifndef TAO_TAO_CHILD_CHANNEL_REGISTRY_H_
#define TAO_TAO_CHILD_CHANNEL_REGISTRY_H_

#include <map>
#include <string>

#include <keyczar/base/basictypes.h>

using std::map;
using std::string;

namespace tao {
class TaoChildChannel;

/// A registry class that takes a serialized TaoChildChannelParams and produces
/// a TaoChildChannel. The convention is that the last argument of a hosted
/// is a Base64W-encoded TaoChildChannelParams message that can be decoded then
/// passed to a registry object to get the appropriate communication channel.
class TaoChildChannelRegistry {
 public:
  /// A function that can create a channel from parameters.
  typedef TaoChildChannel *(*CreateChannel)(const string &params);

  TaoChildChannelRegistry() : channel_types_() {}

  /// Register a Create function under a name.
  /// @param name The name of the type of channel, like KvmUnixTaoChannel.
  /// @param channel_creator A function pointer for a function that can create
  /// channels of this type.
  bool Register(const string &name, CreateChannel channel_creator);

  /// Create a TaoChildChannel from a given serialized TaoChildChannelParams.
  /// @param params A serialized TaoChildChannelParams that contains the
  /// information needed to access the registry and create a TaoChildChannel of
  /// the appropriate type.
  TaoChildChannel *Create(const string &params);

  /// A utility method for calling a constructor with a single string method.
  /// @param params The only argument to the constructor.
  template <class T>
  static TaoChildChannel *CallConstructor(const string &params) {
    return new T(params);
  }

 private:
  // The registry data: a map from channel type names to functions that can
  // create a channel of this type.
  map<string, CreateChannel> channel_types_;
  DISALLOW_COPY_AND_ASSIGN(TaoChildChannelRegistry);
};
}  // end namespace tao

#endif  // TAO_TAO_CHILD_CHANNEL_REGISTRY_H_
