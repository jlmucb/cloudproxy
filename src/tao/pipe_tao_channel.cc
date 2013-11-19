//  File: pipe_tao_channel.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Implementation of PipeTaoChannel for Tao
//  communication over file descriptors
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

#include <tao/pipe_tao_channel.h>
#include <tao/pipe_tao_channel_params.pb.h>
#include <tao/tao_child_channel_params.pb.h>

#include <keyczar/base/scoped_ptr.h>

#include <stdlib.h>
#include <errno.h>

#include <thread>

using std::thread;

extern int errno;

namespace tao {

PipeTaoChannel::PipeTaoChannel() { }
PipeTaoChannel::~PipeTaoChannel() { }

bool PipeTaoChannel::AddChildChannel(const string &child_hash, string *params) {
  if (params == nullptr) {
    LOG(ERROR) << "Could not write the params to a null string";
    return false;
  }

  // check to make sure this hash isn't already instantiated with pipes
  {
    lock_guard<mutex> l(data_m_);
    auto hash_it = hash_to_descriptors_.find(child_hash);
    if (hash_it != hash_to_descriptors_.end()) {
      LOG(ERROR) << "This child has already been instantiated with a channel";
      return false;
    }
  }

  int down_pipe[2];
  if (pipe(down_pipe)) {
    LOG(ERROR) << "Could not create the down pipe for the client";
    return false;
  }

  int up_pipe[2];
  if (pipe(up_pipe)) {
    LOG(ERROR) << "Could not create the up pipe for the client";
    return false;
  }

  // the parent connect reads on the up pipe and writes on the down pipe.
  {
    lock_guard<mutex> l(data_m_);
    hash_to_descriptors_[child_hash].first = up_pipe[0];
    hash_to_descriptors_[child_hash].second = down_pipe[1];
  }

  // the child reads on the down pipe and writes on the up pipe
  PipeTaoChannelParams ptcp;
  ptcp.set_readfd(down_pipe[0]);
  ptcp.set_writefd(up_pipe[1]);

  TaoChildChannelParams tccp;
  tccp.set_channel_type("PipeTaoChannel");
  string *child_params = tccp.mutable_params();
  if (!ptcp.SerializeToString(child_params)) {
    LOG(ERROR) << "Could not serialize the child params to a string";
  }

  if (!tccp.SerializeToString(params)) {
    LOG(ERROR) << "Could not serialize the params to a string";
    return false;
  }

  // Put the child fds in a data structure for later cleanup.
  {
    lock_guard<mutex> l(data_m_);
    child_descriptors_[child_hash].first = down_pipe[0];
    child_descriptors_[child_hash].second = up_pipe[1];
  }

  return true;
}


bool PipeTaoChannel::ChildCleanup(const string &child_hash) {
  {
    // Look up this hash to see if this child has any params to clean up.
    lock_guard<mutex> l(data_m_);
    auto child_it = child_descriptors_.find(child_hash);
    if (child_it == child_descriptors_.end()) {
      LOG(ERROR) << "No child " << child_hash << " to clean up";
      return false;
    }

    close(child_it->second.first);
    close(child_it->second.second);
    
    child_descriptors_.erase(child_it);
  }
    
  return true;
}

bool PipeTaoChannel::ParentCleanup(const string &child_hash) {
  {
    lock_guard<mutex> l(data_m_);
    // Look up this hash to see if this child has any params to clean up.
    auto child_it = hash_to_descriptors_.find(child_hash);
    if (child_it == hash_to_descriptors_.end()) {
      LOG(ERROR) << "No child " << child_hash << " for parent clean up";
      return false;
    }

    close(child_it->second.first);
    close(child_it->second.second);

    hash_to_descriptors_.erase(child_it);
  }

  return true;
}

bool PipeTaoChannel::ReceiveMessage(google::protobuf::Message *m,
                                    const string &child_hash) const {
  // try to receive an integer
  CHECK(m) << "m was null";

  int readfd = 0;
  {
    lock_guard<mutex> l(data_m_);
    // Look up the hash to see if we have descriptors associated with it.
    auto child_it = hash_to_descriptors_.find(child_hash);
    if (child_it == hash_to_descriptors_.end()) {
      LOG(ERROR) << "Could not find any file descriptors for " << child_hash;
      return false;
    }

    readfd = child_it->second.first;
  }


  size_t len;
  ssize_t bytes_read = read(readfd, &len, sizeof(size_t));
  if (bytes_read != sizeof(size_t)) {
    LOG(ERROR) << "Could not receive a size on the channel";
    return false;
  }

  // then read this many bytes as the message
  scoped_array<char> bytes(new char[len]);
  bytes_read = read(readfd, bytes.get(), len);

  // TODO(tmroeder): add safe integer library
  if (bytes_read != static_cast<ssize_t>(len)) {
    LOG(ERROR) << "Could not read the right number of bytes from the fd";
    return false;
  }

  string serialized(bytes.get(), len);
  return m->ParseFromString(serialized);
}

bool PipeTaoChannel::SendMessage(const google::protobuf::Message &m,
                                 const string &child_hash) const {
  // send the length then the serialized message
  string serialized;
  if (!m.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the Message to a string";
    return false;
  }

  int writefd = 0;
  {
    lock_guard<mutex> l(data_m_);
    // Look up the hash to see if we have descriptors associated with it.
    auto child_it = hash_to_descriptors_.find(child_hash);
    if (child_it == hash_to_descriptors_.end()) {
      LOG(ERROR) << "Could not find any file descriptors for " << child_hash;
      return false;
    }

    writefd = child_it->second.first;
  }



  size_t len = serialized.size();
  ssize_t bytes_written = write(writefd, &len, sizeof(size_t));
  if (bytes_written != sizeof(size_t)) {
    LOG(ERROR) << "Could not write the length to the fd";
    return false;
  }

  bytes_written = write(writefd, serialized.data(), len);
  if (bytes_written != static_cast<ssize_t>(len)) {
    LOG(ERROR) << "Could not wire the serialized message to the fd";
    return false;
  }

  return true;
}

bool PipeTaoChannel::Listen(Tao *tao, const string &child_hash) {
  thread t(&PipeTaoChannel::MessageHandler, this, tao, child_hash);
  t.detach();
  return true;
}

bool PipeTaoChannel::MessageHandler(Tao *tao, const string &child_hash) {
  while(true) {
    TaoChannelRPC rpc;
    if (!GetRPC(&rpc, child_hash)) {
      LOG(ERROR) << "Could not get an RPC";
      return false;
    }

    if (!HandleRPC(*tao, child_hash, rpc)) {
      LOG(ERROR) << "Could not handle the RPC";
      return false;
    }
  }

  return true;
}
}  // namespace tao
