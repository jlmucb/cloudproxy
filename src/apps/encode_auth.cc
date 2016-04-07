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
#include <iostream>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/stubs/common.h>

#include "auth.h"
#include "tao/util.h"

using google::protobuf::io::CodedOutputStream;
using google::protobuf::io::StringOutputStream;
using std::string;
using tao::Base64WEncode;
using tao::Bytes;
using tao::InitializeApp;
using tao::MarshalKeyPrin;
using tao::MarshalSpeaksfor;
using tao::Prin;
using tao::PrinExt;
using tao::SubPrin;

namespace {
// This is the canonical implementation of make_unique for C++11. It is wrapped
// in an anonymous namespace to keep it from conflicting with the real thing if
// it exists.
template<typename T, typename ...Args>
std::unique_ptr<T> make_unique( Args&& ...args )
{
    return std::unique_ptr<T>( new T( std::forward<Args>(args)... ) );
}
}  // namespace


int main(int argc, char **argv) {
  InitializeApp(&argc, &argv, false);

  Prin p;
  p.type_ = "key";

  auto bytes = make_unique<Bytes>();
  bytes->elt_ = "These are not key bytes";
  p.key_ = std::move(bytes);

  p.ext_ = make_unique<SubPrin>();
  auto ext = make_unique<PrinExt>();
  ext->name_ = "Validated";
  p.ext_->elts_.emplace_back(std::move(ext));

  string serialized_prin;
  {
    StringOutputStream raw_output_stream(&serialized_prin);
    CodedOutputStream output_stream(&raw_output_stream);
    p.Marshal(&output_stream);
  }

  string encoded_prin;
  if (!Base64WEncode(serialized_prin, &encoded_prin)) {
    LOG(FATAL) << "Could not encode the prin in Base64W";
  }

  std::cout << "A Prin encoded with Base64W:" << std::endl;
  std::cout << encoded_prin << std::endl;

  // A fake key for the parent.
  string taoKeyName("test tao key");
  string taoName;
  if (!MarshalKeyPrin(taoKeyName, &taoName)) {
    LOG(FATAL) << "Could not marshal a fake key auth.Prin value";
  }

  // A dummy key string to encode as bytes in MarshalSpeaksfor
  string testKey("test key");
  string speaksfor;
  if (!MarshalSpeaksfor(testKey, taoName, &speaksfor)) {
    LOG(FATAL) << "Could not marshal a speaksfor statement";
  }

  string encoded;
  if (!Base64WEncode(speaksfor, &encoded)) {
    LOG(FATAL) << "Could not encode the speaksfor in Base64W";
  }

  std::cout << "A Speaksfor encoded with Base64W:" << std::endl;
  std::cout << encoded << std::endl;
  return 0;
}
