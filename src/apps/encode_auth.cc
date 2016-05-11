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

using google::protobuf::io::ArrayInputStream;
using google::protobuf::io::CodedInputStream;
using google::protobuf::io::CodedOutputStream;
using google::protobuf::io::StringOutputStream;
using std::string;
using tao::Base64WEncode;
using tao::Bytes;
using tao::InitializeApp;
using tao::make_unique;
using tao::MarshalKeyPrin;
using tao::MarshalSpeaksfor;
using tao::Prin;
using tao::PrinExt;
using tao::SubPrin;
using tao::Term;

int main(int argc, char **argv) {
  InitializeApp(&argc, &argv, false);

  std::vector<std::unique_ptr<PrinExt>> v;
  v.push_back(make_unique<PrinExt>("Validated", std::vector<std::unique_ptr<Term>>()));

  Prin p("key", make_unique<Bytes>("These are not key bytes"),
         make_unique<SubPrin>(std::move(v)));

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

  Prin unmarshalled_prin;
  {
    ArrayInputStream raw_input_stream(serialized_prin.data(),
                                      serialized_prin.size());
    CodedInputStream input_stream(&raw_input_stream);
    if (!unmarshalled_prin.Unmarshal(&input_stream)) {
      LOG(FATAL) << "Unmarshalling failed";
    }
  }

  if (unmarshalled_prin.type_ != "key") {
    LOG(ERROR) << "The unmarshalled prin had incorrect type '"
               << unmarshalled_prin.type_ << "'";
  }

  auto unmarshalled_bytes =
      reinterpret_cast<Bytes*>(unmarshalled_prin.key_.get());
  if (unmarshalled_bytes->elt_ != "These are not key bytes") {
    LOG(ERROR) << "The unmarshalled bytes did not match the original bytes";
  }

  if (unmarshalled_prin.ext_->elts_.size() != 1) {
    LOG(ERROR) << "The unmarshalled prin did not have one extension";
  }

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
