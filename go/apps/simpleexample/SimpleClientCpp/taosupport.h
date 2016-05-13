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
#include <string>
#include <taosupport.pb.h>

#ifndef __TAOSUPPORT_H__
#define __TAOSUPPORT_H__

#include <taosupport.pb.h>

class TaoProgramData {
public:
  bool  initialized_;
  string tao_name_;
  int size_policy_cert_
  byte* policy_cert_;
  // need a key representation
  int size_program_sym_key_;
  byte* program_sym_key_;
  int size_program_cert_;
  byte* program_cert_;
  string program_file_path_;

  void ClearProgramData();
  bool InitTao(FDMessageChannel& msg, Tao& tao, string&, string&);
  void Print();
};

class TaoChannel {
public:
  string server_name_;
  int fd_;

  bool OpenTaoChannel(FDMessageChannel& msg, Tao& tao, TaoProgramData& client_program_data,
                      string& serverAddress);
  bool CloseTaoChannel();
  bool SendRequest(SimpleMessage& out);
  bool GetRequest(SimpleMessage* in);
};
#endif


