//  File: fake_program_factory.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: A factory that pretends to create hosted programs but doesn't.
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

#ifndef TAO_FAKE_PROGRAM_FACTORY_H_
#define TAO_FAKE_PROGRAM_FACTORY_H_

#include "tao/hosted_program_factory.h"

#include <glog/logging.h>
#include <keyczar/keyczar.h>

namespace tao {
// A fake factory that doesn't really create programs
class FakeProgramFactory : public HostedProgramFactory {
 public:
  FakeProgramFactory() {}
  virtual ~FakeProgramFactory() {}

  // Instead of creating a program, it returns true and ignores the arguments
  virtual bool CreateHostedProgram(const string &name, const list<string> &args,
                                   const string &child_hash,
                                   TaoChannel &parent_channel) const {
    return true;
  }
  virtual string GetFactoryName() const { return "FakeProgramFactory"; }

 private:
  DISALLOW_COPY_AND_ASSIGN(FakeProgramFactory);
};
}  // namespace tao

#endif  // TAO_FAKE_PROGRAM_FACTORY_H_
