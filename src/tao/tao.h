//  File: tao.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: The Tao interface for Trusted Computing
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



#ifndef TAO_TAO_H_
#define TAO_TAO_H_

#include <string>

using std::string;

namespace tao {

// The Tao interface
class Tao {
 public:
  virtual ~Tao() {}
  virtual bool Init() = 0;
  virtual bool Destroy() = 0;
  virtual bool StartHostedProgram(const string &path, int argc,
                                  char **argv) = 0;
  virtual bool GetRandomBytes(size_t size, string *bytes) const = 0;
  virtual bool Seal(const string &data, string *sealed) const = 0;
  virtual bool Unseal(const string &sealed, string *data) const = 0;
  virtual bool Attest(const string &data, string *attestation) const = 0;
  virtual bool VerifyAttestation(const string &attestation, string *data) const = 0;
};
}

#endif  // TAO_TAO_H_
