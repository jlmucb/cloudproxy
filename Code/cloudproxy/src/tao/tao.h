//  File: tao.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: The Tao interface for Trusted Computing
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
//
// Use, duplication and disclosure of this file and derived works of
// this file are subject to and licensed under the Apache License dated
// January, 2004, (the "License").  This License is contained in the
// top level directory originally provided with the CloudProxy Project.
// Your right to use or distribute this file, or derived works thereof,
// is subject to your being bound by those terms and your use indicates
// consent to those terms.
//
// If you distribute this file (or portions derived therefrom), you must
// include License in or with the file and, in the event you do not include
// the entire License in the file, the file must contain a reference
// to the location of the License.

// ------------------------------------------------------------------------

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
  virtual bool Quote(const string &data, string *signature) const = 0;
  virtual bool VerifyQuote(const string &data,
                           const string &signature) const = 0;
  virtual bool Attest(string *attestation) const = 0;
  virtual bool VerifyAttestation(const string &attestation) const = 0;
};
}

#endif  // TAO_TAO_H_
