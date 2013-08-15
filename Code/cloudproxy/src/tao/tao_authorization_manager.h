//  File: tao_authorization_manager.h
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An interface for hosted-program authorization mechanisms
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

#ifndef TAO_AUTHORIZATION_MANAGER_H_
#define TAO_AUTHORIZATION_MANAGER_H_

#include <string>

using std::string;

namespace tao {
class TaoAuthorizationManager {
public:
  virtual ~TaoAuthorizationManager() { }
  virtual bool IsAuthorized(const string &program_hash) const = 0;
  virtual bool IsAuthorized(const string &program_name, const string &program_hash) const = 0;
};
} // namespace tao

#endif // TAO_AUTHORIZATION_MANAGER_H_
