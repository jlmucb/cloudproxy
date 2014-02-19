//  File: get_guest_hash.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Gets a Base64W-encoded representation of a kernel, a spec, a
//  name, and an initrd
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

#include <iostream>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "tao/util.h"

using std::cout;

DEFINE_string(name, "cp-server", "The name of the guest to start");
DEFINE_string(kernel, "vmlinuz-3.7.5", "The kernel to inject into the guest");
DEFINE_string(initrd, "initrd.img-3.7.5", "The initrd to inject");
DEFINE_string(vmspec, "vm.xml", "The VM spec template to use");

int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);

  string hash;
  if (!tao::HashVM(FLAGS_vmspec, FLAGS_name, FLAGS_kernel, FLAGS_initrd,
                   &hash)) {
    LOG(ERROR) << "Could not compute the hash of the vm parameters";
    return 1;
  }

  cout << hash;
  return 0;
}
