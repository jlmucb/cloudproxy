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

#include <fstream>
#include <iostream>
#include <sstream>

#include <gflags/gflags.h>
#include <glog/logging.h>
#include <keyczar/base/base64w.h>

#include "tao/util.h"

using std::cout;
using std::ifstream;
using std::stringstream;

DEFINE_string(name, "cp-server", "The name of the guest to start");
DEFINE_string(kernel, "vmlinuz-3.7.5", "The kernel to inject into the guest");
DEFINE_string(initrd, "initrd.img-3.7.5", "The initrd to inject");
DEFINE_string(vmspec, "vm.xml", "The VM spec template to use");

int main(int argc, char **argv) {
  google::ParseCommandLineFlags(&argc, &argv, true);
  FLAGS_alsologtostderr = true;
  google::InitGoogleLogging(argv[0]);

  ifstream template_file(FLAGS_vmspec.c_str());
  if (!template_file) {
    LOG(ERROR) << "Could not open the template file " << FLAGS_vmspec;
    return 1;
  }

  ifstream kernel_file(FLAGS_kernel.c_str());
  if (!kernel_file) {
    LOG(ERROR) << "Could not load the kernel file " << FLAGS_kernel;
    return 1;
  }

  ifstream initrd_file(FLAGS_initrd.c_str());
  if (!initrd_file) {
    LOG(ERROR) << "Could not load the initrd file " << FLAGS_initrd;
    return 1;
  }

  stringstream template_stream;
  template_stream << template_file.rdbuf();

  stringstream kernel_stream;
  kernel_stream << kernel_file.rdbuf();

  stringstream initrd_stream;
  initrd_stream << initrd_file.rdbuf();

  string hash;
  if (!tao::HashVM(template_stream.str(), FLAGS_name, kernel_stream.str(),
        initrd_stream.str(), &hash)) {
    LOG(ERROR) << "Could not compute the hash of the vm parameters";
    return 1;
  }

  string digest;
  if (!keyczar::base::Base64WEncode(hash, &digest)) {
    LOG(ERROR) << "Could not encode the digest";
    return 1;
  }

  cout << digest;
  return 0;
}
