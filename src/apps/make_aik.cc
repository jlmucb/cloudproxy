//  File: make_aik.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Creates an AIK the TPM, assuming the caller controls the TPM
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
#include <list>
#include <string>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "tao/tpm_tao.h"
#include "tao/util.h"

using std::cout;
using std::endl;
using std::list;
using std::string;

using tao::TPMTao;
using tao::WriteStringToFile;

DEFINE_string(aik_blob_file, "tpm/aikblob", "A file in which to store the AIK blob");

int main(int argc, char **argv) {
  tao::InitializeApp(&argc, &argv, true);

  string aik_blob;

  TPMTao tao(list<int>{} /* pcr indexes */);
  CHECK(tao.Init());
  CHECK(tao.CreateAIK(&aik_blob));

  if (!WriteStringToFile(FLAGS_aik_blob_file, aik_blob)) {
    LOG(ERROR) << "Could not write AIK blob to the file";
    return 1;
  }

  cout << "AIK blob saved: " << FLAGS_aik_blob_file << endl;

  return 0;
}
