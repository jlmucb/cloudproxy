//  File: get_pcrs.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Prints a hex-encoded representation of current PCR values.
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

#include <glog/logging.h>

#include "tao/tpm_tao.h"
#include "tao/util.h"

using std::cout;
using std::endl;
using std::list;
using std::string;

using tao::TPMTao;

int main(int argc, char **argv) {
  tao::InitializeApp(&argc, &argv, true);

  list<int> pcr_indexes;
  list<string> pcr_values;

  if (argc == 1) {
    pcr_indexes.push_back(17);
    pcr_indexes.push_back(18);
  } else {
    for (int i = 1; i < argc; i++) pcr_indexes.push_back(atoi(argv[i]));
  }

  TPMTao tao(pcr_indexes);
  CHECK(tao.Init());
  CHECK(tao.GetPCRValues(&pcr_values));

  auto idx = pcr_indexes.begin();
  auto val = pcr_values.begin();
  while (idx != pcr_indexes.end()) {
    cout << "PCR[" << *idx << "] = " << *val << endl;
    ++idx;
    ++val;
  }

  return 0;
}
