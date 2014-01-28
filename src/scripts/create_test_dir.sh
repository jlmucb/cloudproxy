#!/bin/bash
# Copyright (c) 2013, Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

if [[ "$#" != "4" ]]; then
  echo "Usage: $0 <run dir> <test dir> <git root dir> <build dir>"
  exit 1
fi

RUN=$1
TEST=$2
ROOT=$3
BUILD_DIR=$4

# Set up a test directory to use for tests. This copies over the run directory
# into an adjacent test directory
rm -fr /tmp/.linux_tao_socket
cp -r ${RUN} ${TEST}
cd $TEST
mkdir linux_tao_service_files

# Get all the code and an extra script
cp ${BUILD_DIR}/* .
cp ${ROOT}/src/scripts/run_simple_test.sh .
cp ${ROOT}/src/scripts/run_simple_fake_test.sh .

rm *.a
