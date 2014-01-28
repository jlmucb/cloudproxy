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

TEST=~/testing/test
ROOT=~/src/fileProxy
BUILD_DIR=${ROOT}/src/out/Release/bin
SAMPLE_WHITELIST=${ROOT}/run/sample_guest_whitelist.pb2
KERNEL=/tmp/vmlinuz-3.7.5
INITRD=/tmp/initrd.img-3.7.5
VMSPEC=${TEST}/vm.xml
VMNAME=cp-test
KEYCZAR_PASS=cppolicy

cd $TEST
# populate the whitelist (for tcca) with the current hashes
cp ${ROOT}/src/scripts/getHash.sh .
cp ${ROOT}/run/vm.xml ${TEST}/vm.xml
cat $SAMPLE_WHITELIST |
  sed "s/REPLACE_ME_SERVER/`cat server | ./getHash.sh`/g" |
  sed "s/REPLACE_ME_CLIENT/`cat client | ./getHash.sh`/g" |
  sed "s/REPLACE_ME_FSERVER/`cat fserver | ./getHash.sh`/g" |
  sed "s/REPLACE_ME_FCLIENT/`cat fclient | ./getHash.sh`/g" > whitelist.pb2

# Create a signed version of the whitelist and the ACL for CloudServer
cat whitelist.pb2 |
  ${BUILD_DIR}/protoc -I${ROOT}/src/tao/ --encode=tao.Whitelist \
    ${ROOT}/src/tao/hosted_programs.proto > whitelist
./sign_whitelist --pass $KEYCZAR_PASS


