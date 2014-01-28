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

if [[ "$#" != "6" ]]; then
  echo "Usage: $0 <test dir> <git root dir> <build dir> <sample whitelist> <keyczar pass> <use fake>"
  exit 1
fi

TEST=$1
ROOT=$2
BUILD_DIR=$3
SAMPLE_WHITELIST=$4
KEYCZAR_PASS=$5
USE_FAKE=$6

#KERNEL=/tmp/vmlinuz-3.7.5
#INITRD=/tmp/initrd.img-3.7.5
#VMSPEC=${TEST}/vm.xml
#VMNAME=cp-test

cd $TEST
# populate the whitelist (for tcca) with the current hashes
cp ${ROOT}/src/scripts/getHash.sh .
#cp ${ROOT}/run/vm.xml ${TEST}/vm.xml

# the trusted hash of linux in the fake case is "FAKE_PCRS"
PCRS=FAKE_PCRS
if [[ "$USE_FAKE" = "NO_FAKE" ]]; then
  PCRS=`./get_pcrs`
fi

cat $SAMPLE_WHITELIST |
  sed "s/REPLACE_ME_SERVER/`cat server | ./getHash.sh`/g" |
  sed "s/REPLACE_ME_CLIENT/`cat client | ./getHash.sh`/g" |
  sed "s/REPLACE_ME_FSERVER/`cat fserver | ./getHash.sh`/g" |
  sed "s/REPLACE_ME_PCRS/$PCRS/g" |
  sed "s/REPLACE_ME_FCLIENT/`cat fclient | ./getHash.sh`/g" > whitelist.pb2
  
#  sed "s/REPLACE_ME_GUEST_VM_NAME/${VMNAME}/g" |
#  sed "s/REPLACE_ME_GUEST_VM/`./get_guest_hash -name ${VMNAME} \
#    -kernel ${KERNEL} -initrd ${INITRD} -vmspec ${VMSPEC}`/g" > whitelist.pb2

# Create a signed version of the whitelist and the ACL for CloudServer
cat whitelist.pb2 |
  ${BUILD_DIR}/protoc -I${ROOT}/src/tao/ --encode=tao.Whitelist \
    ${ROOT}/src/tao/hosted_programs.proto > whitelist
./sign_whitelist --pass $KEYCZAR_PASS


