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
if [[ "$#" != "5" ]]; then
  echo "Usage: $0 <test dir> <git root dir> <build dir> <sample acls> <keyczar pass>"
  exit 1
fi

TEST=$1
ROOT=$2
BUILD_DIR=$3
SAMPLE_ACLS=$4
KEYCZAR_PASS=$5

cd $TEST
cat $SAMPLE_ACLS |
  ${BUILD_DIR}/protoc -I${ROOT}/src/cloudproxy --encode=cloudproxy.ACL \
    ${ROOT}/src/cloudproxy/cloudproxy.proto > acls
${BUILD_DIR}/sign_acls --policy_pass ${KEYCZAR_PASS} \
	--acl_file acls --acl_sig_file acls_sig


