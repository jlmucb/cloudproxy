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
  echo "Usage: $0 <run dir> <git root dir> <build dir> <policy pass>"
  exit 1
fi

RUN=$1
ROOT=$2
BUILD_DIR=$3
PASS=$4

# The CloudServer and CloudClient tests rely on there being users tmroeder and
# jlm.

# Create keys for users tmroeder and jlm with simple passwords.
cd $RUN
mkdir -p keys/tmroeder keys/jlm
${BUILD_DIR}/keyczart create --location=keys/tmroeder --purpose=sign \
    --asymmetric=ecdsa
${BUILD_DIR}/keyczart addkey --location=keys/tmroeder --status=primary \
    --pass=tmroeder
${BUILD_DIR}/keyczart create --location=keys/jlm --purpose=sign \
	--asymmetric=ecdsa
${BUILD_DIR}/keyczart addkey --location=keys/jlm --status=primary --pass=jlm


# Extract and sign the public keys for these files using the policy key.

mkdir -p keys/tmroeder_pub keys/jlm_pub
${BUILD_DIR}/keyczart create --location=keys/tmroeder_pub --purpose=sign \
  --asymmetric=ecdsa
${BUILD_DIR}/keyczart pubkey --location=keys/tmroeder \
  --destination=keys/tmroeder_pub --pass=tmroeder

${BUILD_DIR}/keyczart create --location=keys/jlm_pub --purpose=sign \
  --asymmetric=ecdsa
${BUILD_DIR}/keyczart pubkey --location=keys/jlm --destination=keys/jlm_pub \
  --pass=jlm

# These commands rely on the sign_pub_key command in src/apps/sign_pub_key.cc
${BUILD_DIR}/sign_pub_key --policy_pass $PASS  \
    --pub_key_loc keys/tmroeder_pub \
    --signed_speaks_for keys/tmroeder_pub_signed --subject tmroeder
${BUILD_DIR}/sign_pub_key --policy_pass $PASS  \
    --pub_key_loc keys/jlm_pub \
    --signed_speaks_for keys/jlm_pub_signed --subject jlm
