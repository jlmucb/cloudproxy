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

# BEFORE RUNNING THIS SCRIPT, YOU MUST HAVE:
# 1. built everything in ROOT/src (using ./bootstrap.sh &&
# third_party/ninja/ninja -C out/Release);
# 2. have a version of keyczart in $PATH (either install keyczar or build the
# one in third_party/keyczar);
# 3. followed the directions in ROOT/Doc/SetupTPM.txt to take ownership of the
# TPM
# 4. changed the following variables to suit your directory choices:
if [[ "$#" != "4" ]]; then
  echo "Usage: $0 <run dir> <git root dir> <build dir> <keyczar pass>"
fi

RUN=$1
ROOT=$2
BUILD_DIR=$3
KEYCZAR_PASS=$4

# The CloudServer and CloudClient tests rely on there being users tmroeder and
# jlm.

# Create keys for users tmroeder and jlm with simple passwords.
cd $RUN
mkdir -p keys/tmroeder keys/jlm
keyczart create --location=keys/tmroeder --purpose=sign --asymmetric=rsa
keyczart addkey --location=keys/tmroeder --status=primary --pass=tmroeder

keyczart create --location=keys/jlm --purpose=sign --asymmetric=rsa
keyczart addkey --location=keys/jlm --status=primary --pass=jlm


# Extract and sign the public keys for these files using the policy key.

mkdir -p keys/tmroeder_pub keys/jlm_pub
keyczart create --location=keys/tmroeder_pub --purpose=sign --asymmetric=rsa
keyczart pubkey --location=keys/tmroeder --destination=keys/tmroeder_pub \
  --pass=tmroeder

keyczart create --location=keys/jlm_pub --purpose=sign --asymmetric=rsa
keyczart pubkey --location=keys/jlm --destination=keys/jlm_pub \
  --pass=jlm

# These commands rely on the sign_pub_key command in src/apps/sign_pub_key.cc
${BUILD_DIR}/sign_pub_key --key_loc ./policy_key \
    --pub_key_loc keys/tmroeder_pub \
    --pass ${KEYCZAR_PASS} \
    --signed_speaks_for keys/tmroeder_pub_signed --subject tmroeder
${BUILD_DIR}/sign_pub_key --key_loc ./policy_key \
    --pass ${KEYCZAR_PASS} --pub_key_loc keys/jlm_pub \
    --signed_speaks_for keys/jlm_pub_signed --subject jlm
