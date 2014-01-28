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
  echo "Usage: $0 <run dir> <build dir> <git root dir> <keyczar pass> <openssl pass>"
  exit 1
fi

RUN=$1
BUILD_DIR=$2
ROOT=$3
KEYCZAR_PASS=$4
PASS=$5

# Create a directory structure for the openssl keys:

# CloudClient and CloudServer store their TPM-locked keys in the openssl_keys
# directory, too.
mkdir -p ${RUN}/openssl_keys/policy ${RUN}/openssl_keys/server \
  ${RUN}/openssl_keys/client

# Then, create a policy key:

# An openssl form.
cd ${RUN}/openssl_keys/policy
openssl ecparam -out policy_pub.pem -name prime256v1
echo "Encrypting the policy private key"
echo $PASS > ${RUN}/pass
openssl ecparam -in policy_pub.pem -genkey |
  openssl ec -aes256 -out policy.pem -passout file:${RUN}/pass

# Two forms for keyczar: one encrypted private/public key pair for tcca
# and one public key for all other programs.
cd ${RUN}
mkdir policy_key
${BUILD_DIR}/keyczart create --location=policy_key --purpose=sign \
  --asymmetric=ecdsa
${BUILD_DIR}/keyczart importkey --location=policy_key --status=primary \
  --key=openssl_keys/policy/policy.pem --passphrase=$PASS \
  --pass=$KEYCZAR_PASS
mkdir policy_public_key
${BUILD_DIR}/keyczart pubkey --location=policy_key \
  --destination=policy_public_key --pass=$KEYCZAR_PASS
