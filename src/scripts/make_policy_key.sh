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
  echo "Usage: $0 <run dir> <git root dir> <keyczar pass> <openssl pass>"
fi

RUN=$1
ROOT=$2
KEYCZAR_PASS=$3
PASS=$4

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
keyczart create --location=policy_key --purpose=sign --asymmetric=ecdsa
keyczart importkey --location=policy_key --status=primary \
  --key=openssl_keys/policy/policy.pem --passphrase=$PASS \
  --pass=$KEYCZAR_PASS
mkdir policy_public_key
keyczart pubkey --location=policy_key --destination=policy_public_key \
  --pass=$KEYCZAR_PASS


