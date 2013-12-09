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
# third_party/ninja/ninja -C out/Default);
# 2. have a version of keyczart in $PATH (either install keyczar or build the
# one in third_party/keyczar);
# 3. followed the directions in ROOT/Doc/SetupTPM.txt to take ownership of the
# TPM
# 4. changed the following variables to suit your directory choices:
RUN=~/testing/run
TEST=~/testing/test
ROOT=~/src/fileProxy
BUILD_DIR=${ROOT}/src/out/Default/bin
AIKBLOB=~/testing/run/HW/aikblob
SAMPLE_WHITELIST=${ROOT}/run/sample_whitelist.pb2
SAMPLE_ACLS=${ROOT}/run/acls.ascii
KEYCZAR_PASS=cppolicy
PASS=cppolicy

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
openssl ecparam -in policy_pub.pem -genkey |
  openssl ec -aes256 -out policy.pem

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



# The CloudServer and CloudClient tests rely on there being users tmroeder and
# jlm.

# Create keys for users tmroeder and jlm with simple passwords.
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

# Create an AIK for certification


# These commands rely on the attest_to_aik and make_aik commands in
# src/apps and they depend on the TPM having the well-known 0 password.
mkdir -p HW
${BUILD_DIR}/make_aik --aik_blob_file $AIKBLOB
${BUILD_DIR}/attest_to_aik --aik_blob_file $AIKBLOB \
  --aik_attest_file HW/aik.attest --policy_pass $KEYCZAR_PASS

# Set up a test directory to use for tests. This copies over the run directory
# into an adjacent test directory
rm -fr /tmp/.linux_tao_socket
cp -r ${RUN} ${TEST}
cd $TEST
mkdir linux_tao_service_files

# Get all the code and an extra script
cp ${BUILD_DIR}/* .
cp ${ROOT}/src/scripts/getHash.sh .
cp ${ROOT}/src/scripts/run_simple_test.sh .

rm *.a

# populate the whitelist (for tcca) with the current hashes
cat $SAMPLE_WHITELIST |
  sed "s/REPLACE_ME_SERVER/`cat server | ./getHash.sh`/g" |
  sed "s/REPLACE_ME_CLIENT/`cat client | ./getHash.sh`/g" |
  sed "s/REPLACE_ME_FSERVER/`cat fserver | ./getHash.sh`/g" |
  sed "s/REPLACE_ME_FCLIENT/`cat fclient | ./getHash.sh`/g" |
  sed "s/REPLACE_ME_PCRS/`./get_pcrs`/g" > whitelist.pb2

# Create a signed version of the whitelist and the ACL for CloudServer
cat whitelist.pb2 |
  ${BUILD_DIR}/../protoc -I${ROOT}/src/tao/ --encode=tao.Whitelist \
    ${ROOT}/src/tao/hosted_programs.proto > whitelist
./sign_whitelist --pass $KEYCZAR_PASS
cat $SAMPLE_ACLS |
  ${BUILD_DIR}/../protoc -I${ROOT}/src/cloudproxy --encode=cloudproxy.ACL \
    ${ROOT}/src/cloudproxy/cloudproxy.proto > acls
./sign_acls --pass $KEYCZAR_PASS


echo "Now run ./run_simple_test.sh"
