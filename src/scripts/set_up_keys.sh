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
# 2. followed the directions in ROOT/Doc/SetupTPM.txt to take ownership of the
# TPM (to use the TPM version. Otherwise, call this script with argument "FAKE")
# 3. changed the following variables to suit your directory choices:
if [[ $# -gt 0 ]]; then
  USE_FAKE=$1
else
  USE_FAKE=NO_FAKE
fi

ROOT=~/src/fileProxy
RUN=~/testing/run
TEST=~/testing/test
BUILD_DIR=${ROOT}/src/out/Debug/bin
SAMPLE_ACLS=${ROOT}/run/acls.ascii
AIKBLOB=${RUN}/tpm/aikblob
PASS=cppolicy # policy password
CONFIG=${RUN}/tao.config

ROOT=~/src/fileProxy
SCRIPTS=${ROOT}/src/scripts

rm -rf ${RUN} ${TEST}

mkdir -p ${RUN}

${BUILD_DIR}/tao_admin -config_path $CONFIG -policy_pass $PASS \
	-init ${ROOT}/run/tao-default.config -name testing 

if [[ "$USE_FAKE" = "NO_FAKE" ]]; then
  ${SCRIPTS}/make_aik.sh $RUN $ROOT $BUILD_DIR $AIKBLOB $PASS
  PCRS=`${BUILD_DIR}/get_pcrs`
  ${BUILD_DIR}/tao_admin -config_path $CONFIG -policy_pass $PASS \
	  -whitelist "${PCRS}:PCR_SHA1:Linux"
else
  ${BUILD_DIR}/tao_admin -config_path $CONFIG -policy_pass $PASS \
	  -make_fake_tpm fake_tpm
  ${BUILD_DIR}/tao_admin -config_path $CONFIG -policy_pass $PASS \
	  -whitelist "FAKE_TPM:FAKE_HASH:BogusTPM"
  # TODO(kwalsh): this should be FAKE_HASH, not SHA256, but the channels
  # don't yet support hash_alg parameter
  ${BUILD_DIR}/tao_admin -config_path $CONFIG -policy_pass $PASS \
	  -whitelist "FAKE_PCRS:SHA256:Linux"
fi

#HOSTED_PROGRAMS=$(echo ${BUILD_DIR}/*)
HOSTED_PROGRAMS=$(echo ${BUILD_DIR}/{client,server,fclient,fserver})
HOSTED_PROGRAMS=${HOSTED_PROGRAMS// /,}
${BUILD_DIR}/tao_admin -config_path $CONFIG -policy_pass $PASS \
	-whitelist ${HOSTED_PROGRAMS}

${SCRIPTS}/create_users.sh $RUN $ROOT $BUILD_DIR $PASS
${SCRIPTS}/set_up_acls.sh $RUN $ROOT $BUILD_DIR $SAMPLE_ACLS $PASS

${SCRIPTS}/create_test_dir.sh $RUN $TEST $ROOT $BUILD_DIR

