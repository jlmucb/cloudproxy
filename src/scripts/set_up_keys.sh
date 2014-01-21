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
ROOT=~/src/fileProxy
RUN=~/testing/run
TEST=~/testing/test
BUILD_DIR=${ROOT}/src/out/Release/bin
SAMPLE_ACLS=${ROOT}/run/acls.ascii
SAMPLE_WHITELIST=${ROOT}/run/sample_whitelist.pb2
AIKBLOB=${RUN}/HW/aikblob
PASS=cppolicy
KEYCZAR_PASS=cppolicy

ROOT=~/src/fileProxy
SCRIPTS=${ROOT}/src/scripts

${SCRIPTS}/make_policy_key.sh $RUN $ROOT $KEYCZAR_PASS $PASS
${SCRIPTS}/create_users.sh $RUN $ROOT $BUILD_DIR $KEYCZAR_PASS
${SCRIPTS}/make_aik.sh $RUN $ROOT $BUILD_DIR $AIKBLOB $KEYCZAR_PASS
${SCRIPTS}/create_test_dir.sh $RUN $TEST $ROOT $BUILD_DIR
${SCRIPTS}/set_up_whitelist.sh $TEST $ROOT $BUILD_DIR $SAMPLE_WHITELIST $KEYCZAR_PASS
${SCRIPTS}/set_up_acls.sh $TEST $ROOT $BUILD_DIR $SAMPLE_ACLS $KEYCZAR_PASS

