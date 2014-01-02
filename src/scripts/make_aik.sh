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

RUN=~/testing/run
ROOT=~/src/fileProxy
BUILD_DIR=${ROOT}/src/out/Release/bin
AIKBLOB=~/testing/run/HW/aikblob
KEYCZAR_PASS=cppolicy

# Create an AIK for certification

# These commands rely on the attest_to_aik and make_aik commands in
# src/apps and they depend on the TPM having the well-known 0 password.
cd $RUN
mkdir -p HW
${BUILD_DIR}/make_aik --aik_blob_file $AIKBLOB
${BUILD_DIR}/attest_to_aik --aik_blob_file $AIKBLOB \
  --aik_attest_file HW/aik.attest --policy_pass $KEYCZAR_PASS


