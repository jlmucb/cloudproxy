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
  echo "Usage: $0 <run dir> <git root dir> <build dir> <aik blob file> <keyczar pass>"
  exit 1
fi

RUN=$1
ROOT=$2
BUILD_DIR=$3
AIKBLOB=$4
KEYCZAR_PASS=$5

# Create an AIK for certification

# These commands rely on the attest_to_aik and make_aik commands in
# src/apps and they depend on the TPM having the well-known 0 password.
cd $RUN
mkdir -p tpm
${BUILD_DIR}/make_aik --aik_blob_file $AIKBLOB \
  --policy_pass ${KEYCZAR_PASS}
${BUILD_DIR}/attest_to_aik --aik_blob_file $AIKBLOB \
  --aik_attest_file tpm/aik.attest  \
  --policy_pass ${KEYCZAR_PASS}


