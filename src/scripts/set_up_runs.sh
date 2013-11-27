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

cp -r run test
cd test
mkdir linux_tao_service_files
cp ../src/out/Default/bin/* .
rm *.a
cat sample_whitelist.pb2 | sed "s/REPLACE_ME_SERVER/`cat server | ./getHash.sh`/g" | sed "s/REPLACE_ME_CLIENT/`cat client | ./getHash.sh`/g" | sed "s/REPLACE_ME_FSERVER/`cat fserver | ./getHash.sh`/g" | sed "s/REPLACE_ME_FCLIENT/`cat fclient | ./getHash.sh`/g" > whitelist.pb2
cat whitelist.pb2 | protoc -I../src/tao/ --encode=tao.Whitelist ../src/tao/hosted_programs.proto > whitelist
./sign_whitelist
cat acls.ascii | protoc -I../src/cloudproxy --encode=cloudproxy.ACL ../src/cloudproxy/cloudproxy.proto > acls
./sign_acls
