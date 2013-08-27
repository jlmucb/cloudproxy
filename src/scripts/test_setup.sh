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

rm -fr b_meas/* bootstrap_files/* boots* server client openssl_keys/client/* client_secret openssl_keys/server/* server_secret
mkdir bootstrap_files
cp ~/src/fileProxy/Code/cloudproxy/src/out/Default/bin/bootstrap .
cp ~/src/fileProxy/Code/cloudproxy/src/out/Default/bin/server .
cp ~/src/fileProxy/Code/cloudproxy/src/out/Default/bin/client .
cp ~/src/fileProxy/Code/cloudproxy/src/out/Default/bin/fserver .
cp ~/src/fileProxy/Code/cloudproxy/src/out/Default/bin/fclient .
cat sample_whitelist.pb2 | sed "s/REPLACE_ME_SERVER/`cat server | ./getHash.sh`/g" | sed "s/REPLACE_ME_CLIENT/`cat client | ./getHash.sh`/g" | sed "s/REPLACE_ME_FSERVER/`cat fserver | ./getHash.sh`/g" | sed "s/REPLACE_ME_FCLIENT/`cat fclient | ./getHash.sh`/g" > whitelist.pb2
cat whitelist.pb2 | protoc -I/home/tmroeder/src/fileProxy/Code/cloudproxy/src/tao/ --encode=tao.Whitelist /home/tmroeder/src/fileProxy/Code/cloudproxy/src/tao/hosted_programs.proto > whitelist
~/src/fileProxy/Code/cloudproxy/src/out/Default/bin/sign_whitelist 
