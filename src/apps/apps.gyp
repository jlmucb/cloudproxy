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

{
  'target_defaults': {
    'cflags': [
      '-Wall',
      '-Werror',
      '-std=c++0x',
    ],
    'product_dir': 'bin',
  },
  'targets': [
    {
      'target_name': 'tpm_test',
      'type': 'executable',
      'sources': [ 'tpm_test.cc', ],
      'include_dirs': [ '.', ],
      'libraries': [
	    '-ltspi',
        '-lcrypto',
      ],
      'dependencies': [
	'../third_party/gflags/gflags.gyp:gflags',
	'../third_party/google-glog/glog.gyp:glog',
        '../third_party/keyczar/keyczar.gyp:keyczar'
      ],
    },
    {
      'target_name': 'convert_aik_to_pem',
      'type': 'executable',
      'sources': [ 'convert_aik_to_pem.cc', ],
      'dependencies': [ 
        '../third_party/gflags/gflags.gyp:gflags',
        '../third_party/google-glog/glog.gyp:glog',
        '../third_party/keyczar/keyczar.gyp:keyczar'
      ],
      'libraries': [
        '-ltspi',
        '-lcrypto',
      ],
    },
    {
      'target_name': 'linux_tao_service',
      'type': 'executable',
      'sources': [ 'linux_tao_service.cc', ],
      'dependencies': [ 
        '../tao/tao.gyp:tao',
        '../third_party/gflags/gflags.gyp:gflags',
        '../third_party/google-glog/glog.gyp:glog',
      ],
      'libraries': [
        '-lcrypto',
        '-lssl',
      ],
    },
    {
      'target_name': 'test',
      'type': 'executable',
      'sources': [ 'main.cc', ],
      'include_dirs': [ '.', ],
      'dependencies': [ '../cloudproxy/cloudproxy.gyp:cloudproxy', ],
    },
    {
      'target_name': 'sign_acls',
      'type': 'executable',
      'sources': [ 'sign_acls.cc', ],
      'include_dirs': [ '..', ],
      'dependencies': [ '../cloudproxy/cloudproxy.gyp:cloudproxy', ],
    },
    {
      'target_name': 'verify_acls',
      'type': 'executable',
      'sources': [ 'verify_acls.cc', ],
      'include_dirs': [ '..', ],
      'dependencies': [ '../cloudproxy/cloudproxy.gyp:cloudproxy', ],
    },
    {
      'target_name': 'sign_pub_key',
      'type': 'executable',
      'sources': [ 'sign_pub_key.cc', ],
      'include_dirs': [ '..', ],
      'dependencies': [ '../cloudproxy/cloudproxy.gyp:cloudproxy', ],
    },
    {
      'target_name': 'verify_pub_key',
      'type': 'executable',
      'sources': [ 'verify_pub_key.cc', ],
      'include_dirs': [ '..', ],
      'dependencies': [ '../cloudproxy/cloudproxy.gyp:cloudproxy', ],
    },
    {
      'target_name': 'client',
      'type': 'executable',
      'sources': [ 'client.cc', ],
      'include_dirs': [ '..', ],
      'dependencies': [
        '../cloudproxy/cloudproxy.gyp:cloudproxy',
	'../tao/tao.gyp:tao',
      ],
    },
    {
      'target_name': 'fclient',
      'type': 'executable',
      'sources': [ 'fclient.cc', ],
      'include_dirs': [ '..', ],
      'dependencies': [
        '../cloudproxy/cloudproxy.gyp:cloudproxy',
	'../tao/tao.gyp:tao',
      ],
    },
    {
      'target_name': 'server',
      'type': 'executable',
      'sources': [ 'server.cc', ],
      'include_dirs': [ '..', ],
      'dependencies': [
         '../cloudproxy/cloudproxy.gyp:cloudproxy',
         '../tao/tao.gyp:tao',
      ],
    },
    {
      'target_name': 'server_test',
      'type': 'executable',
      'sources': [ 'server_test.cc', ],
      'include_dirs': [ '..', ],
      'dependencies': [
         '../cloudproxy/cloudproxy.gyp:cloudproxy',
         '../tao/tao.gyp:tao',
	 '../tao/tao.gyp:tao_test_utilities',
      ],
    },
    {
      'target_name': 'fserver',
      'type': 'executable',
      'sources': [ 'fserver.cc', ],
      'include_dirs': [ '..', ],
      'dependencies': [
         '../cloudproxy/cloudproxy.gyp:cloudproxy',
         '../tao/tao.gyp:tao',
      ],
    },
    {
      'target_name': 'create_ecdsa',
      'type': 'executable',
      'sources': [ 'create_ecdsa.cc', ],
      'include_dirs': [ '..', ],
      'dependencies': [
         '../cloudproxy/cloudproxy.gyp:cloudproxy',
      ],
    },
    {
      'target_name': 'hash_file',
      'type': 'executable',
      'sources': [ 'hash_file.cc', ],
      'include_dirs': [ '..', ],
      'libraries' : [
        '-lcrypto',
      ],
      'dependencies': [
        '../third_party/google-glog/glog.gyp:glog',
	'../third_party/gflags/gflags.gyp:gflags',
	'../third_party/keyczar/keyczar.gyp:keyczar',
      ],        
    },
    {
      'target_name': 'sign_whitelist',
      'type': 'executable',
      'sources': [ 'sign_whitelist.cc', ],
      'include_dirs': [ '..', ],
      'dependencies': [ '../tao/tao.gyp:tao', ],
    },
   # {
   #    'target_name': 'bootstrap',
   #    'type': 'executable',
   #    'sources': [ 'bootstrap.cc', ],
   #    'include_dirs': [ '..', ],
   #    'dependencies': [
   #      '../legacy_tao/legacy_tao.gyp:legacy_tao_channel',
   #    ],
   #  },
  ]
}
