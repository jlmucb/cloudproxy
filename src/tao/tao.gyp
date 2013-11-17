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
  'variables': {
    'proto_dir': '<(SHARED_INTERMEDIATE_DIR)/tao',
  },
  'targets': [
    {
      'target_name': 'fake_tao_unittests',
      'type': 'executable',
      'sources': [
        'fake_tao_unittests.cc',
      ],
      'include_dirs': [
        '..',
      ],
      'dependencies': [
        'tao',
        'tao_test_utilities',
        '../third_party/googlemock/gmock.gyp:gmock',
        '../third_party/googlemock/gtest/gtest.gyp:gtest',
      ],
    },
    {
      'target_name': 'linux_tao_unittests',
      'type': 'executable',
      'sources': [
	    'linux_tao_unittests.cc',
      ],
      'include_dirs': [
        '..',
      ],
      'dependencies': [
        'tao',
        'tao_test_utilities',
        '../third_party/googlemock/gmock.gyp:gmock',
        '../third_party/googlemock/gtest/gtest.gyp:gtest',
      ],
    },
    {
      'target_name': 'tao_test_utilities',
      'type': 'static_library',
      'sources': [
	'fake_tao.h',
	'fake_tao.cc',
        'fake_program_factory.h',
      ],
      'include_dirs': [
        '..',
      ],
      'dependencies': [
        'tao',
      ],
    },
    {
      'target_name': 'tao',
      'type': 'static_library',
      'sources': [
        'attestation.proto',
	'direct_tao_channel.cc',
	'direct_tao_channel.h',
        'hosted_programs.proto',
        'hosted_program_factory.h',
	'keyczar_public_key.proto',
        'linux_tao.cc',
        'linux_tao.h',
        'pipe_tao_channel.cc',
        'pipe_tao_channel_factory.cc',
        'pipe_tao_channel_factory.h',
        'pipe_tao_channel.h',
        'pipe_tao_channel_params.proto',
        'process_factory.cc',
        'process_factory.h',
	'sealed_data.proto',
	'tao_auth.h',
        'tao_channel.cc',
        'tao_channel_factory.h',
        'tao_channel.h',
        'tao_channel_rpc.proto',
        'tao_binary_cache.h',
        'tao.h',
	'util.cc',
	'util.h',
	'whitelist_auth.h',
	'whitelist_auth.cc',
      ],
      'libraries': [
        '-lcrypto',
        '-lssl',
      ],
      'include_dirs': [
        '<(SHARED_INTERMEDIATE_DIR)',
        '..',
      ],
      'includes': [
        '../build/protoc.gypi',
      ],
      'dependencies': [
	'../third_party/gflags/gflags.gyp:gflags',
	'../third_party/google-glog/glog.gyp:glog',
	'../third_party/keyczar/keyczar.gyp:keyczar',
	'../third_party/protobuf/protobuf.gyp:protobuf',
      ],        
      'direct_dependent_settings': {
        'libraries': [
          '-lcrypto',
          '-lssl',
        ],
        'include_dirs': [
          '<(SHARED_INTERMEDIATE_DIR)',
          '..',
        ],
      },
      'export_dependent_settings': [
	'../third_party/gflags/gflags.gyp:gflags',
	'../third_party/google-glog/glog.gyp:glog',
	'../third_party/keyczar/keyczar.gyp:keyczar',
	'../third_party/protobuf/protobuf.gyp:protobuf',
      ],
    },
  ]
}
