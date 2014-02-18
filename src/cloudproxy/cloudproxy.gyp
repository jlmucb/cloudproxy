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
    'includes': [
      '../build/common.gypi',
    ],
  },
  'variables': {
    'proto_dir': '<(SHARED_INTERMEDIATE_DIR)/cloudproxy',
  },
  'targets': [
    {
      'target_name': 'cloudproxy_test',
      'type': 'executable',
      'sources': [
        'cloud_auth_unittests.cc',
        'cloud_client_server_unittests.cc',
        'cloud_server_thread_data_unittests.cc',
        'cloud_user_manager_unittests.cc',
        'cloudproxy_test.cc',
        'file_client_server_unittests.cc',
        'util_unittests.cc',
      ],
      'include_dirs': [
        '..',
      ],
      'dependencies': [
        'cloudproxy',
        '../tao/tao.gyp:tao',
        '../tao/tao.gyp:tao_test_utilities',
        '../third_party/googlemock/gmock.gyp:gmock',
        '../third_party/googlemock/gtest/gtest.gyp:gtest',
      ],
    },
    {
      'target_name': 'cloudproxy',
      'type': 'static_library',
      'sources': [
        'cloudproxy.proto',
        'cloud_auth.cc',
        'cloud_auth.h',
        'cloud_client.cc',
        'cloud_client.h',
        'cloud_server.cc',
        'cloud_server.h',
        'cloud_server_thread_data.cc',
        'cloud_server_thread_data.h',
        'cloud_user_manager.cc',
        'cloud_user_manager.h',
        'file_client.cc',
        'file_client.h',
        'file_server.cc',
        'file_server.h',
        'util.cc',
        'util.h',
      ],
      'libraries': [
        '-lcrypto',
        '-lssl',
        '-lpthread',
      ],
      'include_dirs': [
        '<(SHARED_INTERMEDIATE_DIR)',
        '..',
      ],
      'dependencies': [
        '../tao/tao.gyp:tao',
        '../third_party/gflags/gflags.gyp:gflags',
        '../third_party/google-glog/glog.gyp:glog',
        '../third_party/keyczar/keyczar.gyp:keyczar',
        '../third_party/protobuf/protobuf.gyp:protobuf',
      ],
      'export_dependent_settings': [
        '../third_party/gflags/gflags.gyp:gflags',
        '../third_party/google-glog/glog.gyp:glog',
        '../third_party/keyczar/keyczar.gyp:keyczar',
        '../third_party/protobuf/protobuf.gyp:protobuf',
      ],
      'includes': [
        '../build/protoc.gypi',
      ],
      'direct_dependent_settings': {
        'libraries': [
          '-lcrypto',
          '-lssl',
          '-lpthread',
        ],
        'include_dirs': [
          '<(SHARED_INTERMEDIATE_DIR)',
          '..',
        ],
      },
    },
  ]
}
