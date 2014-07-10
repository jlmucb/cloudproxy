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
	'target_defaults' : {
		'includes' : [
			'../build/common.gypi',
		],
	},
	'variables' : {
		'proto_dir' : '<(SHARED_INTERMEDIATE_DIR)/tao',
	},
	'targets' : [
		{
			'target_name' : 'auth_lua',
			'type' : 'none',
			'dependencies' : [
				'../third_party/datalog/datalog.gyp:bin2c',
			],
			'actions' : [
				{
					'inputs' : [ '<(PRODUCT_DIR)/bin/bin2c', 'auth.lua' ],
					'outputs' : [ '<(SHARED_INTERMEDIATE_DIR)/tao/auth_lua.h' ],
					'action_name' : 'bin2c', 
					'action' : [
						'<(PRODUCT_DIR)/bin/bin2c',
					  '-o', '<(SHARED_INTERMEDIATE_DIR)/tao/auth_lua.h',
						'auth.lua'
					],
					'message' : 'Embedding lua source in C',
				}
			]
		},
		{
			'target_name' : 'tao_test',
			'type' : 'executable',
			'sources' : [
				'attestation_unittests.cc',
				'auth_unittests.cc', 
				'datalog_guard_unittests.cc',
				'keys_unittests.cc',
				'linux_host_unittests.cc',
				'linux_process_factory_unittests.cc',
				'pipe_factory_unittests.cc',
				'tao_domain_unittests.cc', 
				'tao_test.cc',
				'tao_test.h',
				'tao_unittests.cc',
				'unix_socket_factory_unittests.cc',
				'util_unittests.cc',
			],
			'include_dirs' : [
				'..',
			],
			'dependencies' : [
				'tao',
				'../third_party/googlemock/gmock.gyp:gmock',
				'../third_party/googlemock/gtest/gtest.gyp:gtest',
			],
		},
		{
			'target_name' : 'tao',
			'type' : 'static_library',
			'sources' : [
				'acl_guard.cc', # unit test: tao_domain_unittests.cc
				'acl_guard.h', # unit test: tao_domain_unittests.cc
				'acl_guard.proto', # unit test: tao_domain_unittests.cc
				'attestation.cc', # unit test: attestation_unittests.cc
				'attestation.h', # unit test: attestation_unittests.cc
				'attestation.proto', # unit test: attestation_unittests.cc
				'auth.cc', # unit test: auth_unittests.cc
				'auth.h', # unit test: auth_unittests.cc
				'datalog_guard.cc', # unit test: datalog_guard_unittests.cc, tao_domain_unittests.cc
				'datalog_guard.h', # unit test: datalog_guard_unittests.cc, tao_domain_unittests.cc
				'datalog_guard.proto', # unit test: datalog_guard_unittests.cc, tao_domain_unittests.cc
				'fd_message_channel.cc', # unit test: pipe_factory_unittests.cc
				'fd_message_channel.h', # unit test: pipe_factory_unittests.cc
				'keys.cc', # unit test: keys_unittests.cc
				'keys.h', # unit test: keys_unittests.cc
				'keys.proto', # unit test: keys_unittests.cc
				'linux_admin_rpc.cc', # unit test: linux_host_unittests.cc
				'linux_admin_rpc.h', # unit test: linux_host_unittests.cc
				'linux_admin_rpc.proto', # unit test: linux_host_unittests.cc
				'linux_host.cc', # unit test: linux_host_unittests.cc
				'linux_host.h', # unit test: linux_host_unittests.cc
				'linux_host.proto', # unit test: linux_host_unittests.cc
				'linux_process_factory.cc', # unit test: linux_process_factory_unittests.cc
				'linux_process_factory.h', # unit test: linux_process_factory_unittests.cc
				'log_net.cc', # no unit test needed
				'log_net.h', # no unit test needed
				'log_net.proto', # no unit test needed
				'message_channel.cc', # unit test: pipe_factory_unittests.cc
				'message_channel.h', # unit test: pipe_factory_unittests.cc
				'pipe_factory.cc', # unit test: pipe_factory_unittests.cc
				'pipe_factory.h', # unit test: pipe_factory_unittests.cc
				'soft_tao.cc', # unit test: tao_unittests.cc
				'soft_tao.h', # unit test: tao_unittests.cc
				'tao.cc', # unit test: tao_unittests.cc, linux_host_unittests.cc
				'tao.h', # unit test: tao_unittests.cc, linux_host_unittests.cc
				'tao_domain.cc', # unit test: tao_domain_unittests.cc
				'tao_domain.h', # unit test: tao_domain_unittests.cc
				'tao_guard.cc', # unit test: tao_domain_unittests.cc
				'tao_guard.h', # unit test: tao_domain_unittests.cc
				'tao_host.h', # unit test: linux_host_unittests.cc
				'tao_root_host.cc',
				'tao_root_host.h',
				'tao_rpc.cc', # unit test: linux_host_unittests.cc
				'tao_rpc.h', # unit test: linux_host_unittests.cc
				'tao_rpc.proto', # unit test: linux_host_unittests.cc
				'tao_stacked_host.cc',
				'tao_stacked_host.h',
				'tpm_tao.cc', # unit test: tao_unittests.cc
				'tpm_tao.h', # unit test: tao_unittests.cc
				'trivial_guard.h', # unit test: tao_domain_unittests.cc
				'unix_socket_factory.cc', # unit test: unix_socket_factory_unittests.cc
				'unix_socket_factory.h', # unit test: unix_socket_factory_unittests.cc
				'util.cc', # unit test: util_unittests.cc
				'util.h', # unit test: util_unittests.cc
			],
			'libraries' : [
				'-lcrypto',
				'-lssl',
				'-ltspi',
				'-lvirt',
			],
			'include_dirs' : [
				'<(SHARED_INTERMEDIATE_DIR)',
				'..',
			],
			'includes' : [
				'../build/protoc.gypi',
			],
			'dependencies' : [
				'auth_lua',
				'../third_party/datalog/datalog.gyp:datalog',
				'../third_party/gflags/gflags.gyp:gflags',
				'../third_party/google-glog/glog.gyp:glog',
				'../third_party/keyczar/keyczar.gyp:keyczar',
				'../third_party/protobuf/protobuf.gyp:protobuf',
				'../third_party/libb64/libb64.gyp:b64',
				'../third_party/modp/modp.gyp:modp',
			],
			'direct_dependent_settings' : {
				'libraries' : [
					'-lcrypto',
					'-lssl',
					'-ltspi',
					'-lvirt',
				],
				'include_dirs' : [
					'<(SHARED_INTERMEDIATE_DIR)',
					'..',
				],
			},
			'export_dependent_settings' : [
				'../third_party/gflags/gflags.gyp:gflags',
				'../third_party/google-glog/glog.gyp:glog',
				'../third_party/keyczar/keyczar.gyp:keyczar',
				'../third_party/protobuf/protobuf.gyp:protobuf',
				'../third_party/libb64/libb64.gyp:b64',
				'../third_party/modp/modp.gyp:modp',
			],
		},
	],
}
