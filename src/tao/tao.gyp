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
					'outputs' : [ '<(SHARED_INTERMEDIATE_DIR)/auth_lua.h' ],
					'action_name' : 'bin2c', 
					'action' : [
						'<(PRODUCT_DIR)/bin/bin2c',
					  '-o', '<(SHARED_INTERMEDIATE_DIR)/auth_lua.h',
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
				# 'acl_guard.cc', see 'tao_domain_unittests.cc'
				'auth_unittests.cc', 
				'attestation_unittests.cc',
				'datalog_guard_unittests.cc', # also see 'tao_domain_unittests.cc'
				# 'fd_message_channel.cc', see 'pipe_factory_unittests.cc'
				'keys_unittests.cc',
				# 'linux_admin_rpc.cc', see 'linux_host_unittests.cc'
				'linux_host_unittests.cc',
				'linux_process_factory_unittests.cc',
				'pipe_factory_unittests.cc',
				# 'soft_tao.cc', see 'tao_unittests.cc'
				# 'tao.cc', see 'linux_host_unittests.cc'
				'tao_domain_unittests.cc', 
				# 'tao_host.cc', see 'linux_host_unittests.cc'
				# 'tao_rpc.cc', see 'linux_host_unittests.cc'
				'tao_test.cc',
				'tao_unittests.cc',
				# 'tpm_tao.cc' see 'tao_unittests.cc'
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
				'acl_guard.cc',
				'acl_guard.h',
				'acl_guard.proto',
				'attestation.cc',
				'attestation.h',
				'attestation.proto',
				'auth.cc',
				'auth.h',
				'datalog_guard.cc',
				'datalog_guard.h',
				'datalog_guard.proto',
				'fd_message_channel.cc',
				'fd_message_channel.h',
				'keys.cc',
				'keys.h',
				'keys.proto',
				'linux_admin_rpc.cc',
				'linux_admin_rpc.h',
				'linux_admin_rpc.proto',
				'linux_host.cc',
				'linux_host.h',
				'linux_host.proto',
				'linux_process_factory.cc',
				'linux_process_factory.h',
				'message_channel.h',
				'pipe_factory.cc',
				'pipe_factory.h',
				'signature.proto',
				'soft_tao.cc',
				'soft_tao.h',
				'tao.cc',
				'tao.h',
				'tao_domain.cc',
				'tao_domain.h',
				'tao_guard.cc',
				'tao_guard.h',
				'tao_host.h',
				'tao_root_host.cc',
				'tao_root_host.h',
				'tao_rpc.cc',
				'tao_stacked_host.cc',
				'tao_stacked_host.h',
				'tao_rpc.h',
				'tao_rpc.proto',
				'tpm_tao.cc',
				'tpm_tao.h',
				'trivial_guard.h',
				'unix_socket_factory.cc',
				'unix_socket_factory.h',
				'util.cc',
				'util.h',
#				'hosted_program_factory.h',
#				'kvm_unix_tao_channel.cc',
#				'kvm_unix_tao_channel.h',
#				'kvm_unix_tao_channel_params.proto',
#				'kvm_unix_tao_child_channel.cc',
#				'kvm_unix_tao_child_channel.h',
#				'kvm_vm_factory.cc',
#				'kvm_vm_factory.h',
#				'tao_ca.cc',
#				'tao_ca.h',
#				'tao_ca.proto',
#				'tao_ca_server.cc',
#				'tao_ca_server.h',
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
			],
		},
	],
}
