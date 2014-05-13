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
			'target_name' : 'tao_test',
			'type' : 'executable',
			'sources' : [
				'attestation_unittests.cc',
				# 'fd_message_channel_unittests.cc', # see 'pipe_factory_unittests.cc'
				'fd_message_channel.h',
				'keys_unittests.cc',
				'pipe_factory_unittests.cc',
				'tao_test.cc',
				'tpm_tao_unittests.cc',
				'util_unittests.cc',
				'linux_process_factory_unittests.cc',
#				'fake_tao_unittests.cc',
#				'kvm_unix_tao_channel_unittests.cc',
#				'kvm_vm_factory_unittests.cc',
#				'linux_tao_unittests.cc',
#				'process_factory_unittests.cc',
#				'tao_child_channel_registry_unittests.cc',
#				'tao_domain_unittests.cc',
#				'tpm_tao_child_channel_unittests.cc',
			],
			'include_dirs' : [
				'..',
			],
			'dependencies' : [
				'tao',
#				'tao_test_utilities',
				'../third_party/googlemock/gmock.gyp:gmock',
				'../third_party/googlemock/gtest/gtest.gyp:gtest',
			],
		},
#		{
#			'target_name' : 'tao_test_utilities',
#			'type' : 'static_library',
#			'sources' : [
#				'fake_tao_channel.h',
#				'fake_tao_channel.cc',
#				'fake_program_factory.h',
#			],
#			'include_dirs' : [
#				'..',
#			],
#			'dependencies' : [
#				'tao',
#			],
#		},
		{
			'target_name' : 'tao',
			'type' : 'static_library',
			'sources' : [
				'attestation.cc',
				'attestation.h',
				'attestation.proto',
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
				'tao_host.cc',
				'tao_host.h',
				'tao_rpc.cc',
				'tao_rpc.h',
				'tao_rpc.proto',
				'tpm_tao.cc',
				'tpm_tao.h',
				'unix_socket_factory.cc',
				'unix_socket_factory.h',
				'util.cc',
				'util.h',
#				'acl_guard.cc',
#				'acl_guard.h',
#				'acl_guard.proto',
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
#				'tao_guard.h',
#				'tao_ca_server.cc',
#				'tao_ca_server.h',
#				'tao_child_channel_registry.cc',
#				'tao_child_channel_registry.h',
#				'tao_domain.cc',
#				'tao_domain.h',
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
