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
	'targets' : [
		{
			'target_name' : 'make_aik',
			'type' : 'executable',
			'sources' : [
				'make_aik.cc',
			],
			'include_dirs' : [
				'.',
			],
			'libraries' : [
				'-ltspi',
			],
			'dependencies' : [
				'../third_party/gflags/gflags.gyp:gflags',
				'../third_party/google-glog/glog.gyp:glog',
				'../third_party/keyczar/keyczar.gyp:keyczar',
			],
		},
		{
			'target_name' : 'get_pcrs',
			'type' : 'executable',
			'sources' : [
				'get_pcrs.cc',
			],
			'include_dirs' : [
				'.',
			],
			'libraries' : [
				'-ltspi',
			],
			'dependencies' : [
				'../third_party/gflags/gflags.gyp:gflags',
				'../third_party/google-glog/glog.gyp:glog',
				'../third_party/keyczar/keyczar.gyp:keyczar'
			],
		},
		{
			'target_name' : 'tpm_test',
			'type' : 'executable',
			'sources' : [
				'tpm_test.cc',
			],
			'include_dirs' : [
				'.',
			],
			'libraries' : [
				'-ltspi',
				'-lcrypto',
			],
			'dependencies' : [
				'../third_party/gflags/gflags.gyp:gflags',
				'../third_party/google-glog/glog.gyp:glog',
				'../third_party/keyczar/keyczar.gyp:keyczar'
			],
		},
		{
			'target_name' : 'stop_service',
			'type' : 'executable',
			'sources' : [
				'stop_service.cc',
			],
			'dependencies' : [
				'../tao/tao.gyp:tao',
				'../third_party/gflags/gflags.gyp:gflags',
				'../third_party/google-glog/glog.gyp:glog',
			],
		},
		{
			'target_name' : 'start_hosted_program',
			'type' : 'executable',
			'sources' : [
				'start_hosted_program.cc',
			],
			'dependencies' : [
				'../tao/tao.gyp:tao',
				'../third_party/gflags/gflags.gyp:gflags',
				'../third_party/google-glog/glog.gyp:glog',
				'../third_party/keyczar/keyczar.gyp:keyczar'
			],
		},
		{
			'target_name' : 'attest_to_aik',
			'type' : 'executable',
			'sources' : [
				'attest_to_aik.cc',
			],
			'dependencies' : [
				'../tao/tao.gyp:tao',
				'../third_party/gflags/gflags.gyp:gflags',
				'../third_party/google-glog/glog.gyp:glog',
				'../third_party/keyczar/keyczar.gyp:keyczar'
			],
			'libraries' : [
				'-ltspi',
				'-lcrypto',
			],
		},
		{
			'target_name' : 'tcca',
			'type' : 'executable',
			'sources' : [
				'tcca.cc',
			],
			'dependencies' : [
				'../tao/tao.gyp:tao',
				'../third_party/gflags/gflags.gyp:gflags',
				'../third_party/google-glog/glog.gyp:glog',
				'../third_party/keyczar/keyczar.gyp:keyczar'
			],
			'libraries' : [
				'-lcrypto',
				'-lssl',
			],
		},
		{
			'target_name' : 'linux_kvm_guest_tao_service',
			'type' : 'executable',
			'sources' : [
				'linux_kvm_guest_tao_service.cc',
			],
			'dependencies' : [
				'../tao/tao.gyp:tao',
				'../third_party/gflags/gflags.gyp:gflags',
				'../third_party/google-glog/glog.gyp:glog',
				'../third_party/keyczar/keyczar.gyp:keyczar'
			],
			'libraries' : [
				'-lcrypto',
				'-lssl',
			],
		},
		{
			'target_name' : 'linux_kvm_tao_service',
			'type' : 'executable',
			'sources' : [
				'linux_kvm_tao_service.cc',
			],
			'dependencies' : [
				'../tao/tao.gyp:tao',
				'../third_party/gflags/gflags.gyp:gflags',
				'../third_party/google-glog/glog.gyp:glog',
				'../third_party/keyczar/keyczar.gyp:keyczar'
			],
			'libraries' : [
				'-lcrypto',
				'-lssl',
			],
		},
		{
			'target_name' : 'linux_tao_service',
			'type' : 'executable',
			'sources' : [
				'linux_tao_service.cc',
			],
			'dependencies' : [
				'../tao/tao.gyp:tao',
				'../tao/tao.gyp:tao_test_utilities',
				'../third_party/gflags/gflags.gyp:gflags',
				'../third_party/google-glog/glog.gyp:glog',
				'../third_party/keyczar/keyczar.gyp:keyczar'
			],
			'libraries' : [
				'-lcrypto',
				'-lssl',
			],
		},
		{
			'target_name' : 'client',
			'type' : 'executable',
			'sources' : [
				'client.cc',
			],
			'include_dirs' : [
				'..',
			],
			'dependencies' : [
				'../cloudproxy/cloudproxy.gyp:cloudproxy',
				'../tao/tao.gyp:tao',
			],
		},
		{
			'target_name' : 'fclient',
			'type' : 'executable',
			'sources' : [
				'fclient.cc',
			],
			'include_dirs' : [
				'..',
			],
			'dependencies' : [
				'../cloudproxy/cloudproxy.gyp:cloudproxy',
				'../tao/tao.gyp:tao',
			],
		},
		{
			'target_name' : 'server',
			'type' : 'executable',
			'sources' : [
				'server.cc',
			],
			'include_dirs' : [
				'..',
			],
			'dependencies' : [
				'../cloudproxy/cloudproxy.gyp:cloudproxy',
				'../tao/tao.gyp:tao',
			],
		},
		{
			'target_name' : 'fserver',
			'type' : 'executable',
			'sources' : [
				'fserver.cc',
			],
			'include_dirs' : [
				'..',
			],
			'dependencies' : [
				'../cloudproxy/cloudproxy.gyp:cloudproxy',
				'../tao/tao.gyp:tao',
			],
		},
		{
			'target_name' : 'http_echo_server',
			'type' : 'executable',
			'sources' : [
				'http_echo_server.cc',
			],
			'include_dirs' : [
				'..',
			],
			'dependencies' : [
				'../cloudproxy/cloudproxy.gyp:cloudproxy',
				'../tao/tao.gyp:tao',
			],
		},
		{
			'target_name' : 'https_echo_server',
			'type' : 'executable',
			'sources' : [
				'https_echo_server.cc',
			],
			'include_dirs' : [
				'..',
			],
			'dependencies' : [
				'../cloudproxy/cloudproxy.gyp:cloudproxy',
				'../tao/tao.gyp:tao',
			],
		},
		{
			'target_name' : 'tao_admin',
			'type' : 'executable',
			'sources' : [
				'tao_admin.cc',
			],
			'include_dirs' : [
				'..',
			],
			'dependencies' : [
				'../tao/tao.gyp:tao',
				'../tao/tao.gyp:tao_test_utilities',
				'../cloudproxy/cloudproxy.gyp:cloudproxy',
				'../third_party/gflags/gflags.gyp:gflags',
				'../third_party/google-glog/glog.gyp:glog',
				'../third_party/keyczar/keyczar.gyp:keyczar'
			],
		},
	],
}
