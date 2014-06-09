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
		'proto_dir' : '<(SHARED_INTERMEDIATE_DIR)/apps',
	},
	'targets' : [
		{
			'target_name' : 'tpm_tao',
			'type' : 'executable',
			'sources' : [
				'tpm_tao.cc',
			],
			'include_dirs' : [
				'.',
			],
			#			'libraries' : [
			#				'-ltspi',
			#			],
			'dependencies' : [
				'../tao/tao.gyp:tao',
				'../third_party/gflags/gflags.gyp:gflags',
				'../third_party/google-glog/glog.gyp:glog',
				'../third_party/keyczar/keyczar.gyp:keyczar',
			],
		},
		{
			'target_name' : 'soft_tao',
			'type' : 'executable',
			'sources' : [
				'soft_tao.cc',
			],
			'include_dirs' : [
				'.',
			],
			#			'libraries' : [
			#				'-ltspi',
			#			],
			'dependencies' : [
				'../tao/tao.gyp:tao',
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
			#			'libraries' : [
			#				'-ltspi',
			#			],
			'dependencies' : [
				'../tao/tao.gyp:tao',
				'../third_party/gflags/gflags.gyp:gflags',
				'../third_party/google-glog/glog.gyp:glog',
				'../third_party/keyczar/keyczar.gyp:keyczar'
			],
		},
#		{
#			'target_name' : 'tcca',
#			'type' : 'executable',
#			'sources' : [
#				'tcca.cc',
#			],
#			'dependencies' : [
#				'../tao/tao.gyp:tao',
#				'../third_party/gflags/gflags.gyp:gflags',
#				'../third_party/google-glog/glog.gyp:glog',
#				'../third_party/keyczar/keyczar.gyp:keyczar'
#			],
#			'libraries' : [
#				'-lcrypto',
#				'-lssl',
#			],
#		},
#		{
#			'target_name' : 'linux_kvm_guest_tao_service',
#			'type' : 'executable',
#			'sources' : [
#				'linux_kvm_guest_tao_service.cc',
#			],
#			'dependencies' : [
#				'../tao/tao.gyp:tao',
#				'../third_party/gflags/gflags.gyp:gflags',
#				'../third_party/google-glog/glog.gyp:glog',
#				'../third_party/keyczar/keyczar.gyp:keyczar'
#			],
#			'libraries' : [
#				'-lcrypto',
#				'-lssl',
#			],
#		},
#		{
#			'target_name' : 'linux_kvm_tao_service',
#			'type' : 'executable',
#			'sources' : [
#				'linux_kvm_tao_service.cc',
#			],
#			'dependencies' : [
#				'../tao/tao.gyp:tao',
#				'../third_party/gflags/gflags.gyp:gflags',
#				'../third_party/google-glog/glog.gyp:glog',
#				'../third_party/keyczar/keyczar.gyp:keyczar'
#			],
#			'libraries' : [
#				'-lcrypto',
#				'-lssl',
#			],
#		},
		{
			'target_name' : 'linux_host',
			'type' : 'executable',
			'sources' : [
				'linux_host.cc',
			],
			'dependencies' : [
				'../tao/tao.gyp:tao',
				'../third_party/gflags/gflags.gyp:gflags',
				'../third_party/google-glog/glog.gyp:glog',
				'../third_party/keyczar/keyczar.gyp:keyczar'
			],
			#			'libraries' : [
			#				'-lcrypto',
			#				'-lssl',
			#			],
		},
#		{
#			'target_name' : 'client',
#			'type' : 'executable',
#			'sources' : [
#				'client.cc',
#			],
#			'include_dirs' : [
#				'..',
#			],
#			'dependencies' : [
#				'../cloudproxy/cloudproxy.gyp:cloudproxy',
#				'../tao/tao.gyp:tao',
#			],
#		},
#		{
#			'target_name' : 'fclient',
#			'type' : 'executable',
#			'sources' : [
#				'fclient.cc',
#			],
#			'include_dirs' : [
#				'..',
#			],
#			'dependencies' : [
#				'../cloudproxy/cloudproxy.gyp:cloudproxy',
#				'../tao/tao.gyp:tao',
#			],
#		},
#		{
#			'target_name' : 'server',
#			'type' : 'executable',
#			'sources' : [
#				'server.cc',
#			],
#			'include_dirs' : [
#				'..',
#			],
#			'dependencies' : [
#				'../cloudproxy/cloudproxy.gyp:cloudproxy',
#				'../tao/tao.gyp:tao',
#			],
#		},
#		{
#			'target_name' : 'fserver',
#			'type' : 'executable',
#			'sources' : [
#				'fserver.cc',
#			],
#			'include_dirs' : [
#				'..',
#			],
#			'dependencies' : [
#				'../cloudproxy/cloudproxy.gyp:cloudproxy',
#				'../tao/tao.gyp:tao',
#			],
#		},
#		{
#			'target_name' : 'http_echo_server',
#			'type' : 'executable',
#			'sources' : [
#				'http_echo_server.cc',
#			],
#			'include_dirs' : [
#				'..',
#			],
#			'dependencies' : [
#				'../cloudproxy/cloudproxy.gyp:cloudproxy',
#				'../tao/tao.gyp:tao',
#			],
#		},
#		{
#			'target_name' : 'https_echo_server',
#			'type' : 'executable',
#			'sources' : [
#				'https_echo_server.cc',
#			],
#			'include_dirs' : [
#				'..',
#			],
#			'dependencies' : [
#				'../cloudproxy/cloudproxy.gyp:cloudproxy',
#				'../tao/tao.gyp:tao',
#			],
#		},
		{
			'target_name' : 'demo',
			'type' : 'executable',
			'sources' : [ 'demo.cc', ],
			'include_dirs' : [ '..', ],
			'dependencies' : [ '../tao/tao.gyp:tao', ],
		},
		{
			'target_name' : 'demo_server',
			'type' : 'executable',
			'sources' : [ 'demo_server.cc', 'demo_server.proto', ],
			'include_dirs' : [ '..', ],
			'dependencies' : [ '../cloudproxy/cloudproxy.gyp:cloudproxy', ],
			'includes' : [ '../build/protoc.gypi', ],
		},
		{
			'target_name' : 'log_net_server',
			'type' : 'executable',
			'sources' : [ 'log_net_server.cc' ],
			'include_dirs' : [ '..', ],
			'dependencies' : [ '../tao/tao.gyp:tao', ],
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
				#'../cloudproxy/cloudproxy.gyp:cloudproxy',
				'../third_party/gflags/gflags.gyp:gflags',
				'../third_party/google-glog/glog.gyp:glog',
				'../third_party/keyczar/keyczar.gyp:keyczar'
			],
		},
	],
}
