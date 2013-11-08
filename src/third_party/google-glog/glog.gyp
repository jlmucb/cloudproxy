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
      '-O2',
    ],
    'product_dir': 'bin',
  },
  'variables': {
    'src': 'src',
    'base': '<(src)/base',
    'glog': '<(src)/glog',
  },
  'targets': [
    {
      'target_name': 'glog',
      'type': 'static_library',
      'sources': [
        '<(src)/config.h',
	'<(src)/demangle.cc',
	'<(src)/demangle.h',
	'<(src)/googletest.h',
	'<(src)/logging.cc',
	'<(src)/raw_logging.cc',
	'<(src)/signalhandler.cc',
	'<(src)/stacktrace_generic-inl.h',
	'<(src)/stacktrace.h',
	'<(src)/stacktrace_libunwind-inl.h',
	'<(src)/stacktrace_powerpc-inl.h',
	'<(src)/stacktrace_unittest.cc',
	'<(src)/stacktrace_x86_64-inl.h',
	'<(src)/stacktrace_x86-inl.h',
	'<(src)/symbolize.cc',
	'<(src)/symbolize.h',
	'<(src)/utilities.cc',
	'<(src)/utilities.h',
	'<(src)/vlog_is_on.cc',
	'<(base)/commandlineflags.h',
	'<(base)/googleinit.h',
	'<(base)/mutex.h',
	'<(glog)/logging.h',
	'<(glog)/log_severity.h',
	'<(glog)/raw_logging.h',
	'<(glog)/stl_logging.h',
	'<(glog)/vlog_is_on.h',
      ],
      'include_dirs': [
        'src',
      ],
      'direct_dependent_settings': {
        'include_dirs': [
          'src',
        ],
	'libraries': [
	  '-lpthread',
	],
      },
    },
  ]
}
