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
    'gflags': '<(src)/gflags',
  },
  'targets': [
    {
      'target_name': 'gflags',
      'type': 'static_library',
      'sources': [
        '<(src)/config.h',
	'<(src)/gflags.cc',
	'<(src)/gflags_completions.cc',
	'<(src)/gflags_nc.cc',
	'<(src)/gflags_reporting.cc',
	'<(src)/gflags_strip_flags_test.cc',
	'<(src)/mutex.h',
	'<(src)/util.h',
	'<(gflags)/gflags_completions.h',
	'<(gflags)/gflags_declare.h',
	'<(gflags)/gflags.h',
      ],
      'include_dirs': [
        'src',
      ],
      'direct_dependent_settings': {
        'include_dirs': [
          'src',
        ],
      },
    },
  ]
}
