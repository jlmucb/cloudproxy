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
      '../../build/third_party_common.gypi',
    ],
  },
  'variables': {
    'src': 'src',
    'inc': 'include/chromium',
  },
  'targets': [
    {
      'target_name': 'chromium',
      'type': 'static_library',
			'defines': [
				'OS_POSIX',
				'OS_LINUX',
				'COMPILER_GCC',
			],
      'sources': [
				'<(inc)/base/file_path.h',
				'<(src)/base/file_path.cc',
				'<(src)/base/file_path_constants.cc',
				'<(src)/base/file_util.cc',
				'<(src)/base/file_util.h',
				'<(src)/base/file_util_posix.cc',
      ],
      'include_dirs': [
        'include/chromium',
      ],
      'direct_dependent_settings': {
        'include_dirs': [
          'include',
        ],
      },
    },
  ]
}
