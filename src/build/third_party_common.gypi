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
  'product_dir': '<(PRODUCT_DIR)/bin',
  # One third_party package, google-glog, has platform dependent config.
  # Use gyp -Dtarget_arch=x64 for 64 bit config.
  # Use gyp -target_Darch=ia32 for 32 bit config.
  # Default is defined here.
  'variables': {
    'target_arch%': "x64",
  },
  'conditions': [
    [ 'target_arch == "ia32"', {
      'cflags': [
        '-m32',
      ],
      'defines': [
        'TARGET_ARCH_IA32',
      ],
    }, { # else target_arch == "x64"
      'cflags': [
        '-m64',
      ],
      'defines': [
        'TARGET_ARCH_X64',
      ],
    }],
  ],
  'configurations': {
    'Release': {
      'cflags': [
        '-O2',
      ],
    },
    'Debug': {
      'cflags': [
        '-g',
      ],
    },
  },
}

