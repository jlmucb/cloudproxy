# Copyright (c) 2014, Kevin Walsh. All rights reserved.
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
    'src': '.',
    'lua': '<(src)/lua',
  },
  'targets': [
		{
			'target_name' : 'bin2c',
			'type' : 'executable',
			'sources' : [
				'bin2c.c',
			],
		},
		{
			'target_name' : 'dl_lua',
			'type' : 'none',
			'dependencies' : [
				'bin2c',
			],
			'actions' : [
				{
					'inputs' : [ '<(PRODUCT_DIR)/bin/bin2c', 'datalog.lua' ],
					'outputs' : [ '<(SHARED_INTERMEDIATE_DIR)/dl_lua.h' ],
					'action_name' : 'bin2c', 
					'action' : [
						'<(PRODUCT_DIR)/bin/bin2c',
					  '-o', '<(SHARED_INTERMEDIATE_DIR)/dl_lua.h',
						'datalog.lua'
					],
					'message' : 'Embedding lua source in C',
				}
			]
		},
    {
      'target_name': 'lua',
      'type': 'static_library',
      'sources': [
				'<(lua)/lapi.c', 
				'<(lua)/lapi.h',
				'<(lua)/lauxlib.c', 
				'<(lua)/lauxlib.h',
				'<(lua)/lbaselib.c', 
				'<(lua)/lcode.c', 
				'<(lua)/lcode.h',
				'<(lua)/ldblib.c', 
				'<(lua)/ldebug.c', 
				'<(lua)/ldebug.h',
				'<(lua)/ldo.c', 
				'<(lua)/ldo.h',
				'<(lua)/ldump.c', 
				'<(lua)/lfunc.c', 
				'<(lua)/lfunc.h',
				'<(lua)/lgc.c', 
				'<(lua)/lgc.h',
				'<(lua)/linit.c', 
				'<(lua)/liolib.c', 
				'<(lua)/llex.c', 
				'<(lua)/llex.h',
				'<(lua)/llimits.h',
				'<(lua)/lmathlib.c', 
				'<(lua)/lmem.c', 
				'<(lua)/lmem.h',
				'<(lua)/loadlib.c', 
				'<(lua)/lobject.c', 
				'<(lua)/lobject.h',
				'<(lua)/lopcodes.c', 
				'<(lua)/lopcodes.h',
				'<(lua)/loslib.c', 
				'<(lua)/lparser.c', 
				'<(lua)/lparser.h',
				'<(lua)/lstate.c', 
				'<(lua)/lstate.h',
				'<(lua)/lstring.c', 
				'<(lua)/lstring.h',
				'<(lua)/lstrlib.c', 
				'<(lua)/ltable.c', 
				'<(lua)/ltable.h',
				'<(lua)/ltablib.c', 
				'<(lua)/ltm.c', 
				'<(lua)/ltm.h',
				'<(lua)/lua.c', 
				'<(lua)/lua.h',
				'<(lua)/luac.c', 
				'<(lua)/luaconf.h',
				'<(lua)/lualib.h',
				'<(lua)/lundump.c', 
				'<(lua)/lundump.h',
				'<(lua)/lvm.c', 
				'<(lua)/lvm.h',
				'<(lua)/lzio.c', 
				'<(lua)/lzio.h',
				'<(lua)/print.c', 
      ],
      'include_dirs': [
        '<(lua)',
      ],
      'direct_dependent_settings': {
        'include_dirs': [
          '<(lua)',
        ],
      },
    },
    {
      'target_name': 'datalog',
      'type': 'static_library',
			'dependencies' : [
				'dl_lua',
				'lua',
			],
      'sources': [
	      '<(src)/datalog.c',
	      '<(src)/datalog.h',
	      '<(src)/loader.c',
      ],
      'include_dirs': [
				'<(SHARED_INTERMEDIATE_DIR)',
        '<(src)',
      ],
      'direct_dependent_settings': {
        'include_dirs': [
          '<(src)',
          '<(lua)',
        ],
      },
    },
  ]
}
