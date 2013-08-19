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
  'variables': {
    'basesrc': '../..',
    'ac': '<(basesrc)/accessControl',
    'ch': '<(basesrc)/channels',
    'cl': '<(basesrc)/claims',
	'cm': '<(basesrc)/commonCode',
    'fp': '<(basesrc)/fileProxy',
    'kn': '<(basesrc)/keyNegoServer',
	'jb': '<(basesrc)/jlmbignum',
	'jc': '<(basesrc)/jlmcrypto',
    'pr': '<(basesrc)/protocolChannel',
    'ta': '<(basesrc)/tao',
    'tc': '<(basesrc)/tcService',
    'tp': '<(basesrc)/TPMDirect',
    'vt': '<(basesrc)/vault',
    'tao_sources': [
      '<(ta)/tao.h',
      '<(ta)/trustedKeyNego.h',
      '<(ta)/trustedKeyNego.cpp',
      '<(ta)/taoEnvironment.cpp',
      '<(ta)/taoHostServices.cpp',
      '<(ta)/taoInit.cpp',
      '<(ta)/taoSupport.cpp',
      '<(ta)/TPMHostsupport.h',
      '<(ta)/TPMHostsupport.cpp',
      '<(ta)/linuxHostsupport.h',
      '<(ta)/linuxHostsupport.cpp',
      '<(tp)/hashprep.h',
      '<(tp)/hashprep.cpp',
      '<(tp)/hmacsha1.h',
      '<(tp)/hmacsha1.cpp',
      '<(tp)/vTCIDirect.h',
      '<(tp)/vTCIDirect.cpp',
      '<(tc)/tcIO.h',
      '<(tc)/tcIO.cpp',
      '<(tc)/buffercoding.h',
      '<(tc)/buffercoding.cpp',
    ],
    'support_sources': [
      '<(ac)/accessControl.h',
      '<(ac)/accessControl.cpp',
      '<(ac)/signedAssertion.h',
      '<(ac)/signedAssertion.cpp',
      '<(ch)/channel.h',
      '<(ch)/channel.cpp',
      '<(ch)/safeChannel.h',
      '<(ch)/safeChannel.cpp',
      '<(cl)/cert.h',
      '<(cl)/cert.cpp',
      '<(cl)/quote.h',
      '<(cl)/quote.cpp',
      '<(cl)/validateEvidence.h',
      '<(cl)/validateEvidence.cpp',
      '<(pr)/channelstate.h',
      '<(pr)/request.h',
      '<(pr)/request.cpp',
      '<(pr)/session.h',
      '<(pr)/session.cpp',
      '<(fp)/resource.h',
      '<(fp)/resource.cpp',
      '<(vt)/vault.h',
      '<(vt)/vault.cpp',
    ],
  },
  'target_defaults': {
    'product_dir': 'bin',
    'cflags': [
      '-Wall',
      '-Werror',
      '-Wno-format',
      '-Wno-unknown-pragmas',
    ],
  },
  'targets': [
    {
      'target_name': 'jlmcommon',
      'type': 'static_library',
      'cflags': [
	    '-O3',
      ],
      'sources': [
	    '<(cm)/jlmTypes.h',
	    '<(cm)/jlmUtility.h',
	    '<(cm)/jlmUtility.cpp',
	    '<(cm)/logging.h',
	    '<(cm)/logging.cpp',
	    '<(cm)/objectManager.h',
	    '<(cm)/timer.h',
	    '<(cm)/tinystr.h',
	    '<(cm)/tinystr.cpp',
	    '<(cm)/tinyxml.h',
	    '<(cm)/tinyxml.cpp',
	    '<(cm)/tinyxmlerror.cpp',
	    '<(cm)/tinyxmlparser.cpp',
      ],
      'include_dirs': [
        '<(cm)',
        '<(jc)',
        '<(jb)',
      ],
      'libraries': [
	    '-lpthread',
      ],
	  'defines': [
	    'LINUX',
	    'TEST',
	    '__FLUSHIO__',
	    'TIXML_USE_STL',
	  ],
      'direct_dependent_settings': {
	    'include_dirs': [
	      '<(cm)',
          '<(jc)',
          '<(jb)',
	    ],
	    'defines': [
	      'LINUX',
	      'TEST',
	      '__FLUSHIO__',
	      'TIXML_USE_STL',
	    ],
	    'libraries': [
	      '-lpthread',
	    ],
      },
    },
    {
      'target_name': 'jlmbignum',
      'type': 'static_library',
      # should add a condition for aes/aesni
      'sources': [
    	# bignum
    	'<(jb)/fastArith.h',
    	'<(jb)/fastArith.cpp',
    	'<(jb)/mpFunctions.h',
    	'<(jb)/mpBasicArith.cpp',
    	'<(jb)/mpModArith.cpp',
    	'<(jb)/mpNumTheory.cpp',
    	'<(jb)/mpRand.cpp',
    	'<(jb)/bignum.h',
      ],
      'dependencies': [
	    'jlmcommon',
      ],
      'direct_dependent_settings': {
	    'include_dirs': [
	      '<(jb)',
	    ],
      },
      'export_dependent_settings': [
	    'jlmcommon',
      ],
    },
    {
      'target_name': 'jlmcrypto',
      'type': 'static_library',
      'cflags': [
	    '-O3',
      ],
      'defines': [
	'ENCRYPTTHENMAC',
      ],
      'sources': [
    	# core crypto
    	'<(jc)/algs.h',
    	'<(jc)/cryptoHelper.h',
    	'<(jc)/cryptoHelper.cpp',
    	'<(jc)/encryptedblockIO.h',
    	'<(jc)/encryptedblockIO.cpp',
    	'<(jc)/fileHash.h',
    	'<(jc)/fileHash.cpp',
    	'<(jc)/jlmcrypto.h',
    	'<(jc)/jlmcrypto.cpp',
    	'<(jc)/keys.h',
    	'<(jc)/keys.cpp',
    	'<(jc)/modesandpadding.cpp',
    	'<(jc)/hmacsha256.h',
    	'<(jc)/hmacsha256.cpp',
    	'<(jc)/sha1.cpp',
    	'<(jc)/sha256.cpp',
    	'<(jc)/aesni.h',
    	'<(jc)/aesni.cpp',
    	'<(jc)/encapsulate.h',
    	'<(jc)/encapsulate.cpp',
      ],
      'dependencies': [
    	'jlmbignum',
    	'jlmcommon',
      ],
      'direct_dependent_settings': {
	    'include_dirs': [
	      '<(jc)',
	    ],
      },
      'export_dependent_settings': [
	    'jlmcommon',
	    'jlmbignum',
      ],
    },
    {
      'target_name': 'jlmsupportclient',
      'type': 'static_library',
      'cflags': [
        '-O3',
      ],
      'sources': [
        '<@(support_sources)',
      ],
      'defines': [
        'FILECLIENT',
      ],
	  'include_dirs': [
	    '<(ac)',
	    '<(ch)',
	    '<(cl)',
	    '<(pr)',
	    '<(fp)',
	    '<(vt)',
        '<(ta)',
        '<(tp)',
	  ],
      'dependencies': [
        'jlmcrypto',
        'jlmbignum',
        'jlmcommon',
      ],
      'direct_dependent_settings': {
	    'include_dirs': [
	      '<(ac)',
	      '<(ch)',
	      '<(cl)',
	      '<(pr)',
	      '<(fp)',
	      '<(vt)',
          '<(ta)',
          '<(tp)',
	    ],
        'defines': [
          'FILECLIENT',
        ],
      },
      'export_dependent_settings': [
	    'jlmcommon',
	    'jlmbignum',
	    'jlmcrypto',
      ],
    },
    {
      'target_name': 'jlmsupport',
      'type': 'static_library',
      'cflags': [
        '-O3',
      ],
      'sources': [
        '<@(support_sources)',
      ],
	  'include_dirs': [
	    '<(ac)',
	    '<(ch)',
	    '<(cl)',
	    '<(pr)',
	    '<(fp)',
	    '<(vt)',
        '<(ta)',
        '<(tp)',
	  ],
      'dependencies': [
        'jlmcrypto',
        'jlmbignum',
        'jlmcommon',
      ],
      'direct_dependent_settings': {
	    'include_dirs': [
	      '<(ac)',
	      '<(ch)',
	      '<(cl)',
	      '<(pr)',
	      '<(fp)',
	      '<(vt)',
          '<(ta)',
          '<(tp)',
	    ],
      },
      'export_dependent_settings': [
	    'jlmcommon',
	    'jlmbignum',
	    'jlmcrypto',
      ],
    },
    {
      'target_name': 'tao',
      'type': 'static_library',
      'variables': {
      },
      'cflags': [
        '-O3',
      ],
      'sources': [
        '<@(tao_sources)',
      ],
	  'include_dirs': [
	    '<(ta)',
	    '<(tp)',
	    '<(tc)',
	  ],
      'dependencies': [
        'jlmsupport',
        'jlmcrypto',
        'jlmbignum',
        'jlmcommon',
      ],
      'direct_dependent_settings': {
	    'include_dirs': [
	      '<(ta)',
	      '<(tp)',
	      '<(tc)',
	    ],
      },
      'export_dependent_settings': [
    	'jlmcommon',
    	'jlmbignum',
    	'jlmcrypto',
    	'jlmsupport',
      ],
    },
    {
      'target_name': 'taoquote',
      'type': 'static_library',
      'variables': {
      },
      'cflags': [
        '-O3',
      ],
      'defines': [
        'QUOTE2_DEFINED',
      ],
      'sources': [
        '<@(tao_sources)',
      ],
	  'include_dirs': [
	    '<(ta)',
	    '<(tp)',
	    '<(tc)',
	  ],
      'dependencies': [
        'jlmsupport',
        'jlmcrypto',
        'jlmbignum',
        'jlmcommon',
      ],
      'direct_dependent_settings': {
    	'include_dirs': [
    	  '<(ta)',
    	  '<(tp)',
    	  '<(tc)',
    	],
      },
      'export_dependent_settings': [
    	'jlmcommon',
    	'jlmbignum',
    	'jlmcrypto',
    	'jlmsupport',
      ],
    },
    {
      'target_name': 'taotpmquote',
      'type': 'static_library',
      'variables': {
      },
      'cflags': [
        '-O3',
      ],
      'defines': [
        'QUOTE2_DEFINED',
        'TPMSUPPORT',
      ],
      'sources': [
        '<@(tao_sources)',
      ],
	  'include_dirs': [
	    '<(ta)',
	    '<(tp)',
	    '<(tc)',
	  ],
      'dependencies': [
        'jlmsupport',
        'jlmcrypto',
        'jlmbignum',
        'jlmcommon',
      ],
      'direct_dependent_settings': {
    	'include_dirs': [
    	  '<(ta)',
    	  '<(tp)',
    	  '<(tc)',
    	],
      },
      'export_dependent_settings': [
    	'jlmcommon',
    	'jlmbignum',
    	'jlmcrypto',
    	'jlmsupport',
      ],
    },
    {
      'target_name': 'fileServer',
      'type': 'executable',
      'variables': {
        'fs': '<(basesrc)/fileProxy',
      },
      'cflags': [
        '-O3',
      ],
      'sources': [
        '<(fs)/domain.h',
        '<(fs)/fileServer.h',
        '<(fs)/fileServer.cpp',
        '<(fs)/fileServices.h',
        '<(fs)/fileServices.cpp',
        '<(fs)/policyCert.inc',
      ],
      'dependencies': [
        'jlmcommon',
        'jlmbignum',
        'jlmcrypto',
        'jlmsupport',
        'tao',
      ],
    },
    {
      'target_name': 'fileClient',
      'type': 'executable',
      'variables': {
        'fs': '<(basesrc)/fileProxy',
      },
      'cflags': [
        '-O3',
      ],
      'sources': [
        '<(fs)/domain.h',
        '<(fs)/fileClient.h',
        '<(fs)/fileClient.cpp',
        '<(fs)/fileServices.h',
        '<(fs)/fileServices.cpp',
        '<(fs)/policyCert.inc',
        '<(fs)/fileTester.h',
        '<(fs)/fileTester.cpp',
      ],
      'dependencies': [
        'jlmcommon',
        'jlmbignum',
        'jlmcrypto',
        'jlmsupportclient',
        'tao',
      ],
    },
    {
      'target_name': 'cryptUtility',
      'type': 'executable',
      'variables': {
        'cu': '<(basesrc)/cryptUtility',
      },
      'cflags': [
        '-O3',
      ],
      'sources': [
        '<(cu)/cryptUtility.cpp',
        '<(cu)/cryptUtility.h',
      ],
      'dependencies': [
        'jlmcommon',
        'jlmbignum',
        'jlmcrypto',
        'jlmsupport',
        'taoquote',
      ],
    },
    {
      'target_name': 'tcService',
      'type': 'executable',
      'variables': {
        'tc': '<(basesrc)/tcService',
      },
      'cflags': [
        '-O3',
      ],
      'sources': [
        '<(tc)/policyglobals.h',
        '<(tc)/tcService.h',
        '<(tc)/tcService.cpp',
        '<(tc)/tcServiceCodes.h',
        '<(tc)/tciohdr.h',
        '<(tc)/policyCert.inc',
      ],
      'dependencies': [
        'jlmcommon',
        'jlmbignum',
        'jlmcrypto',
        'jlmsupport',
        'taotpmquote',
      ],
    },
    {
      'target_name': 'keyNegoServer',
      'type': 'executable',
      'variables': {
        'tc': '<(basesrc)/tcService',
      },
      'cflags': [
        '-O3',
      ],
      'sources': [
        '<(kn)/keyNegoServer.h',
        '<(kn)/keyNegoServer.cpp',
        '<(kn)/policyglobals.h',
        '<(kn)/validHashes.inc',
      ],
      'dependencies': [
        'jlmcommon',
        'jlmbignum',
        'jlmcrypto',
        'jlmsupportclient',
        'taoquote',
      ],
    },
  ]
}
