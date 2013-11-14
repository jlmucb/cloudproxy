# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Modified by Tom Roeder <tmroeder@google.com> to remove parts that
# are unnecessary for CloudProxy.

{
  'targets': [
    {
      'target_name': 'gtest',
      'type': 'static_library',
      'sources': [
        'include/gtest/gtest-death-test.h',
        'include/gtest/gtest-message.h',
        'include/gtest/gtest-param-test.h',
        'include/gtest/gtest-printers.h',
        'include/gtest/gtest-spi.h',
        'include/gtest/gtest-test-part.h',
        'include/gtest/gtest-typed-test.h',
        'include/gtest/gtest.h',
        'include/gtest/gtest_pred_impl.h',
        'include/gtest/internal/gtest-death-test-internal.h',
        'include/gtest/internal/gtest-filepath.h',
        'include/gtest/internal/gtest-internal.h',
        'include/gtest/internal/gtest-linked_ptr.h',
        'include/gtest/internal/gtest-param-util-generated.h',
        'include/gtest/internal/gtest-param-util.h',
        'include/gtest/internal/gtest-port.h',
        'include/gtest/internal/gtest-string.h',
        'include/gtest/internal/gtest-tuple.h',
        'include/gtest/internal/gtest-type-util.h',
        'src/gtest-death-test.cc',
        'src/gtest-filepath.cc',
        'src/gtest-internal-inl.h',
        'src/gtest-port.cc',
        'src/gtest-printers.cc',
        'src/gtest-test-part.cc',
        'src/gtest-typed-test.cc',
        'src/gtest.cc',
      ],
      'include_dirs': [
        '.',
        'include',
      ],
      'direct_dependent_settings': {
        'defines': [
          'UNIT_TEST',
        ],
        'include_dirs': [
          'include',  # So that gtest headers can find themselves.
        ],
	'libraries': [
	  '-lpthread',
	],
        'target_conditions': [
          ['_type=="executable"', {
            'test': 1,
          }],
        ],
      },
    },
    {
      'target_name': 'gtest_main',
      'type': 'static_library',
      'sources': [
	'src/gtest_main.cc',
      ],
      'dependencies': [
	'gtest',
      ],
    },
  ],
}
