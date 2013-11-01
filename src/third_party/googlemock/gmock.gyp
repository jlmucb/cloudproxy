# Copyright (c) 2009 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# Modified by Tom Roeder <tmroeder@google.com> to add files for the
# version of gmock that's used in CloudProxy and to remove the
# conditions that CloudProxy doesn't need

{
  'targets': [
    {
      'target_name': 'gmock',
      'type': 'static_library',
      'dependencies': [
        'gtest/gtest.gyp:gtest',
      ],
      'sources': [
        'include/gmock/gmock-actions.h',
        'include/gmock/gmock-cardinalities.h',
        'include/gmock/gmock-generated-actions.h',
        'include/gmock/gmock-generated-function-mockers.h',
        'include/gmock/gmock-generated-matchers.h',
        'include/gmock/gmock-generated-nice-strict.h',
        'include/gmock/gmock-spec-builders.h',
        'include/gmock/gmock.h',
        'include/gmock/gmock-matchers.h',
	'include/gmock/gmock-more-actions.h',
	'include/gmock/gmock-more-matchers.h',
        'include/gmock/internal/gmock-generated-internal-utils.h',
        'include/gmock/internal/gmock-internal-utils.h',
        'include/gmock/internal/gmock-port.h',
        'src/gmock-cardinalities.cc',
        'src/gmock-internal-utils.cc',
        'src/gmock-matchers.cc',
        'src/gmock-spec-builders.cc',
        'src/gmock.cc',
      ],
      'include_dirs': [
        '.',
        'include',
      ],
      'direct_dependent_settings': {
        'include_dirs': [
          'include',  # So that gmock headers can find themselves.
        ],
      },
      'export_dependent_settings': [
        'gtest/gtest.gyp:gtest',
      ],
    },
  ],
}
