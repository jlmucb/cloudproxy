# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This file was copied from Chromium's src/build/protoc.gypi, then modified for
# our purposes

# This file is meant to be included into a target to provide a rule
# to invoke protoc in a consistent manner. 
#
# To use this, create a gyp target with the following form:
# {
#   'target_name': 'my_proto_lib',
#   'type': 'static_library',
#   'sources': [
#     'foo.proto',
#     'bar.proto',
#   ],
#   'includes': ['path/to/this/gypi/file'],
# }
# If necessary, you may add normal .cc files to the sources list or other gyp
# dependencies.  The proto headers are guaranteed to be generated before any
# source files, even within this target, are compiled.
#
{
  'variables': {
    'cc_dir': '<(SHARED_INTERMEDIATE_DIR)',
    'protoc': '<!(which protoc)',
  },
  'rules': [
    {
      'rule_name': 'genproto',
      'extension': 'proto',
      'inputs': [
        '<(protoc)',
      ],
      'outputs': [
        '<(cc_dir)/<(RULE_INPUT_ROOT).pb.cc',
        '<(cc_dir)/<(RULE_INPUT_ROOT).pb.h',
      ],
      'action': [
        '<(protoc)',
        #  | sed "s/^\(.*\)\/[^/]*$/\1/g")',
        '-I<(RULE_INPUT_DIRNAME)',
        '--cpp_out=<(cc_dir)',
        '<(RULE_INPUT_PATH)'
      ],
      'message': 'Generating C++ and Python code from <(RULE_INPUT_PATH)',
      'process_outputs_as_sources': 1,
    },
  ],
  # This target exports a hard dependency because it generates header
  # files.
  'hard_dependency': 1,
}
