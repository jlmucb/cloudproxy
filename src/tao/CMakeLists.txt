# Copyright 2014 Google Inc. All rights reserved.
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

set(TAO_PROTO
    tao_rpc.proto
   )

PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS ${TAO_PROTO})

set(TAO_SOURCES
    fd_message_channel.cc
    message_channel.cc
    tao_rpc.cc
    util.cc
   )

set(TAO_HEADERS
    fd_message_channel.h
    message_channel.h
    tao.h
    tao_rpc.h
    util.h
   )

# This is added to get the right path for the protobuf generated header files.
include_directories(${CMAKE_BINARY_DIR})
include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/third_party/google-glog/src)
include_directories(${CMAKE_SOURCE_DIR}/third_party/gflags/src)

# for the chromium definitions, we need -DOS_POSIX
add_definitions(-DOS_POSIX)
include_directories(${CMAKE_SOURCE_DIR}/third_party/chromium/include)

include_directories(${CMAKE_SOURCE_DIR}/third_party/modp/include)
add_library(tao STATIC
    ${PROTO_SRCS}
    ${PROTO_HDRS}
    ${TAO_SOURCES}
    ${TAO_HEADERS}
   )

# TODO(tmroeder): add checks for OpenSSL, libvirt, and libtspi.
target_link_libraries(tao
    chromium
    gflags
    glog
    modp
    protobuf
    crypto
    ssl
    virt
    tspi
   )
