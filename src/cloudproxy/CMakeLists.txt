# Copyright (c) 2014, Google Inc. All rights reserved.
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

set(CLOUDPROXY_SOURCES
    cloud_channel.cc
    cloud_client.cc
    cloud_server.cc
    tls_message_channel.cc
    util.cc
   )

set(CLOUDPROXY_PROTO
    cloud_channel.proto
   )

set(CLOUDPROXY_HEADERS
    cloud_channel.h
    cloud_client.h
    cloud_server.h
    tls_message_channel.h
    util.h
   )

PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS ${CLOUDPROXY_PROTO})
include_directories(..)
include_directories(${CMAKE_BINARY_DIR})
include_directories(${CMAKE_SOURCE_DIR}/third_party/keyczar/cpp/src)
include_directories(${CMAKE_SOURCE_DIR}/third_party/google-glog/src)
include_directories(${CMAKE_SOURCE_DIR}/third_party/gflags/src)

# for the chromium definitions, we need -DOS_POSIX
add_definitions(-DOS_POSIX)
include_directories(${CMAKE_SOURCE_DIR}/third_party/chromium/include)

add_library(cloudproxy STATIC
    ${PROTO_SRCS}
    ${PROTO_HDRS}
    ${CLOUDPROXY_SOURCES}
    ${CLOUDPROXY_HEADERS}
   )

target_link_libraries(cloudproxy
    tao
    crypto
    ssl
    pthread
   )
