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
    acl_guard.proto
    attestation.proto
    datalog_guard.proto
    keys.proto
    linux_admin_rpc.proto
    linux_host.proto
    log_net.proto
    tao_rpc.proto
   )

PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS ${TAO_PROTO})

set(TAO_SOURCES
    acl_guard.cc
    attestation.cc
    auth.cc
    datalog_guard.cc
    fd_message_channel.cc
    keys.cc
    linux_admin_rpc.cc
    linux_host.cc
    linux_process_factory.cc
    log_net.cc
    message_channel.cc
    pipe_factory.cc
    soft_tao.cc
    tao.cc
    tao_domain.cc
    tao_guard.cc
    tao_root_host.cc
    tao_rpc.cc
    tao_stacked_host.cc
    tpm_tao.cc
    unix_socket_factory.cc
    util.cc
   )

set(TAO_HEADERS
    acl_guard.h
    attestation.h
    auth.h
    datalog_guard.h
    fd_message_channel.h
    keys.h
    linux_admin_rpc.h
    linux_host.h
    linux_process_factory.h
    log_net.h
    message_channel.h
    pipe_factory.h
    soft_tao.h
    tao.h
    tao_domain.h
    tao_guard.h
    tao_host.h
    tao_root_host.h
    tao_rpc.h
    tao_stacked_host.h
    tpm_tao.h
    trivial_guard.h
    unix_socket_factory.h
    util.h
   )

add_lua_header(auth_lua.h auth.lua)

# This is added to get the right path for the protobuf generated header files.
include_directories(${CMAKE_BINARY_DIR})
include_directories(${CMAKE_SOURCE_DIR})
include_directories(${CMAKE_SOURCE_DIR}/third_party/keyczar/cpp/src)
include_directories(${CMAKE_SOURCE_DIR}/third_party/google-glog/src)
include_directories(${CMAKE_SOURCE_DIR}/third_party/gflags/src)
include_directories(${CMAKE_SOURCE_DIR}/third_party/datalog)
include_directories(${CMAKE_SOURCE_DIR}/third_party/datalog/lua)
add_library(tao STATIC
    ${PROTO_SRCS}
    ${PROTO_HDRS}
    ${TAO_SOURCES}
    ${TAO_HEADERS}
    ${CMAKE_CURRENT_BINARY_DIR}/auth_lua.h
   )

# TODO(tmroeder): add checks for OpenSSL, libvirt, and libtspi.
target_link_libraries(tao
    datalog
    gflags
    glog
    keyczar
    protobuf
    crypto
    ssl
    virt
    tspi
   )

# Test code.
set(TEST_SOURCES
    attestation_unittests.cc
    auth_unittests.cc
    datalog_guard_unittests.cc
    keys_unittests.cc
    linux_host_unittests.cc
    linux_process_factory_unittests.cc
    pipe_factory_unittests.cc
    tao_domain_unittests.cc
    tao_test.cc
    tao_unittests.cc
    unix_socket_factory_unittests.cc
    util_unittests.cc
   )

set(TEST_HEADERS
    tao_test.h
   )

include_directories(../third_party/googlemock/gtest/include)
add_executable(tao_test ${TEST_SOURCES} ${TEST_HEADERS})
target_link_libraries(tao_test gtest_main)
target_link_libraries(tao_test tao)
add_test(tao_test tao)
