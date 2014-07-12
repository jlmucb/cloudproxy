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

include_directories(..)
include_directories(${CMAKE_BINARY_DIR})
include_directories(../third_party/keyczar/cpp/src)
include_directories(../third_party/google-glog/src)
include_directories(../third_party/gflags/src)

add_executable(tpm_tao tpm_tao.cc)
target_link_libraries(tpm_tao tao)

add_executable(soft_tao soft_tao.cc)
target_link_libraries(soft_tao tao)

add_executable(get_pcrs get_pcrs.cc)
target_link_libraries(get_pcrs tao)

add_executable(linux_host linux_host.cc)
target_link_libraries(linux_host tao)

add_executable(demo demo.cc)
target_link_libraries(demo tao)

PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS demo_server.proto)
add_executable(demo_server demo_server.cc ${PROTO_SRCS} ${PROTO_HDRS})
target_link_libraries(demo_server cloudproxy)

add_executable(log_net_server log_net_server.cc)
target_link_libraries(log_net_server tao)

add_executable(tao_admin tao_admin.cc)
target_link_libraries(tao_admin tao)
