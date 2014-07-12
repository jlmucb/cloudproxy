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

set(SD src)
set(ISD include/chromium)

set(CHROMIUM_SOURCES
    ${SD}/base/file_path.cc
    ${SD}/base/file_path_constants.cc
    ${SD}/base/file_util.cc
    ${SD}/base/file_util_posix.cc
   )

set(CHROMIUM_HEADERS
    ${ISD}/base/file_path.h
    ${ISD}/base/file_util.h
   )

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-variable")
add_definitions(
    -DOS_POSIX
    -DOS_LINUX
    -DCOMPILER_GCC
   )
include_directories(../google-glog/src)
include_directories(${ISD})
include_directories(include)
add_library(chromium STATIC ${CHROMIUM_SOURCES} ${CHROMIUM_HEADERS})
target_link_libraries(chromium glog)
