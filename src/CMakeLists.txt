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

cmake_minimum_required(VERSION 2.8.12)
project(cloudproxy C CXX ASM)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
find_package(Protobuf REQUIRED)
include_directories(${PROTOBUF_INCLUDE_DIRS})

include(cloudproxy.cmake)

# This macro assumes that the header_file will go in CMAKE_CURRENT_BINARY_DIR
# and that the lua_file is located in CMAKE_CURRENT_SOURCE_DIR.
macro(add_lua_header header_file lua_file)
add_custom_command(
    OUTPUT ${header_file}
    COMMAND ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/bin2c -o ${CMAKE_CURRENT_BINARY_DIR}/${header_file} ${lua_file}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS bin2c ${lua_file}
   )
endmacro()


add_subdirectory(apps)
add_subdirectory(cloudproxy)
add_subdirectory(tao)
add_subdirectory(third_party)
