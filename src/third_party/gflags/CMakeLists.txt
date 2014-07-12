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
set(GSD ${SD}/gflags)

set(GFLAGS_SOURCES
	${SD}/gflags.cc
	${SD}/gflags_completions.cc
	${SD}/gflags_nc.cc
	${SD}/gflags_reporting.cc
	${SD}/gflags_strip_flags_test.cc
   )

set(GFLAGS_HEADERS
    ${SD}/config.h
	${SD}/mutex.h
	${SD}/util.h
	${GSD}/gflags_completions.h
	${GSD}/gflags_declare.h
	${GSD}/gflags.h
   )

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-unused-local-typedefs -Wno-sign-compare")
include_directories(${SD})
add_library(gflags STATIC ${GFLAGS_SOURCES} ${GFLAGS_HEADERS})
