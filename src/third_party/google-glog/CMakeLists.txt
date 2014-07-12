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
set(BSD ${SD}/base)
set(GSD ${SD}/glog)

set(GLOG_SOURCES
    ${SD}/demangle.cc
    ${SD}/logging.cc
    ${SD}/raw_logging.cc
    ${SD}/signalhandler.cc
    ${SD}/stacktrace_unittest.cc
    ${SD}/symbolize.cc
    ${SD}/utilities.cc
    ${SD}/vlog_is_on.cc
   )

set(GLOG_HEADERS
    ${SD}/config_ia32.h
    ${SD}/config_x64.h
    ${SD}/config.h
    ${SD}/demangle.h
    ${SD}/googletest.h
    ${SD}/stacktrace_generic-inl.h
    ${SD}/stacktrace.h
    ${SD}/stacktrace_libunwind-inl.h
    ${SD}/stacktrace_powerpc-inl.h
    ${SD}/stacktrace_x86_64-inl.h
    ${SD}/stacktrace_x86-inl.h
    ${SD}/symbolize.h
    ${SD}/utilities.h
    ${BSD}/commandlineflags.h
    ${BSD}/googleinit.h
    ${BSD}/mutex.h
    ${GSD}/logging.h
    ${GSD}/log_severity.h
    ${GSD}/raw_logging.h
    ${GSD}/stl_logging.h
    ${GSD}/vlog_is_on.h
   )

include_directories(${SD})
include_directories(../gflags/src)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-sign-compare")
add_library(glog STATIC ${GLOG_SOURCES} ${GLOG_HEADERS})
target_link_libraries(glog gflags)
target_link_libraries(glog pthread)
