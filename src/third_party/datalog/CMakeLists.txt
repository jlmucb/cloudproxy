# Copyright (c) 2014 Google Inc. All rights reserved.
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

add_executable(bin2c bin2c.c)

add_lua_header(dl_lua.h datalog.lua)

set(LSD lua)

set(LUA_SOURCES
    ${LSD}/lapi.c
    ${LSD}/lauxlib.c
    ${LSD}/lbaselib.c
    ${LSD}/lcode.c
    ${LSD}/ldblib.c
    ${LSD}/ldebug.c
    ${LSD}/ldo.c
    ${LSD}/ldump.c
    ${LSD}/lfunc.c
    ${LSD}/lgc.c
    ${LSD}/linit.c
    ${LSD}/liolib.c
    ${LSD}/llex.c
    ${LSD}/lmathlib.c
    ${LSD}/lmem.c
    ${LSD}/loadlib.c
    ${LSD}/lobject.c
    ${LSD}/lopcodes.c
    ${LSD}/loslib.c
    ${LSD}/lparser.c
    ${LSD}/lstate.c
    ${LSD}/lstring.c
    ${LSD}/lstrlib.c
    ${LSD}/ltable.c
    ${LSD}/ltablib.c
    ${LSD}/ltm.c
    ${LSD}/lua.c
    ${LSD}/luac.c
    ${LSD}/lundump.c
    ${LSD}/lvm.c
    ${LSD}/lzio.c
    ${LSD}/print.c
   )

set(LUA_HEADERS
    ${LSD}/lapi.h
    ${LSD}/lauxlib.h
    ${LSD}/lcode.h
    ${LSD}/ldebug.h
    ${LSD}/ldo.h
    ${LSD}/lfunc.h
    ${LSD}/lgc.h
    ${LSD}/llex.h
    ${LSD}/llimits.h
    ${LSD}/lmem.h
    ${LSD}/lobject.h
    ${LSD}/lopcodes.h
    ${LSD}/lparser.h
    ${LSD}/lstate.h
    ${LSD}/lstring.h
    ${LSD}/ltable.h
    ${LSD}/ltm.h
    ${LSD}/lua.h
    ${LSD}/luaconf.h
    ${LSD}/lualib.h
    ${LSD}/lundump.h
    ${LSD}/lvm.h
    ${LSD}/lzio.h
   )

add_library(lua STATIC ${LUA_SOURCES} ${LUA_HEADERS})

set(SD .)

set(DATALOG_SOURCES
    ${SD}/datalog.c
    ${SD}/loader.c
   )

set(DATALOG_HEADERS
    ${SD}/datalog.h
    ${CMAKE_CURRENT_BINARY_DIR}/dl_lua.h
   )

include_directories(lua)
include_directories(${CMAKE_CURRENT_BINARY_DIR})
add_library(datalog STATIC ${DATALOG_SOURCES} ${DATALOG_HEADERS})
target_link_libraries(datalog lua)
