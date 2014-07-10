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

set(INCLUDE_DIRS
    "../../common/include"
    "../../common/include/arch"
    "../../vmm"
    )

include_directories(${INCLUDE_DIRS})

set(CMAKE_C_FLAGS "-m32 -fno-strict-aliasing -fno-stack-protector ${CMAKE_C_FLAGS}")
set(BOOTSTRAP_SRCS
    bootstrap_ap_procs_init.c
    bootstrap_e820.c
    bootstrap_entry.c
    bootstrap_print.c
    bootstrap_startap.c
    bootstrap_string.c
    bootstrap.x
   )

set(CMAKE_EXE_LINKER_FLAGS "-m32 -static -T ${CMAKE_CURRENT_SOURCE_DIR}/bootstrap.x -e start32_evmm")
add_executable(bootstrap.bin ${BOOTSTRAP_SRCS})
