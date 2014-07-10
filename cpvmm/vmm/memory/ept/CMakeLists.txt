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

set(MEMORY_EPT_SRCS
    ept.c
    ept_hw_layer.c
    fvs.c
    invept2.c
    ve.c
   )

include_directories(../../guest)
include_directories(../../guest/guest_cpu)
add_library(memory_ept STATIC ${MEMORY_EPT_SRCS})

target_link_libraries(memory_ept guest)
