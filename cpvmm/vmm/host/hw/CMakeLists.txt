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

set(HOST_HW_SRCS
    host_pci_configuration.c
    hw_utils.c
    local_apic.c
    machinesupport.c
    reset.c
    vmcs_init.c
   )

include_directories(../../guest)
include_directories(../../guest/guest_cpu)
add_library(host_hw STATIC ${HOST_HW_SRCS})

add_subdirectory(em64t)
