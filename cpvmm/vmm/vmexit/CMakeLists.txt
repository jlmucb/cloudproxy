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

set(VMEXIT_SRCS
    vmcall.c
    vmexit.c
    vmexit_analysis.c
    vmexit_cpuid.c
    vmexit_cr_access.c
    vmexit_dbg.c
    vmexit_dtr_tr_access.c
    vmexit_ept.c
    vmexit_init.c
    vmexit_interrupt_exception_nmi.c
    vmexit_io.c
    vmexit_invd.c
    vmexit_invlpg.c
    vmexit_msr.c
    vmexit_sipi.c
    vmexit_task_switch.c
    vmexit_triple_fault.c
    vmexit_ud.c
    vmexit_vmx.c
    vmx_teardown.c
   )

include_directories(../guest/guest_cpu)
add_library(vmexit STATIC ${VMEXIT_SRCS})

target_link_libraries(vmexit host_hw)
