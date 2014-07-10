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

set(HOST_HW_EM64T_SRCS
    em64t_gdt.c
    em64t_idt.c
    fixup.c
   )

set(HOST_HW_EM64T_ASM_SRCS
    em64t_isr.s
    em64t_setjmp.s
    em64t_vmx.s
   )

set_source_files_properties(${HOST_HW_EM64T_ASM_SRCS} PROPERTIES COMPILE_FLAGS "-x assembler-with-cpp")
add_library(host_hw_em64t STATIC ${HOST_HW_EM64T_SRCS} ${HOST_HW_EM64T_ASM_SRCS})
