#############################################################################
# Copyright (c) 2013 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#############################################################################

#############################################################################
# INTEL CONFIDENTIAL
# Copyright 2013 Intel Corporation All Rights Reserved.
#
# The source code contained or described herein and all documents related to
# the source code ("Material") are owned by Intel Corporation or its
# suppliers or licensors.  Title to the Material remains with Intel
# Corporation or its suppliers and licensors.  The Material contains trade
# secrets and proprietary and confidential information of Intel or its
# suppliers and licensors.  The Material is protected by worldwide copyright
# and trade secret laws and treaty provisions.  No part of the Material may
# be used, copied, reproduced, modified, published, uploaded, posted,
# transmitted, distributed, or disclosed in any way without Intel's prior
# express written permission.
#
# No license under any patent, copyright, trade secret or other intellectual
# property right is granted to or conferred upon you by disclosure or
# delivery of the Materials, either expressly, by implication, inducement,
# estoppel or otherwise.  Any license under such intellectual property rights
# must be express and approved by Intel in writing.
#############################################################################

-include config_path

VCDIRS := \
    "/Program Files (x86)/Microsoft Visual Studio 10.0" \
    "/Program Files/Microsoft Visual Studio 10.0"

VC := \
    $(shell \
        for x in $(VCDIRS); do \
            y="/cygdrive/c$$x"; \
            if [ -d "$$y" ]; then \
                echo $$y; \
                break; \
            fi \
        done \
    )

#############################################################################

PRJ = ../../..

SRC = \
    evmmh.c \
    e820.c \
    idt.c \
    ./utils/compression/decompress.c \
    ./utils/memory/memory.c \
    ./utils/x64/x32_gdt64.c \
    ./utils/x64/x32_pt64.c \
    $(PRJ)/common/libc/common_libc.c \
    $(PRJ)/common/libc/ia32/ia32_low_level.c \
    $(PRJ)/common/libc/ia32/ia32_mem.asm \
    $(PRJ)/common/ld/pe_ld/pe_ld.c \
    $(PRJ)/common/ld/image_accessors/image_access_mem.c

VPATH = \
    ./utils/compression \
    ./utils/memory \
    ./utils/x64 \
    $(PRJ)/common/libc \
    $(PRJ)/common/libc/ia32 \
    $(PRJ)/common/ld/pe_ld \
    $(PRJ)/common/ld/image_accessors

INC = \
    ./ \
    ../starter \
    ./utils/compression \
    ./utils/memory \
    ./utils/x64 \
    $(PRJ)/common/include \
    $(PRJ)/common/include/arch \
    $(PRJ)/common/libc \
    $(PRJ)/common/libc/ia32 \
    $(PRJ)/startap

OBJ = $(addsuffix .obj,$(basename $(notdir $(SRC))))

%.obj: %.asm
	ml /c $(addprefix /I ,$(INC)) $<

%.obj: %.c
	cl \
    /c \
    /X \
    /GS- \
    /Oi \
    /O2 \
    /WX \
    /DARCH_ADDRESS_WIDTH=4 \
    /DUVMM_MBR_LOADER \
    /DCIRT_DEBUG_DISABLED \
    $(addprefix /I ,$(INC)) \
    $<

evmmh.exe: config_path $(OBJ)
	link \
    /ENTRY:evmmh \
    /BASE:0x10000 \
    /ALIGN:32 \
    /FIXED:NO \
    /SUBSYSTEM:CONSOLE \
    /DRIVER \
    /MACHINE:X86 \
    /INCREMENTAL:NO \
    /OPT:REF \
    /NODEFAULTLIB \
    $(subst config_path,,$^) \
    /out:$@

clean:
	rm -f *.obj *.exe config_path

config_path:
	@echo "set vc=$(subst /cygdrive/c,c:,$(VC))/VC/" > tmp.$@.bat; \
    sed '/^call/a path' "$(VC)/VC/vcvarsall.bat" >> tmp.$@.bat; \
    sed -i 's/~dp0/vc%/g' tmp.$@.bat; \
    chmod +x ./tmp.$@.bat; \
    ./tmp.$@.bat x86 | sed -ne 's/PATH=/PATH="/p' > $@; \
    rm -f ./tmp.$@.bat; \
    sed -i 's/\(.\):/\/cygdrive\/\1/g' $@; \
    sed -i 's/\\/\//g' $@; \
    sed -i 's/;/:/g' $@; \
    sed -i 's/$$/:"/' $@

# End of file
