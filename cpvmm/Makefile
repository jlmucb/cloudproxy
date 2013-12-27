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
# Copyright 2001-2013 Intel Corporation All Rights Reserved.
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

export PROJS = $(CURDIR)


#############################################################################
# Find tool chain location
#############################################################################

VCDIRS := \
    "/Program Files (x86)/Microsoft Visual Studio 10.0" \
    "/Program Files/Microsoft Visual Studio 10.0" \
    "/Program Files (x86)/Microsoft Visual Studio 8" \
    "/Program Files/Microsoft Visual Studio 8"

ifeq ($@,vmm)
	$@ = vmm
endif

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

$(info ======================== Build configuration ========================)
$(info Tools: $(VC))
$(info =====================================================================)


config_path = \
    echo "set vc=$(subst /cygdrive/c,c:,$(VC))/VC/" > tmp.$@.bat; \
    sed '/^call/a path' "$(VC)/VC/vcvarsall.bat" >> tmp.$@.bat; \
    sed -i 's/~dp0/vc%/g' tmp.$@.bat; \
    chmod +x ./tmp.$@.bat; \
    ./tmp.$@.bat $(1) | sed -ne 's/PATH=/PATH="/p' > $(2); \
    rm -f ./tmp.$@.bat; \
    sed -i 's/\(.\):/\/cygdrive\/\1/g' $(2); \
    sed -i 's/\\/\//g' $(2); \
    sed -i 's/;/:/g' $(2); \
    sed -i 's/$$/:"/' $(2)

#############################################################################
# Find build type: release or debug
#############################################################################

CONFIG_BUILD_TYPE := \
    $(shell \
        if [ -e config_build_type ]; then \
            cat config_build_type; \
        else \
            echo "release"; \
        fi \
    )


#############################################################################
# Target rules
#############################################################################

.PHONY: vmm startap clean

# variables pass-down to sublevel make
make_vars= \
    MAKE_TOOLS_FILE=tools$(1).mak \
    TARGET_MACHINE_TYPE=x$(1:32=86) \
    $(shell cat config_path_$(1))


$(VMM): config_path_64
$(VMM): vmm

vmm: config_path_64
	$(MAKE) -C $@ -f Makefile $(CONFIG_BUILD_TYPE) $(call make_vars,64)
	if ! [ -e $(PROJS)/bin/ms/$(CONFIG_BUILD_TYPE) ]; then \
		mkdir -p $(PROJS)/bin/ms/$(CONFIG_BUILD_TYPE); \
	fi
	cp $(PROJS)/vmm/build/ms/x64/$(CONFIG_BUILD_TYPE)/evmm.bin $(PROJS)/bin/ms/$(CONFIG_BUILD_TYPE)/

startap: config_path_32
	$(MAKE) -C $@ -f Makefile $(CONFIG_BUILD_TYPE) $(call make_vars,32)

.PHONY: clean_vmm clean_startap
clean: clean_vmm clean_startap

clean_startap:
	$(MAKE) -C $(patsubst clean_%, %, $@) -f Makefile clean $(call make_vars,32)
	
clean_vmm:
	$(MAKE) -C $(patsubst clean_%, %, $@) -f Makefile clean $(call make_vars,64)

config_release::
	@echo "release" > config_build_type

config_debug::
	@echo "debug" > config_build_type

config_path_32::
	@$(call config_path,x86,config_path_32)

config_path_64::
	@$(call config_path,x86_amd64,config_path_64)

all: startap vmm

# End of file
