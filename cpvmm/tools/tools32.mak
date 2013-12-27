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
################################################################################
# file		: tools32.mak
# contains	: describes Microsoft tools for compilation/assembly/link/in 32-bit mode
# purpose	: should be included by makefiles
################################################################################

include $(PROJS)/tools/cygdrive_to_dos_rule.mak

# Tools
AR		= lib
CC     	= cl
LD     	= link
ASM 	= ml

# Standard compilation and linking options

CFLAGS          +=  /nologo /c /W3 /WX /X /GS- /Oi /wd4711 /D ARCH_ADDRESS_WIDTH=4 /MP
CFLAGS_DBG      += $(CFLAGS) /Zi /D DEBUG
CFLAGS_REL      += $(CFLAGS) /O2

LDFLAGS         += /NOLOGO /NODEFAULTLIB /SUBSYSTEM:CONSOLE /DRIVER /FIXED:NO /MACHINE:$(TARGET_MACHINE_TYPE) /INCREMENTAL:NO
LDFLAGS_DBG     += $(LDFLAGS) /DEBUG
LDFLAGS_REL     += $(LDFLAGS)

ASM_FLAGS		+= /nologo /c /coff /W3

MAKEDEPEND 		= cl
MAKEDEPEND_FLAGS	= /nologo /showIncludes /Zs /Zi
MAKEDEPEND_FILTER	= perl -S -x $(call cygdrive_to_dos, $(PROJS)/tools/depend_filter_cl.bat)

INCLUDE_DIR 	+= $(ROOT)/include $(PROJS)/common/include $(ROOT)/include $(PROJS)/common/include/arch $(PROJS)/common/include/platform

