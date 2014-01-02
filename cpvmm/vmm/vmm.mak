#############################################################################
# Copyright (c) 2013 Intel Corporation
#
#  Author:    John Manferdelli from previous eVMM makefiles
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


ifndef CPProgramDirectory
E=		/home/jlm/jlmcrypt
else
E=      	$(CPProgramDirectory)
endif
ifndef VMSourceDirectory
S=		/home/jlm/fpDev/fileProxy/cpvmm
else
S=      	$(VMSourceDirectory)
endif
ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

B=		$(E)/vmmobjects
BINARYDIR=	$(B)/startap
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/include/arch
HW_DIR = 	em64t
HW_COMMON_LIBC_DIR = $(S)/common/libc/$(HW_DIR)
ASM_SRC = 	
DEBUG_CFLAGS     := -Wall -Werror -Wno-format -g -DDEBUG
RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

#----------------------------------------------------------------------------
SOURCE     =
ASM_SRC    =

# ENABLE_VTLB empty for disable; not empty for enable vtlb
export ENABLE_VTLB = 

MAIN_SRC   = vmm.c
ROOT       = $(PROJS)/vmm
EXTERN_DIR = 
SOURCE_DIR = .

IMAGE         = evmm.bin
LIBS          =

INCLUDE_DIR   = ./acpi ./include ./include/hw ./dbg ./memory/ept
CFLAGS_DBG    =
CFLAGS_REL    =

ifdef ENABLE_VTLB
    CFLAGS_DBG += /DVTLB_IS_SUPPORTED
    CFLAGS_REL += /DVTLB_IS_SUPPORTED
endif

LDFLAGS       = /ENTRY:vmm_main
LD_LIBDIR     =
LD_LIBDIR_DBG =
LD_LIBDIR_REL =
LD_LIBS       = libacpi.a                                                      \
                libvmx.a                                                       \
                libc.a                                                         \
                libhw.a                                                        \
                libhwcommon.a                                                  \
                libutils.a                                                     \
                libhost.a                                                      \
                libdbg.a                                                       \
                libmem.a                                                       \
                libarch.a                                                      \
                libguest.a                                                     \
                libguest_cpu.a                                                 \
                libscheduler.a                                                 \
                libstartup.a                                                   \
                libvmexit.a                                                    \
                libipc.a                                                       \
                libept.a                                                       

ifdef ENABLE_VTLB
        LD_LIBS += libvtlb.a                                                   	
endif

ifdef ENABLE_MULTI_GUEST_SUPPORT
        LD_LIBS += libguest_create_addon.a
endif


#--------------------------------------------------------------
#   C O N F I G U R A T I O N   M A N A G E M E N T
#--------------------------------------------------------------

HW_MAK = $(HW_DIR).mak

# Other makefiles to be processed before this one
OTHER_MAKEFILES  = ./host/host.mak                                             \
                   ./vmx/vmx.mak                                               \
                   ./acpi/acpi.mak                                             \
                   ./libc/libc.mak                                             \
                   ./utils/utils.mak                                           \
                   ./dbg/dbg.mak                                               \
                   ./memory/memory_manager/memory_manager.mak                  \
                   ./arch/arch.mak                                             \
                   ./guest/guest.mak                                           \
                   ./startup/startup.mak                                       \
                   ./vmexit/vmexit.mak                                         \
                   ./ipc/ipc.mak                                               \
                   ./memory/ept/ept.mak                                        

ifdef ENABLE_VTLB	
        OTHER_MAKEFILE += ./memory/vtlb/vtlb.mak                               
endif

ifdef ENABLE_MULTI_GUEST_SUPPORT
        OTHER_MAKEFILE += ./samples/guest_create_addon/guest_create_addon.mak
endif

# Force the same tools and options on following sub-makes
OVERRIDE_OPTIONS =
# Tools to be enforced on these sub-makes
ENFORCE_TOOLS    = AR CC LD

# Project-wide configuration macros

# Pre-condition csh script name
# Spec for pre-condition csh script:
#  - if error it should print error message to stdout,
#  - if pre-conditions are met, it should print OK.
PRECOND =

# Delivery csh script name
DELIVER =

# This makefile name (must be set to actual name if it is not "Makefile")
THIS_MAKEFILE = vmm.mak

#-------------------------------------------------------------------
# include makefile template (PROJS variable should be set correctly)
#
#--------------------------------------------------------------------
ifdef PROJS
INCLUDED_MAKEFILES=$(PROJS)/tools/$(MAKE_TOOLS_FILE) $(PROJS)/tools/rules.mak
INCLUDED_MAKEFILES+=$(PROJS)/common/evmm_cmpl_flag_option.mak
include $(INCLUDED_MAKEFILES)
else
$(warning Please define the PROJS environment variable)
$(warning e.g., set PROJS=c:/work)
$(error The PROJS enivornment variable is undefined)
endif
