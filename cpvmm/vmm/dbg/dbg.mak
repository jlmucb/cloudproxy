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
#  Author:    Victor Umansky
#
#  User-specific makefile:
#
#  Notes:
#
#  1. This makefile automatically builds executable targets upon
#     C/C++ files declared in $SOURCE variable. Source files reside
#     in directories declared in $SOURCE_DIR variable.
#
#  2. This makefile should be customized for specific component or
#     subsystem (or entire system) by means of the following
#     variables: IMAGE_DBG, IMAGE_REL, LIB_DBG, LIB_REL, INCLUDE_DIR,
#     CFLAGS_DBG, CFLAGS_REL, LDFLAGS, LD_LIBDIR, LD_LIBS, MAIN_SRC.
#     Detailed description - see below in the code.
#
#  3. In addition, it is possible to build temporary targets for testing
#     in debug mode. Up to 5 alternative configurations are available.
#     In order to define a configuration, define IMAGE_DBG<num>
#     and list of configuration-specific source files (including
#     that with "main" function) in TEST_SRC<num>.
#
#  4. Every instance of this makefile may also invoke other makefiles
#     as a prerequisite. The list and order of these files may be specified
#     in OTHER_MAKEFILES variable, those of them which tools and options
#     must be overriden, should appear also in OVERRIDE_OPTIONS list. In
#     addition, a user may specify list of tools which must be enforced
#     in these files.
#
#  5. Optional customization:
#
#     DBGCONF=file with macro config for debug mode (default dbgConf.macros)
#     RELCONF=file with macro config for release mode (default relConf.macros)
#
#     PRECOND=csh script which checks pre-condition for Makefile invocation.
#     By default, no precondition check at all.
#
#  6. IMPORTANT: There are assumptions that makefile's name is "Makefile"
#                and template makefile resides in the same directory.
#                Otherwise set THIS_MAKEFILE and PROJS variables to proper
#                values.
#
#

#----------------------------------------------------------------------------
#          P R O J E C T   S O U R C E   B A S E
#----------------------------------------------------------------------------
# SOURCE      = Put here list of all project source files less MAIN_SRC
#               (file names only)
#
# MAIN_SRC    = name of source file(s) with main function and accompanying
#               stuff
#
# SOURCE_DIR  = Put here list of all directories where reside files
#               .c, .cpp, and .cxx. Use $(ROOT) variable as a root
#               of a directory path.
#----------------------------------------------------------------------------
SOURCE     = trace.c                                                           \
			vmx_trace.c                                                        \
			cli_libc.c                                                         \
			vmdb.c                                                             \
			vt100.c                                                            \
			vmm_dbg.c														   

MAIN_SRC   =
ROOT       = $(PROJS)/vmm
SOURCE_DIR = .

#-----------------------------------------------------------------
#   MACROS    User MUST define these definitions
#             (or intentionally leave some of them undefined)
#-----------------------------------------------------------------
# Destinations: images
# IMAGE_DBG = full path name of executable with debug information
# IMAGE_REL = full path name of executable w/o debug information
#
# Destinations: object libraries
# LIB_DBG = full path name of object library with debug information
# LIB_REL = full path name of object library w/o debug information
#
# Vars
# INCLUDE_DIR   = list of include directories
# CFLAGS_DBG    = component-specific compilation flags for debug mode
# CFLAGS_REL    = component-specific compilation flags for release mode
# LDFLAGS       = component-specific linker flags
# LD_LIBDIR     = list of library dirs for linker (if the SAME for debug and release)
# LD_LIBDIR_DBG = list of DEBUG library dirs for linker
# LD_LIBDIR_REL = list of RELEASE library dirs for linker
# LD_LIBS       = libraries for linker in format [-l]<lib>... (if the SAME for debug and release)
# LD_LIBS_DBG   = DEBUG libraries for linker in format [-l]<lib>...
# LD_LIBS_REL   = RELEASE libraries for linker in format [-l]<lib>...
#
# Object directories
# DEBUG   = intermediate directory for object and dependency files (debug mode)
# RELEASE = intermediate directory for object and dependency files (release mode)
#-----------------------------------------------------------------
IMAGE	      =
LIBS		  = libdbg.a

INCLUDE_DIR   = . $(ROOT)/include $(ROOT)/include/hw $(ROOT)/ipc $(PROJS)/common/include
CFLAGS_DBG    =
CFLAGS_REL    =
LDFLAGS       =
LD_LIBDIR     =
LD_LIBDIR_DBG =
LD_LIBDIR_REL =
LD_LIBS       = libguest.a
LD_LIBS_DBG   =
LD_LIBS_REL   =

#--------------------------------------------------------------
#   C O N F I G U R A T I O N   M A N A G E M E N T
#--------------------------------------------------------------

# Other makefiles to be processed before this one
OTHER_MAKEFILES  =

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
THIS_MAKEFILE = dbg.mak

#-------------------------------------------------------------------
# include makefile template (PROJS variable should be set correctly)
#
ifdef PROJS
INCLUDED_MAKEFILES=$(PROJS)/tools/$(MAKE_TOOLS_FILE) $(PROJS)/tools/rules.mak
INCLUDED_MAKEFILES+=$(PROJS)/common/evmm_cmpl_flag_option.mak
include $(INCLUDED_MAKEFILES)
else
$(warning Please define the PROJS environment variable)
$(warning e.g., set PROJS=c:/work)
$(error The PROJS enivornment variable is undefined)
endif
#--------------------------------------------------------------------
