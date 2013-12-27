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

#
# Template Makefile for builds
#   Targets:
#       debug   - creation of non-optimized executable(s) with debug
#       release - creation of optimized executable w/o debug
#       all     - all of above + deliver
#       clean   - clean all
#

# Logo
nodefault:
	@echo  Build Facility
	@echo "----------------------"
	@echo Please specify target:
	@echo "debug   - creation of non-optimized executable(s) with debug"
	@echo release - creation of optimized executable w/o debug
	@echo all     - all of above + deliver
	@echo clean   - clean all
	@echo
	@echo Optional parameters:
	@echo   DBGCONF=file with macro config for debug mode
	@echo	   "(default is dbgConf.macros)"
	@echo   RELCONF=file with macro config for release mode
	@echo	   "(default is relConf.macros)"

#------------------------------------------------------------
#    MACROS
#------------------------------------------------------------

# Mandatory shell is csh
SHELL = /bin/bash

BIN_DIR    = bin/ms
BUILD_DIR  = build/ms


#-------------------------------------------------------------#
#   User defined functions
#-------------------------------------------------------------#

# converts UNIX slashes to DOS backslahes
dosname = $(subst /,\\,$1)


# $1 - space-separated file list, $2 - output file name
build_filelist=@echo $(foreach item, $1, $(shell echo $(call dosname, $(call cygdrive_to_dos, $(item))) >> $2) ) >> /dev/null

# $1 - file name
remove_file=@$(shell \rm -f $1)


# Object directories

DEBUG_PREFIX   = $(BUILD_DIR)/$(TARGET_MACHINE_TYPE)/debug
RELEASE_PREFIX = $(BUILD_DIR)/$(TARGET_MACHINE_TYPE)/release

DEBUG   = $(ROOT)/$(DEBUG_PREFIX)
RELEASE = $(ROOT)/$(RELEASE_PREFIX)

# Source directories
VPATH = $(SOURCE_DIR)

# Dependencies

# Targetst
.PHONY : nodefault debug release all clean other_debug other_release other_clean install title_debug title_release deliver
all    : install debug release deliver
# sub-level phony targets allow users to define local receipes for top level targets
.PHONY : sub_debug sub_release
# Object files
OBJS_DBG = $(addprefix $(DEBUG)/,$(addsuffix .o,$(basename $(notdir $(SOURCE)))))
OBJS_REL = $(addprefix $(RELEASE)/,$(addsuffix .o,$(basename $(notdir $(SOURCE)))))
MAIN_OBJS_DBG  = $(addprefix $(DEBUG)/,$(addsuffix .o,$(basename $(notdir $(MAIN_SRC)))))
MAIN_OBJS_REL  = $(addprefix $(RELEASE)/,$(addsuffix .o,$(basename $(notdir $(MAIN_SRC)))))
OBJS_ASM_DBG = $(addprefix $(DEBUG)/,$(addsuffix .o,$(basename $(notdir $(ASM_SRC)))))
OBJS_ASM_REL = $(addprefix $(RELEASE)/,$(addsuffix .o,$(basename $(notdir $(ASM_SRC)))))
OBJS_C2ASM_OMF_DBG = $(addprefix $(DEBUG)/,$(addsuffix .oc,$(basename $(notdir $(C2ASM_OMF_SRC)))))
OBJS_C2ASM_OMF_REL = $(addprefix $(RELEASE)/,$(addsuffix .oc,$(basename $(notdir $(C2ASM_OMF_SRC)))))

DEP_FILES_DBG = $(patsubst %.o,%.d, $(OBJS_DBG) $(MAIN_OBJS_DBG))
DEP_FILES_REL = $(patsubst %.o,%.d, $(OBJS_REL) $(MAIN_OBJS_REL))

LD_LIBS_DBG   += $(addprefix $(DEBUG)/, $(LD_LIBS))
LD_LIBS_REL   += $(addprefix $(RELEASE)/, $(LD_LIBS))


IMAGE_DBG = $(addprefix $(DEBUG)/, $(IMAGE))
IMAGE_REL = $(addprefix $(RELEASE)/, $(IMAGE))

LIB_DBG = $(addprefix $(DEBUG)/, $(LIBS))
LIB_REL = $(addprefix $(RELEASE)/, $(LIBS))


ifneq "$(DEP_FILES_DBG)" ""
-include $(DEP_FILES_DBG)
endif

ifneq "$(DEP_FILES_REL)" ""
-include $(DEP_FILES_REL)
endif

# Standard compilation and linking options
INCLUDE = $(addprefix /I , $(call multi_cygdrive_to_dos, $(INCLUDE_DIR)))

COMP_OPTIONS_DBG = $(CFLAGS_DBG) $(INCLUDE)
COMP_OPTIONS_REL = $(CFLAGS_REL) $(INCLUDE)

COMP_C2ASM_OPTIONS_DBG = $(C2ASM_CFLAGS_DBG) $(INCLUDE)
COMP_C2ASM_OPTIONS_REL = $(C2ASM_CFLAGS_REL) $(INCLUDE)


# Intermediate variables
ifdef LD_LIBDIR
ifndef LD_LIBDIR_DBG
LD_LIBDIR_DBG = $(LD_LIBDIR)
endif
ifndef LD_LIBDIR_REL
LD_LIBDIR_REL = $(LD_LIBDIR)
endif
endif
LD_LIBDIR_DBG_LIST = $(addprefix -L ,$(LD_LIBDIR_DBG))
LD_LIBDIR_REL_LIST = $(addprefix -L ,$(LD_LIBDIR_REL))

# Target directories
image_dbg_dir      = $(dir $(IMAGE_DBG))
image_rel_dir      = $(dir $(IMAGE_REL))
lib_dbg_dir        = $(dir $(LIB_DBG))
lib_rel_dir        = $(dir $(LIB_REL))

# Pre-condition check
ifdef PRECOND
PRECOND_RESULT = $(shell $(PRECOND))
ifneq "$(PRECOND_RESULT)" "OK"
$(error Precondition failed: $(PRECOND_RESULT))
endif
endif

# Export of tools and options from top-level Makefile
ifeq "$(MAKELEVEL)" "0"
ifdef ENFORCE_TOOLS
MAKEFLAGS += $(foreach i, $(ENFORCE_TOOLS), $(i)=$($(i)))
endif
export CFLAGS_DBG
export CFLAGS_REL
endif


#-------------------------------------------
#  RULES. User should NOT change them
#-------------------------------------------

# Initial creation of work directories
install : $(DEBUG) $(RELEASE)

# Build of debug executable
debug : sub_debug

sub_debug : title_debug other_debug install 
	$(MAKE) -f $(THIS_MAKEFILE) $(IMAGE_DBG) $(LIB_DBG)

# Build of release executable
release : sub_release

sub_release: title_release other_release install 
	$(MAKE) -f $(THIS_MAKEFILE) $(IMAGE_REL) $(LIB_REL)


#------ Image rules -----------

# Rules for debug executables
$(IMAGE_DBG) : $(MAIN_OBJS_DBG) $(OBJS_DBG) $(LD_EXTERN_LIBS_DBG) $(LD_LIBS_DBG) $(OBJS_ASM_DBG) $(OBJS_C2ASM_OMF_DBG) $(LD_LIBS_EXTRN)
ifdef image_dbg_dir
	@if ! [ -d $(image_dbg_dir) ]; then \mkdir -p $(image_dbg_dir); fi
endif
ifeq ($(LD), link)
	$(call remove_file, $@.link)
	$(call build_filelist, $^, $@.link)
	$(LD) $(LDFLAGS_DBG) /OUT:$(call cygdrive_to_dos, $@) @$(call cygdrive_to_dos, $@).link
else
	@echo $(call dosname,$(MAIN_OBJS_DBG) $(OBJS_DBG) $(OBJS_C2ASM_OMF_DBG)), $(call dosname,$@), $(patsubst %.bin,%.map, $(call dosname,$@)),,, > $(DEBUG)/link.cmd
	$(LD) $(LDFLAGS_DBG) @$(call dosname,$(DEBUG)/link.cmd)
endif
	@echo ===Done $(IMAGE_DBG).

# Rule for release executable
$(IMAGE_REL) : $(MAIN_OBJS_REL) $(OBJS_REL) $(LD_EXTERN_LIBS_REL) $(LD_LIBS_REL) $(OBJS_ASM_REL) $(OBJS_C2ASM_OMF_REL) $(LD_LIBS_EXTRN)
ifdef image_rel_dir
	@if ! [ -d $(image_rel_dir) ]; then \mkdir -p $(image_rel_dir); fi
endif
ifeq ($(LD), link)
	$(call remove_file, $@.link)
	$(call build_filelist, $^, $@.link)
	$(LD) $(LDFLAGS_REL) /OUT:$(call cygdrive_to_dos, $@) @$(call cygdrive_to_dos, $@).link
else
	@echo $(call dosname,$(MAIN_OBJS_REL) $(OBJS_REL) $(OBJS_C2ASM_OMF_REL)), $(call dosname,$@), $(patsubst %.bin,%.map, $(call dosname,$@)),,, > $(RELEASE)/link.cmd
	$(LD) $(LDFLAGS_REL) @$(call dosname,$(RELEASE)/link.cmd)
endif
	@echo ===Done $(IMAGE_REL).

#------ Library rules ---------


# Rule for debug object library build
$(LIB_DBG) : $(OBJS_DBG) $(OBJS_ASM_DBG)
ifdef lib_dbg_dir
	@if ! [ -d $(lib_dbg_dir) ]; then \mkdir -p $(lib_dbg_dir); fi
endif
	$(call remove_file, $*.link)
	$(call build_filelist, $^, $*.link)
	$(AR) /NOLOGO /OUT:$(call cygdrive_to_dos, $@) @$(call cygdrive_to_dos, $*).link
	@echo ===Done $(LIB_DBG).



# Rule for release object library build
$(LIB_REL) : $(OBJS_REL) $(OBJS_ASM_REL)
ifdef lib_rel_dir
	@if ! [ -d $(lib_rel_dir) ]; then \mkdir -p $(lib_rel_dir); fi
endif
	$(call remove_file, $*.link)
	$(call build_filelist, $^, $*.link)
	$(AR) /NOLOGO /OUT:$(call cygdrive_to_dos, $@) @$(call cygdrive_to_dos, $*).link
	@echo ===Done $(LIB_REL).

title_debug:
#	@echo Building debug target...
#	@echo Compile "("$(CC)")" options: $(COMP_OPTIONS_DBG)
#	@echo Link    "("$(LD)")" options: $(LDFLAGS) $(LD_LIBDIR_DBG_LIST) $(LD_LIBS_DBG)

title_release:
#	@echo Building release target...
#	@echo Compile "("$(CC)")" options: $(COMP_OPTIONS_REL)
#	@echo Link    "("$(LD)")" options: $(LDFLAGS) $(LD_LIBDIR_REL_LIST) $(LD_LIBS_REL)

#------ Compilation rules -----

# Rule for compilation w/debug
$(DEBUG)/%.o : %.c $(INCLUDED_MAKEFILES) $(THIS_MAKEFILE)
	@echo "==>" $<
	@echo "$(MAKEDEPEND_FILTER)"
	@if ! [ -d $(@D) ]; then \mkdir -p $(@D); fi
	@-set -e; \
	rm -f $(patsubst %.o,%.d,$@); \
	$(MAKEDEPEND) $(MAKEDEPEND_FLAGS) $(INCLUDE) $(call cygdrive_to_dos, $<) | $(MAKEDEPEND_FILTER) $@ > $(patsubst %.o,%.dtmp,$@);
	mv $(patsubst %.o,%.dtmp,$@) $(patsubst %.o,%.d,$@)
	$(CC) $(COMP_OPTIONS_DBG) $(call cygdrive_to_dos, $<) /Fo$(call cygdrive_to_dos,$@) /Fd$(call cygdrive_to_dos,$(patsubst %.o,%.pdb,$@))

$(DEBUG)/%.o : %.asm $(INC_FILES) $(INCLUDED_MAKEFILES) $(THIS_MAKEFILE)
	@if ! [ -d $(@D) ]; then \mkdir -p $(@D); fi
	@echo "==>" $<
	$(ASM) $(ASM_FLAGS) $(INCLUDE) /Fo$(call cygdrive_to_dos, $@) /DDEBUG /Fl$(call cygdrive_to_dos, $(DEBUG)/$*).lst /Ta$(call cygdrive_to_dos, $<)

$(DEBUG)/%.oc : %.ac $(INCLUDED_MAKEFILES) $(THIS_MAKEFILE)
	@echo "==>" $< $@
	@if ! [ -d $(@D) ]; then \mkdir -p $(@D); fi
	@-set -e; \
	rm -f $(patsubst %.oc,%.d,$@); \
	$(MAKEDEPEND) $(MAKEDEPEND_FLAGS) $(INCLUDE) /Tc$(call cygdrive_to_dos, $<) | $(MAKEDEPEND_FILTER) $@ > $(patsubst %.oc,%.dtmp,$@);\
	mv $(patsubst %.oc,%.dtmp,$@) $(patsubst %.oc,%.d,$@)
	$(CC) $(COMP_C2ASM_OPTIONS_DBG) /Tc$(call cygdrive_to_dos, $<) /Fo$(call cygdrive_to_dos, $(patsubst %.oc,%.otmp,$@)) /Fd$(call cygdrive_to_dos, $(patsubst %.oc,%.pdb,$@)) /Fa$(call cygdrive_to_dos, $(patsubst %.oc,%.asm1,$@))
	$(ASM) $(ASM_FLAGS) $(INCLUDE) /I$(LISTING_INC_DIR) /Fo$(call cygdrive_to_dos, $@) /Fl$(call cygdrive_to_dos, $(DEBUG)/$*).lst  /Ta$(patsubst %.oc,%.asm1,$@)

$(DEBUG)/%.o : %.cpp $(INCLUDED_MAKEFILES) $(THIS_MAKEFILE)
	@echo $<
	$(CC) $(COMP_OPTIONS_DBG) $< /Fo$(call cygdrive_to_dos, $@)
$(DEBUG)/%.o : %.cxx $(INCLUDED_MAKEFILES) $(THIS_MAKEFILE)
	@echo $<
	$(CC) $(COMP_OPTIONS_DBG) $< /Fo$(call cygdrive_to_dos, $@)
$(DEBUG)/%.o : %.C   $(INCLUDED_MAKEFILES) $(THIS_MAKEFILE)
	@echo $<
	$(CC) $(COMP_OPTIONS_DBG) $< /Fo$(call cygdrive_to_dos, $@)
$(DEBUG)/%.o : %.cc  $(INCLUDED_MAKEFILES) $(THIS_MAKEFILE)
	@echo $<
	$(CC) $(COMP_OPTIONS_DBG) $< /Fo$(call cygdrive_to_dos, $@)

# Rule for compilation w/o debug
$(RELEASE)/%.o : %.c $(INCLUDED_MAKEFILES)  $(THIS_MAKEFILE)
	@echo "==>" $<
	@if ! [ -d $(@D) ]; then \mkdir -p $(@D); fi
	@-set -e; \
	rm -f $(patsubst %.o,%.d,$@); \
	$(MAKEDEPEND) $(MAKEDEPEND_FLAGS) $(INCLUDE) $(call cygdrive_to_dos, $<) | $(MAKEDEPEND_FILTER) $@ > $(patsubst %.o,%.dtmp,$@);
	mv $(patsubst %.o,%.dtmp,$@) $(patsubst %.o,%.d,$@)
	$(CC) $(COMP_OPTIONS_REL) $(call cygdrive_to_dos, $<) /Fo$(call cygdrive_to_dos, $@) /Fd$(call cygdrive_to_dos, $(patsubst %.o,%.pdb,$@))

$(RELEASE)/%.o : %.asm $(INC_FILES) $(INCLUDED_MAKEFILES) $(THIS_MAKEFILE)
	@echo "==>" $<
	@if ! [ -d $(@D) ]; then \mkdir -p $(@D); fi
	$(ASM) $(ASM_FLAGS) $(INCLUDE) /Fo$(call cygdrive_to_dos, $@) /Fl$(call cygdrive_to_dos, $(RELEASE)/$*).lst /Ta$<

$(RELEASE)/%.oc : %.ac $(INCLUDED_MAKEFILES) $(THIS_MAKEFILE)
	@echo "==>" $< $@
	@if ! [ -d $(@D) ]; then \mkdir -p $(@D); fi
	@-set -e; \
	rm -f $(patsubst %.oc,%.d,$@); \
	$(MAKEDEPEND) $(MAKEDEPEND_FLAGS) $(INCLUDE) /Tc$(call cygdrive_to_dos, $<) | $(MAKEDEPEND_FILTER) $@ > $(patsubst %.oc,%.dtmp,$@);
	mv $(patsubst %.oc,%.dtmp,$@) $(patsubst %.oc,%.d,$@)
	$(CC) $(COMP_C2ASM_OPTIONS_REL) /Tc$(call cygdrive_to_dos, $<) /Fo$(call cygdrive_to_dos, $(patsubst %.oc,%.otmp,$@)) /Fd$(call cygdrive_to_dos, $(patsubst %.oc,%.pdb,$@)) /Fa$(call cygdrive_to_dos, $(patsubst %.oc,%.asm1,$@))
	$(ASM) $(ASM_FLAGS) $(INCLUDE) /I$(LISTING_INC_DIR) /Fo$(call cygdrive_to_dos, $@) /Fl$(RELEASE)/$*.lst   /Ta$(patsubst %.oc,%.asm1,$@)

$(RELEASE)/%.o : %.cpp $(INCLUDED_MAKEFILES) $(THIS_MAKEFILE)
	@echo $<
	$(CC) $(COMP_OPTIONS_REL) $< /Fo$(call cygdrive_to_dos, $@)
$(RELEASE)/%.o : %.cxx $(INCLUDED_MAKEFILES) $(THIS_MAKEFILE)
	@echo $<
	$(CC) $(COMP_OPTIONS_REL) $< /Fo$(call cygdrive_to_dos, $@)
$(RELEASE)/%.o : %.C   $(INCLUDED_MAKEFILES) $(THIS_MAKEFILE)
	@echo $<
	$(CC) $(COMP_OPTIONS_REL) $< /Fo$(call cygdrive_to_dos, $@)
$(RELEASE)/%.o : %.cc  $(INCLUDED_MAKEFILES) $(THIS_MAKEFILE)
	@echo $<
	$(CC) $(COMP_OPTIONS_REL) $< /Fo$(call cygdrive_to_dos, $@)


# Rules for debug executables


# Rule for compilation w/o debug



#------- On-demand directory creation ----------------

$(DEBUG)   : ; @if ! [ -e $(DEBUG)   ]; then mkdir -p $(DEBUG); fi
$(RELEASE) : ; @if ! [ -e $(RELEASE) ]; then mkdir -p $(RELEASE); fi

#------- Overall clean ---------------

clean : other_clean
ifdef DEBUG
ifneq ($(OBJS_DBG),)
	-\rm -f $(OBJS_DBG)
endif
ifneq ($(OBJS_ASM_DBG),)
	-\rm -f $(OBJS_ASM_DBG)
endif
ifneq ($(MAIN_OBJS_DBG),)
	-\rm -f $(MAIN_OBJS_DBG)
endif
ifneq ($(DEP_FILES_DBG),)
	-\rm -f $(DEP_FILES_DBG)
endif
endif

ifdef RELEASE
ifneq ($(OBJS_REL),)
	-\rm -f $(OBJS_REL)
endif
ifneq ($(OBJS_ASM_REL),)
	-\rm -f $(OBJS_ASM_REL)
endif
ifneq ($(MAIN_OBJS_REL),)
	-\rm -f $(MAIN_OBJS_REL)
endif
ifneq ($(DEP_FILES_REL),)
	-\rm -f $(DEP_FILES_REL)
endif
endif

ifneq ($(IMAGE_DBG),)
	-\rm -f $(IMAGE_DBG)
endif
ifneq ($(IMAGE_REL),)
	-\rm -f $(IMAGE_REL)
endif

ifneq ($(LIB_DBG),)
	-\rm -f $(LIB_DBG)
endif
ifneq ($(LIB_REL),)
	-\rm -f $(LIB_REL)
endif
	@echo ===Done.

#----- Recursive invocation of makefiles in sub-directories ----

ifdef OTHER_MAKEFILES
MAKEFILE_SPEC = $(foreach i, $(OTHER_MAKEFILES), \
                             $(if $(findstring $(i), $(OVERRIDE_OPTIONS)), \
                             $(addsuffix .-e, $(i)), $(addsuffix ., $(i))))

else
MAKEFILE_SPEC =
endif

# Make other folders only when the list is not empty
ifneq "$(MAKEFILE_SPEC)" ""

# Phony targets for each sub dirs named by corresponding makefile w/ suffix
.PHONY: $(MAKEFILE_SPEC) 

$(MAKEFILE_SPEC):
	$(MAKE) -f $(notdir $(basename $@))\
                             -C $(dir $(basename $@)) \
                             --no-print-directory       \
                             $(subst ., ,$(suffix $@)) $(DIR_TARGET)

# Debug build
other_debug:
	$(MAKE) -f $(THIS_MAKEFILE) $(MAKEFILE_SPEC) DIR_TARGET=debug

# Release build
other_release:
	$(MAKE) -f $(THIS_MAKEFILE) $(MAKEFILE_SPEC) DIR_TARGET=release

# Clean
other_clean:
	$(MAKE) -f $(THIS_MAKEFILE) $(MAKEFILE_SPEC) DIR_TARGET=clean
else
other_debug:
other_release:
other_clean:

endif
# Deliver
deliver:
	@$(DELIVER)

# end of stuff
