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
#
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

# compile vmm library

mainsrc=    $(S)/vmm

B=		$(E)/vmmobjects
BINDIR=	        $(B)/host
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
    -I$(S)/common/include/arch -I$(S)/vmm/include/hw -I$(S)/common/include/platform \
    -I$(mainsrc)/hw -I$(S)/vmm/memory/ept
ASM_SRC = 	
DEBUG_CFLAGS:=  -Wall -Werror -Wno-format -g -DDEBUG -nostartfiles -nostdlib -nodefaultlibs
RELEASE_CFLAGS:= -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3  -nostartfiles -nostdlib -nodefaultlibs
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
LINK=       gcc
LIBMAKER=   libtool

dobjs=      $(BINDIR)/.o $(BINDIR)/.o $(BINDIR)/.o \
	    $(BINDIR)/.o $(BINDIR)/.o

all: $(E)/.a
 
$(E)/.a: $(dobjs)
	@echo ".a"
	$(LIBMAKER) -static -o $(E)/.a $(dobjs)

$(BINDIR)/.o: $(mainsrc)/vmm.c
	echo ".o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/.o $(mainsrc)/vmm.c

#  vmm.c
#  output: evmm.bin,  ENTRY:vmm_main

# ifdef ENABLE_MULTI_GUEST_SUPPORT
#         OTHER_MAKEFILE += ./samples/guest_create_addon/guest_create_addon.mak
# endif

