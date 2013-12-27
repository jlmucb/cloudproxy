#############################################################################
# Copyright (c) 2013 Intel Corporation
#
#  Author:    John Manferdelli from a VSS make by Victor Umansky
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
ASM_SRC = 	$(HW_COMMON_LIBC_DIR)/em64t_mem.asm
DEBUG_CFLAGS     := -Wall -Werror -Wno-format -g -DDEBUG
RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3
CFLAGS=     	-D TIXML_USE_STL $(RELEASE_CFLAGS) 
LDFLAGS= 	/ENTRY:startap_main

COMMONSRC=	$(S)/common
STARTAPSRC=	$(S)/startap

IMAGE= 		startap.efi

CC=         gcc
LINK=       gcc

dobjs=      $(BINARYDIR)/x32_init64.o $(BINARYDIR)/ap_procs_init.o \
	    $(BINARYDIR)/ia32_low_level.o $(BINARYDIR)/common_libc.o

all: $(E)/startap.bin
 
$(E)/startap.bin: $(dobjs)
	@echo "startap"
	$(LINK) -o $(E)/startap.exe $(dobjs)

#ap_procs_init.c ia32_low_level.c common_libc.c

$(BINARYDIR)/x32_init64.o: $(STARTAPSRC)/x32_init64.c $(S)/common/include/vmm_defs.h \
		$(S)/common/include/arch/ia32_low_level.h $(S)/startap/x32_init64.h
	echo "x32_init64.c" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINARYDIR)/x32_init64.o $(STARTAPSRC)/x32_init64.c

$(BINARYDIR)/ap_procs_init.o: $(STARTAPSRC)/ap_procs_init.c $(S)/common/include/vmm_defs.h \
		$(S)/common/include/arch/ia32_low_level.h $(S)/startap/ap_procs_init.h
	echo "ap_procs_init.c" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINARYDIR)/ap_procs_init.o $(STARTAPSRC)/ap_procs_init.c

$(BINARYDIR)/ia32_low_level.o: $(STARTAPSRC)/ia32_low_level.c $(S)/common/include/vmm_defs.h \
		$(S)/common/include/arch/ia32_low_level.h $(S)/startap/ia32_low_level.h
	echo "ia32_low_level.c" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINARYDIR)/ia32_low_level.o $(STARTAPSRC)/ia32_low_level.c

$(BINARYDIR)/common_libc.o: $(STARTAPSRC)/common_libc.c $(S)/common/include/vmm_defs.h \
		$(S)/common/include/arch/ia32_low_level.h $(S)/startap/common_libc.h
	echo "common_libc.c" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINARYDIR)/common_libc.o $(STARTAPSRC)/common_libc.c

