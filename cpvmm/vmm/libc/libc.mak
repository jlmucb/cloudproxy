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
BINDIR=		$(B)/libc
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
		-I$(S)/vmm/include/hw -I$(S)/common/include/platform
HW_DIR = 	em64t
HW_COMMON_LIBC_DIR = $(S)/common/libc/$(HW_DIR)
ASM_SRC = 	
DEBUG_CFLAGS     := -Wall -Wno-format -g -DDEBUG -nostartfiles -nostdlib -nodefaultlibs 
RELEASE_CFLAGS   := -Wall -Wno-unknown-pragmas -Wno-format -O3  -nostartfiles -nostdlib -nodefaultlibs 
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	
libcsrc=	$(S)/common/libc
mainsrc=	$(S)/vmm/libc

# Compile $(mainsrc)/libc.c $(mainsrc)/vmm_io.c $(mainsrc)/vmm_serial.c 
#    $(libcsrc)/common_libc.c $(libcsrc)/sprintf.c $(libcsrc)/bitarray_utilities.c

CC=         gcc
LINK=       gcc
#LIBMAKER=   libtool
LIBMAKER=   ar

dobjs=      $(BINDIR)/libc.o $(BINDIR)/vmm_io.o $(BINDIR)/vmm_serial.o \
	    $(BINDIR)/common_libc.o $(BINDIR)/sprintf.o $(BINDIR)/bitarray_utilities.o

all: $(E)/libc.a
 
$(E)/libc.a: $(dobjs)
	@echo "libc.a"
	#$(LIBMAKER) -static -o $(E)/libc.a $(dobjs)
	$(LIBMAKER) -r $(E)/libc.a $(dobjs)

$(BINDIR)/libc.o: $(mainsrc)/libc.c
	echo "libc.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/libc.o $(mainsrc)/libc.c

$(BINDIR)/vmm_io.o: $(mainsrc)/vmm_io.c
	echo "vmm_io.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmm_io.o $(mainsrc)/vmm_io.c

$(BINDIR)/vmm_serial.o: $(mainsrc)/vmm_serial.c
	echo "vmm_serial.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmm_serial.o $(mainsrc)/vmm_serial.c

$(BINDIR)/sprintf.o: $(libcsrc)/sprintf.c
	echo "sprintf.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/sprintf.o $(libcsrc)/sprintf.c

$(BINDIR)/common_libc.o: $(libcsrc)/common_libc.c
	echo "common_libc.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/common_libc.o $(libcsrc)/common_libc.c

$(BINDIR)/bitarray_utilities.o: $(libcsrc)/bitarray_utilities.c
	echo "bitarray_utilities.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/bitarray_utilities.o $(libcsrc)/bitarray_utilities.c

