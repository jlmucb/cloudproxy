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

B=		$(E)/vmmobjects
BINDIR=	        $(B)/libutils
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
    -I$(S)/common/include/arch -I$(S)/vmm/include/hw -I$(S)/common/include/platform

DEBUG_CFLAGS:=  -Wall -Wno-format -g -DDEBUG -nostartfiles -nostdlib -nodefaultlibs 
RELEASE_CFLAGS:= -Wall -Wno-unknown-pragmas -Wno-format -O3  -nostartfiles -nostdlib -nodefaultlibs 
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
AS=	    as
LINK=       gcc
#LIBMAKER=   libtool
LIBMAKER=   ar

# compile utils
#       utils_asm.asm
#       heap.c address.c lock.c hash64.c array_list.c event_mgr.c
#       memory_allocator.c math_utils.c cache64.c
# Output: libutils.a

mainsrc=    $(S)/vmm/utils
dobjs=      $(BINDIR)/heap.o $(BINDIR)/address.o $(BINDIR)/lock.o \
	    $(BINDIR)/hash64.o $(BINDIR)/array_list.o \
            $(BINDIR)/cache64.o $(BINDIR)/utils_asm.o \
	    $(BINDIR)/memory_allocator.o $(BINDIR)/math_utils.o \
	    $(BINDIR)/event_mgr.o 

all: $(E)/libutils.a
 
$(E)/libutils.a: $(dobjs)
	@echo "libutils.a"
#	$(LIBMAKER) -static -o $(E)/libutils.a $(dobjs)
	$(LIBMAKER) -r $(E)/libutils.a $(dobjs)

$(BINDIR)/utils_asm.o: $(mainsrc)/utils_asm.s
	echo "utils_asm.o" 
	$(AS) -o $(BINDIR)/utils_asm.o $(mainsrc)/utils_asm.s

$(BINDIR)/heap.o: $(mainsrc)/heap.c
	echo "heap.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/heap.o $(mainsrc)/heap.c

$(BINDIR)/hash64.o: $(mainsrc)/hash64.c
	echo "hash64.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/hash64.o $(mainsrc)/hash64.c

$(BINDIR)/address.o: $(mainsrc)/address.c
	echo "address.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/address.o $(mainsrc)/address.c

$(BINDIR)/lock.o: $(mainsrc)/lock.c
	echo "lock.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/lock.o $(mainsrc)/lock.c

$(BINDIR)/array_list.o: $(mainsrc)/array_list.c
	echo "array_list.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/array_list.o $(mainsrc)/array_list.c

$(BINDIR)/event_mgr.o: $(mainsrc)/event_mgr.c
	echo "event_mgr.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/event_mgr.o $(mainsrc)/event_mgr.c

$(BINDIR)/memory_allocator.o: $(mainsrc)/memory_allocator.c
	echo "memory_allocator.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/memory_allocator.o $(mainsrc)/memory_allocator.c

$(BINDIR)/math_utils.o: $(mainsrc)/math_utils.c
	echo "math_utils.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/math_utils.o $(mainsrc)/math_utils.c

$(BINDIR)/cache64.o: $(mainsrc)/cache64.c
	echo "cache64.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/cache64.o $(mainsrc)/cache64.c

