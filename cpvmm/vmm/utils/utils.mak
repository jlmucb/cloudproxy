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

B=		$(E)/vmmobjects/utils
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
dobjs=      $(B)/heap.o $(B)/address.o $(B)/lock.o \
	    $(B)/hash64.o $(B)/array_list.o \
            $(B)/cache64.o $(B)/utils_asm.o \
	    $(B)/memory_allocator.o $(B)/math_utils.o \
	    $(B)/event_mgr.o 

all: $(E)/libutils.a
 
$(E)/libutils.a: $(dobjs)
	@echo "libutils.a"
#	$(LIBMAKER) -static -o $(E)/libutils.a $(dobjs)
	$(LIBMAKER) -r $(E)/libutils.a $(dobjs)

$(B)/utils_asm.o: $(mainsrc)/utils_asm.s
	echo "utils_asm.o" 
	$(AS) -o $(B)/utils_asm.o $(mainsrc)/utils_asm.s

$(B)/heap.o: $(mainsrc)/heap.c
	echo "heap.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/heap.o $(mainsrc)/heap.c

$(B)/hash64.o: $(mainsrc)/hash64.c
	echo "hash64.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/hash64.o $(mainsrc)/hash64.c

$(B)/address.o: $(mainsrc)/address.c
	echo "address.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/address.o $(mainsrc)/address.c

$(B)/lock.o: $(mainsrc)/lock.c
	echo "lock.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/lock.o $(mainsrc)/lock.c

$(B)/array_list.o: $(mainsrc)/array_list.c
	echo "array_list.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/array_list.o $(mainsrc)/array_list.c

$(B)/event_mgr.o: $(mainsrc)/event_mgr.c
	echo "event_mgr.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/event_mgr.o $(mainsrc)/event_mgr.c

$(B)/memory_allocator.o: $(mainsrc)/memory_allocator.c
	echo "memory_allocator.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/memory_allocator.o $(mainsrc)/memory_allocator.c

$(B)/math_utils.o: $(mainsrc)/math_utils.c
	echo "math_utils.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/math_utils.o $(mainsrc)/math_utils.c

$(B)/cache64.o: $(mainsrc)/cache64.c
	echo "cache64.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/cache64.o $(mainsrc)/cache64.c

