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

# compile memory_manager library
#	host_memory_manager.c vmm_stack.c gpm.c pool.c memory_address_mapper.c 
#	page_walker.c flat_page_tables.c
# output: libmem.a

mainsrc=    	$(S)/vmm/memory/memory_manager

B=		$(E)/vmmobjects/memory/memory_manager
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
    		-I$(S)/common/include/arch -I$(S)/vmm/include/hw \
		-I$(S)/common/include/platform -I$(mainsrc) \
		-I$(S)/vmm -I$(S)/vmm/bootstrap
DEBUG_CFLAGS:=  -Wall -Wno-format -g -DDEBUG -nostartfiles -nostdlib -nodefaultlibs -D INVMM -D JLMDEBUG
RELEASE_CFLAGS:= -Wall -Wno-unknown-pragmas -Wno-format -O3  -nostartfiles -nostdlib -nodefaultlibs -D INVMM -D JLMDEBUG
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
LINK=       gcc
LIBMAKER=   ar

dobjs=      $(B)/host_memory_manager.o $(B)/vmm_stack.o $(B)/gpm.o \
	    $(B)/pool.o $(B)/memory_address_mapper.o \
	    $(B)/page_walker.o $(B)/flat_page_tables.o

all: $(E)/libmem.a
 
$(E)/libmem.a: $(dobjs)
	@echo "libmem.a"
	#$(LIBMAKER) -static -o $(E)/libmem.a $(dobjs)
	$(LIBMAKER) -r $(E)/libmem.a $(dobjs)

$(B)/host_memory_manager.o: $(mainsrc)/host_memory_manager.c
	echo "host_memory_manager.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/host_memory_manager.o $(mainsrc)/host_memory_manager.c

$(B)/vmm_stack.o: $(mainsrc)/vmm_stack.c
	echo "vmm_stack.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/vmm_stack.o $(mainsrc)/vmm_stack.c

$(B)/gpm.o: $(mainsrc)/gpm.c
	echo "gpm.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/gpm.o $(mainsrc)/gpm.c

$(B)/pool.o: $(mainsrc)/pool.c
	echo "pool.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/pool.o $(mainsrc)/pool.c

$(B)/memory_address_mapper.o: $(mainsrc)/memory_address_mapper.c
	echo "memory_address_mapper.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/memory_address_mapper.o $(mainsrc)/memory_address_mapper.c

$(B)/page_walker.o: $(mainsrc)/page_walker.c
	echo "page_walker.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/page_walker.o $(mainsrc)/page_walker.c

$(B)/flat_page_tables.o: $(mainsrc)/flat_page_tables.c
	echo "flat_page_tables.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/flat_page_tables.o $(mainsrc)/flat_page_tables.c

