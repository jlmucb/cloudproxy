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

# compile arch library
#	e820_abstraction.c efer_msr_abstraction.c mtrrs_abstraction.c pat_manager.c
#	output: libarch.a

mainsrc=    $(S)/vmm/arch

B=		$(E)/vmmobjects
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
    -I$(S)/common/include/arch -I$(S)/vmm/include/hw -I$(S)/common/include/platform \
    -I$(mainsrc)/hw -I$(S)/vmm/memory/ept
ASM_SRC = 	
DEBUG_CFLAGS:=  -Wall -Wno-format -fwrapv -Wall -Werror -g -DDEBUG -nostartfiles -nostdlib  -fno-tree-loop-distribute-patterns -nodefaultlibs
RELEASE_CFLAGS:= -Wall -Wno-unknown-pragmas -Wno-format -fwrapv -Wall -Werror -O3  -nostartfiles -nostdlib  -fno-tree-loop-distribute-patterns -nodefaultlibs
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
LINK=       gcc
BINDIR=	        $(B)/arch
#LIBMAKER=   libtool
LIBMAKER=   ar

dobjs=      $(BINDIR)/e820_abstraction.o $(BINDIR)/efer_msr_abstraction.o \
	    $(BINDIR)/mtrrs_abstraction.o $(BINDIR)/pat_manager.o

all: $(E)/libarch.a
 
$(E)/libarch.a: $(dobjs)
	@echo "libarch.a"
	#$(LIBMAKER) -static -o $(E)/libarch.a $(dobjs)
	$(LIBMAKER) -r $(E)/libarch.a $(dobjs)

$(BINDIR)/e820_abstraction.o: $(mainsrc)/e820_abstraction.c
	echo "e820_abstraction.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/e820_abstraction.o $(mainsrc)/e820_abstraction.c

$(BINDIR)/efer_msr_abstraction.o: $(mainsrc)/efer_msr_abstraction.c
	echo "efer_msr_abstraction.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/efer_msr_abstraction.o $(mainsrc)/efer_msr_abstraction.c

$(BINDIR)/mtrrs_abstraction.o: $(mainsrc)/mtrrs_abstraction.c
	echo "mtrrs_abstraction.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/mtrrs_abstraction.o $(mainsrc)/mtrrs_abstraction.c

$(BINDIR)/pat_manager.o: $(mainsrc)/pat_manager.c
	echo "pat_manager.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/pat_manager.o $(mainsrc)/pat_manager.c

clean: 
	rm -f $(E)/libarch.a
