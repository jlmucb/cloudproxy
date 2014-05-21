#############################################################################
# Copyright (c) 2013 Intel Corporation
#
#  File: bootstrap.mak
#  Author:    John Manferdelli
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

mainsrc=    $(S)/vmm
bootsrc=    $(mainsrc)/bootstrap

B=		$(E)/vmmobjects/bootstrap
INCLUDES=	-I$(bootsrc) -I$(S)/common/include -I$(S)/vmm  \
		-I$(S)/vmm/include -I$(S)/common/hw \
    		-I$(S)/common/include/arch -I$(S)/vmm/include/hw \
		-I$(S)/common/include/platform \
    		-I$(mainsrc)/hw -I$(S)/vmm/memory/ept 
DEBUG_CFLAGS=  -Wall -Wextra -Werror -fwrapv -std=c99 -Wno-format -fno-strict-aliasing -fno-stack-protector -g -nostdlib -fno-tree-loop-distribute-patterns
RELEASE_CFLAGS= -Wall -Wextra -Werror -fwrapv -std=c99 -Wno-unknown-pragmas -Wno-format -fno-strict-aliasing -fno-stack-protector -O3  -Wunused-function -nostdlib -fno-tree-loop-distribute-patterns
CFLAGS= -m32 $(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
LINK=       gcc

all: $(E)/bootstrap.bin

clean:
	rm -f $(E)/bootstrap.bin
	rm -f $(B)/*.o

$(E)/bootstrap.bin: $(B)/bootstrap_entry.o $(B)/bootstrap_e820.o \
	$(B)/bootstrap_print.o $(B)/bootstrap_string.o \
	$(B)/bootstrap_startap.o $(B)/bootstrap_ap_procs_init.o
	$(LINK) -static $(CFLAGS) -e start32_evmm \
		-T bootstrap.script  -o $(E)/bootstrap.bin \
		$(B)/bootstrap_entry.o $(B)/bootstrap_e820.o \
		$(B)/bootstrap_print.o $(B)/bootstrap_string.o \
		$(B)/bootstrap_startap.o $(B)/bootstrap_ap_procs_init.o 

$(B)/bootstrap_entry.o: $(bootsrc)/bootstrap_entry.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/bootstrap_entry.o $(bootsrc)/bootstrap_entry.c 

$(B)/bootstrap_print.o: $(bootsrc)/bootstrap_print.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/bootstrap_print.o $(bootsrc)/bootstrap_print.c 

$(B)/bootstrap_e820.o: $(bootsrc)/bootstrap_e820.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/bootstrap_e820.o $(bootsrc)/bootstrap_e820.c 

$(B)/bootstrap_string.o: $(bootsrc)/bootstrap_string.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/bootstrap_string.o $(bootsrc)/bootstrap_string.c 

$(B)/bootstrap_startap.o: $(bootsrc)/bootstrap_startap.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/bootstrap_startap.o $(bootsrc)/bootstrap_startap.c

$(B)/bootstrap_ap_procs_init.o: $(bootsrc)/bootstrap_ap_procs_init.c
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/bootstrap_ap_procs_init.o $(bootsrc)/bootstrap_ap_procs_init.c


