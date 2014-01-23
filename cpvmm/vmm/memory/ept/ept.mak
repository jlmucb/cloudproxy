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

# compile ept library 
#	invept.asm ept.c ept_hw_layer.c fvs.c ve.c
# output: libept.a

mainsrc=    	$(S)/vmm/memory/ept

B=		$(E)/vmmobjects/memory/ept
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
    		-I$(S)/common/include/arch -I$(S)/vmm/include/hw \
		-I$(S)/vmm/guest -I$(S)/vmm/guest/guest_cpu \
		-I$(S)/common/include/platform -I$(mainsrc)
DEBUG_CFLAGS:=  -Wall -Wno-format -g -DDEBUG -nostartfiles -nostdlib -nodefaultlibs 
RELEASE_CFLAGS:= -Wall -Wno-unknown-pragmas -Wno-format -O3 -nostartfiles -nostdlib -nodefaultlibs 
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
AS=         as
LINK=       gcc
LIBMAKER=   ar

dobjs= 	$(B)/ept.o $(B)/invept2.o \
	$(B)/ept_hw_layer.o $(B)/fvs.o $(B)/ve.o 

all: $(E)/libept.a
 
$(E)/libept.a: $(dobjs)
	@echo "libept.a"
	#$(LIBMAKER) -static -o $(E)/libept.a $(dobjs)
	$(LIBMAKER) -r $(E)/libept.a $(dobjs)

$(B)/invept.o: $(mainsrc)/invept.s
	echo "invept.o"
	$(AS) -o $(B)/invept.o $(mainsrc)/invept.s

$(B)/invept2.o: $(mainsrc)/invept2.c
	echo "invept2.o"
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/invept2.o $(mainsrc)/invept2.c

$(B)/ept.o: $(mainsrc)/ept.c
	echo "ept.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/ept.o $(mainsrc)/ept.c

$(B)/ept_hw_layer.o: $(mainsrc)/ept_hw_layer.c
	echo "ept_hw_layer.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/ept_hw_layer.o $(mainsrc)/ept_hw_layer.c

$(B)/fvs.o: $(mainsrc)/fvs.c
	echo "fvs.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/fvs.o $(mainsrc)/fvs.c

$(B)/ve.o: $(mainsrc)/ve.c
	echo "ve.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/ve.o $(mainsrc)/ve.c

