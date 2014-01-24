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

# compile ipc library
#	ipc.c ipc_api.c
#	output: libipc.a

mainsrc=    $(S)/vmm/ipc

B=		$(E)/vmmobjects
BINDIR=	        $(B)/ipc
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
    -I$(S)/common/include/arch -I$(S)/vmm/include/hw -I$(S)/common/include/platform \
    -I$(S)/vmm/guest/guest_cpu -I$(S)/vmm/guest -I$(mainsrc)/hw -I$(S)/vmm/memory/ept
ASM_SRC = 	
DEBUG_CFLAGS:=  -Wall -Wno-format -g -DDEBUG -nostartfiles -nostdlib -nodefaultlibs 
RELEASE_CFLAGS:= -Wall -Wno-unknown-pragmas -Wno-format -O3  -nostartfiles -nostdlib -nodefaultlibs 
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
LINK=       gcc
LIBMAKER=   ar
#LIBMAKER=   libtool

dobjs=      $(BINDIR)/ipc.o $(BINDIR)/ipc_api.o

all: $(E)/libipc.a
 
$(E)/libipc.a: $(dobjs)
	@echo "libipc.a"
	#$(LIBMAKER) -static -o $(E)/libipc.a $(dobjs)
	$(LIBMAKER) -r $(E)/libipc.a $(dobjs)

$(BINDIR)/ipc.o: $(mainsrc)/ipc.c
	echo "ipc.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/ipc.o $(mainsrc)/ipc.c

$(BINDIR)/ipc_api.o: $(mainsrc)/ipc_api.c
	echo "ipc_api.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/ipc_api.o $(mainsrc)/ipc_api.c

clean: 
	rm -f $(E)/libipc.a
