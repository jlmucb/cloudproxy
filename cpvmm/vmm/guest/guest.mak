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

# compile guest library
#   guest.c guest_control.c guest_pci_configuration.c
#   output: libguest.a

mainsrc=    $(S)/vmm/guest

B=		$(E)/vmmobjects/guest
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
    		-I$(S)/common/include/arch -I$(S)/vmm/include/hw \
		-I$(S)/common/include/platform -I$(mainsrc)/guest_cpu \
		-I$(S)/vmm/memory/ept -I$(S)/vmm -I$(S)/vmm/bootstrap
DEBUG_CFLAGS:=  -Wall -Werror -Wno-format -g -DDEBUG -nostartfiles -nostdlib  -fno-tree-loop-distribute-patterns -nodefaultlibs -D INVMM -D JLMDEBUG
RELEASE_CFLAGS:= -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3  -nostartfiles -nostdlib  -fno-tree-loop-distribute-patterns -nodefaultlibs -D INVMM -D JLMDEBUG
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
LINK=       gcc
LIBMAKER=   ar

dobjs=      $(B)/guest.o $(B)/guest_control.o $(B)/guest_pci_configuration.o

all: $(E)/libguest.a
 
$(E)/libguest.a: $(dobjs)
	@echo "libguest.a"
	#$(LIBMAKER) -static -o $(E)/libguest.a $(dobjs)
	$(LIBMAKER) -r $(E)/libguest.a $(dobjs)

$(B)/guest.o: $(mainsrc)/guest.c
	echo "guest.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/guest.o $(mainsrc)/guest.c

$(B)/guest_control.o: $(mainsrc)/guest_control.c
	echo "guest_control.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/guest_control.o $(mainsrc)/guest_control.c

$(B)/guest_pci_configuration.o: $(mainsrc)/guest_pci_configuration.c
	echo "guest_pci_configuration.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/guest_pci_configuration.o $(mainsrc)/guest_pci_configuration.c

