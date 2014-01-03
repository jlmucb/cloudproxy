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

# compile host library
#  vmcs_init.c reset.c local_apic.c host_pci_configuration.c hw_utils.c 
# output: libhwcommon.a

mainsrc=    $(S)/vmm/host/hw

B=		$(E)/vmmobjects
BINDIR=	        $(B)/host
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
    -I$(S)/common/include/arch -I$(S)/vmm/include/hw -I$(S)/common/include/platform \
    -I$(mainsrc)/hw -I$(S)/vmm/memory/ept
ASM_SRC = 	
DEBUG_CFLAGS:=  -Wall -Werror -Wno-format -g -DDEBUG -nostartfiles -nostdlib -nodefaultlibs
RELEASE_CFLAGS:= -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3  -nostartfiles -nostdlib -nodefaultlibs
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
LINK=       gcc
LIBMAKER=   libtool

dobjs=      $(BINDIR)/vmcs_init.o $(BINDIR)/reset.o $(BINDIR)/local_apic.o \
	    $(BINDIR)/host_pci_configuration.o $(BINDIR)/hw_utils.o

all: $(E)/libhwcommon.a
 
$(E)/libhwcommon.a: $(dobjs)
	@echo "libhwcommon.a"
	$(LIBMAKER) -static -o $(E)/libhwcommon.a $(dobjs)

$(BINDIR)/vmcs_init.o: $(mainsrc)/vmcs_init.c
	echo "vmcs_init.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmcs_init.o $(mainsrc)/vmcs_init.c

$(BINDIR)/reset.o: $(mainsrc)/reset.c
	echo "reset.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/reset.o $(mainsrc)/reset.c

$(BINDIR)/local_apic.o: $(mainsrc)/local_apic.c
	echo "local_apic.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/local_apic.o $(mainsrc)/local_apic.c

$(BINDIR)/host_pci_configuration.o: $(mainsrc)/host_pci_configuration.c
	echo "host_pci_configuration.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/host_pci_configuration.o $(mainsrc)/host_pci_configuration.c

$(BINDIR)/hw_utils.o: $(mainsrc)/hw_utils.c
	echo "hw_utils.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/hw_utils.o $(mainsrc)/hw_utils.c

