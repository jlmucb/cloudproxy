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

# compile hw library
#  vmcs_init.c reset.c local_apic.c host_pci_configuration.c hw_utils.c 
# output: libhwcommon.a

mainsrc=    $(S)/vmm/host/hw

B=		$(E)/vmmobjects/host/hw
INCLUDES=	-I$(S)/vmm -I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
    		-I$(S)/common/include/arch -I$(S)/vmm/include/hw -I$(S)/common/include/platform \
    		-I$(mainsrc)/hw -I$(S)/vmm/memory/ept -I$(S)/vmm/vmx -I$(S)/vmm/bootstrap \
		-I$(S)/vmm -I$(src)/vmm/bootstrap
DEBUG_CFLAGS:=  -Wall -Werror -Wno-format -g -DDEBUG -nostartfiles -nostdlib -nodefaultlibs -D INVMM -D JLMDEBUG
RELEASE_CFLAGS:= -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3  -nostartfiles -nostdlib -nodefaultlibs -D INVMM -D JLMDEBUG
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
LINK=       gcc
LIBMAKER=   ar

dobjs=      $(B)/vmcs_init.o $(B)/reset.o $(B)/local_apic.o \
	    $(B)/host_pci_configuration.o $(B)/hw_utils.o $(B)/machinesupport.o

all: $(E)/libhwcommon.a
 
$(E)/libhwcommon.a: $(dobjs)
	@echo "libhwcommon.a"
	#$(LIBMAKER) -static -o $(E)/libhwcommon.a $(dobjs)
	$(LIBMAKER) -r $(E)/libhwcommon.a $(dobjs)

$(B)/vmcs_init.o: $(mainsrc)/vmcs_init.c
	echo "vmcs_init.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/vmcs_init.o $(mainsrc)/vmcs_init.c

$(B)/reset.o: $(mainsrc)/reset.c
	echo "reset.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/reset.o $(mainsrc)/reset.c

$(B)/local_apic.o: $(mainsrc)/local_apic.c
	echo "local_apic.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/local_apic.o $(mainsrc)/local_apic.c

$(B)/host_pci_configuration.o: $(mainsrc)/host_pci_configuration.c
	echo "host_pci_configuration.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/host_pci_configuration.o $(mainsrc)/host_pci_configuration.c

$(B)/hw_utils.o: $(mainsrc)/hw_utils.c
	echo "hw_utils.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/hw_utils.o $(mainsrc)/hw_utils.c

$(B)/machinesupport.o: $(mainsrc)/machinesupport.c
	echo "machinesupport.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/machinesupport.o $(mainsrc)/machinesupport.c

