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
#    vmm_acpi.c vmm_acpi_pm.c
#    output: libacpi.a

mainsrc=    $(S)/vmm/acpi

B=		$(E)/vmmobjects
BINDIR=	        $(B)/acpi
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
    -I$(S)/common/include/arch -I$(S)/vmm/include/hw -I$(S)/common/include/platform \
    -I$(S)/vmm/guest/guest_cpu -I$(S)/vmm/guest -I$(mainsrc)/hw \
		-I$(S)/vmm/memory/ept -I$(S)/startap
ASM_SRC = 	
DEBUG_CFLAGS:=  -Wall -Werror -Wno-format -g -DDEBUG -nostartfiles -nostdlib  -fno-tree-loop-distribute-patterns -nodefaultlibs
RELEASE_CFLAGS:= -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3  -nostartfiles -nostdlib  -fno-tree-loop-distribute-patterns -nodefaultlibs
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
LINK=       gcc
LIBMAKER=   ar

dobjs=      $(BINDIR)/vmm_acpi.o $(BINDIR)/vmm_acpi_pm.o

all: $(E)/libacpi.a
 
$(E)/libacpi.a: $(dobjs)
	@echo "libacpi.a"
	$(LIBMAKER) -r $(E)/libacpi.a $(dobjs)

$(BINDIR)/vmm_acpi.o: $(mainsrc)/vmm_acpi.c
	echo "vmm_acpi.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmm_acpi.o $(mainsrc)/vmm_acpi.c

$(BINDIR)/vmm_acpi_pm.o: $(mainsrc)/vmm_acpi_pm.c
	echo "vmm_acpi_pm.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmm_acpi_pm.o $(mainsrc)/vmm_acpi_pm.c

clean: 
	rm -f $(E)/libacpi.a
