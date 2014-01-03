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

# compile guest cpu library
#	guest_cpu.c guest_cpu_switch.c guest_cpu_access.c guest_cpu_vmenter_event.c
#	guest_cpu_control.c unrestricted_guest.c
# output: libguest_cpu.a

mainsrc=    $(S)/vmm/guest/guest_cpu

B=		$(E)/vmmobjects
BINDIR=	        $(B)/libguestcpu
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
    		-I$(S)/common/include/arch -I$(S)/vmm/include/hw \
		-I$(S)/vmm/memory/ept \
		-I$(S)/common/include/platform $(mainsrc) -I$(S)/vmm/guest

DEBUG_CFLAGS:=  -Wall -Werror -Wno-format -g -DDEBUG -nostartfiles -nostdlib -nodefaultlibs 
RELEASE_CFLAGS:= -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3  -nostartfiles -nostdlib -nodefaultlibs 
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
LINK=       gcc
LIBMAKER=   libtool

dobjs=      $(BINDIR)/guest_cpu.o $(BINDIR)/guest_cpu_switch.o \
	    $(BINDIR)/guest_cpu_vmenter_event.o $(BINDIR)/guest_cpu_control.o \
	    $(BINDIR)/unrestricted_guest.o

all: $(E)/libguest_cpu.a
 
$(E)/libguest_cpu.a: $(dobjs)
	@echo "libguest_cpu.a"
	$(LIBMAKER) -static -o $(E)/libguest_cpu.a $(dobjs)

$(BINDIR)/guest_cpu.o: $(mainsrc)/guest_cpu.c
	echo "guest_cpu.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/guest_cpu.o $(mainsrc)/guest_cpu.c

$(BINDIR)/guest_cpu_vmenter_event.o: $(mainsrc)/guest_cpu_vmenter_event.c
	echo "guest_cpu_vmenter_event.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/guest_cpu_vmenter_event.o $(mainsrc)/guest_cpu_vmenter_event.c

$(BINDIR)/guest_cpu_switch.o: $(mainsrc)/guest_cpu_switch.c
	echo "guest_cpu_switch.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/guest_cpu_switch.o $(mainsrc)/guest_cpu_switch.c

$(BINDIR)/guest_cpu_control.o: $(mainsrc)/guest_cpu_control.c
	echo "guest_cpu_control.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/guest_cpu_control.o $(mainsrc)/guest_cpu_control.c

$(BINDIR)/unrestricted_guest.o: $(mainsrc)/unrestricted_guest.c
	echo "unrestricted_guest.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/unrestricted_guest.o $(mainsrc)/unrestricted_guest.c

