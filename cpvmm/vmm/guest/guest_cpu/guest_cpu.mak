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

B=		$(E)/vmmobjects/guest/guest_cpu
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
    		-I$(S)/common/include/arch -I$(S)/vmm/include/hw \
		-I$(S)/vmm/memory/ept \
		-I$(S)/common/include/platform $(mainsrc) -I$(S)/vmm/guest \
                -I$(S)/vmm/memory/ept -I$(S)/vmm -I$(S)/vmm/bootstrap

DEBUG_CFLAGS:=  -Wall -Wunused-but-set-variable -Wno-format -g -DDEBUG -nostartfiles -nostdlib -nodefaultlibs  -D INVMM -D JLMDEBUG
RELEASE_CFLAGS:= -Wall -Wno-unknown-pragmas -Wno-format -O3  -nostartfiles -nostdlib -nodefaultlibs -Wunused-but-set-variable  -D INVMM -D JLMDEBUG
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
LINK=       gcc
#LIBMAKER=   libtool
LIBMAKER=   ar

dobjs=      $(B)/guest_cpu.o $(B)/guest_cpu_switch.o \
	    $(B)/guest_cpu_vmenter_event.o $(B)/guest_cpu_control.o \
	    $(B)/unrestricted_guest.o $(B)/guest_cpu_access.o

all: $(E)/libguest_cpu.a
 
$(E)/libguest_cpu.a: $(dobjs)
	@echo "libguest_cpu.a"
	#$(LIBMAKER) -static -o $(E)/libguest_cpu.a $(dobjs)
	$(LIBMAKER) -r $(E)/libguest_cpu.a $(dobjs)

$(B)/guest_cpu.o: $(mainsrc)/guest_cpu.c
	echo "guest_cpu.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/guest_cpu.o $(mainsrc)/guest_cpu.c

$(B)/guest_cpu_vmenter_event.o: $(mainsrc)/guest_cpu_vmenter_event.c
	echo "guest_cpu_vmenter_event.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/guest_cpu_vmenter_event.o $(mainsrc)/guest_cpu_vmenter_event.c

$(B)/guest_cpu_switch.o: $(mainsrc)/guest_cpu_switch.c
	echo "guest_cpu_switch.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/guest_cpu_switch.o $(mainsrc)/guest_cpu_switch.c

$(B)/guest_cpu_control.o: $(mainsrc)/guest_cpu_control.c
	echo "guest_cpu_control.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/guest_cpu_control.o $(mainsrc)/guest_cpu_control.c

$(B)/unrestricted_guest.o: $(mainsrc)/unrestricted_guest.c
	echo "unrestricted_guest.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/unrestricted_guest.o $(mainsrc)/unrestricted_guest.c

$(B)/guest_cpu_access.o: $(mainsrc)/guest_cpu_access.c
	echo "guest_cpu_access.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/guest_cpu_access.o $(mainsrc)/guest_cpu_access.c

