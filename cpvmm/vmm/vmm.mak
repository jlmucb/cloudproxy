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

# compile vmm library

mainsrc=    $(S)/vmm

B=		$(E)/vmmobjects
BINDIR=	        $(B)/vmm
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
    -I$(S)/common/include/arch -I$(S)/vmm/include/hw -I$(S)/common/include/platform \
    -I$(mainsrc)/hw -I$(S)/vmm/memory/ept
ASM_SRC = 	
DEBUG_CFLAGS:=  -Wall -Werror -Wno-format -g -DDEBUG -nostartfiles -nostdlib -nodefaultlibs
RELEASE_CFLAGS:= -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3  -nostartfiles -nostdlib -nodefaultlibs
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	
#VM_LIBS       = $(E)/libacpi.a $(E)/libvmx.a $(E)/libc.a $(E)/libhwcommon.a $(E)/libhw.a \
#	        $(E)/libutils.a  $(E)/libhost.a $(E)/libdbg.a $(E)/libmem.a \
#		$(E)/libarch.a $(E)/libguest.a $(E)/libguest_cpu.a $(E)/libscheduler.a \
#		$(E)/libstartup.a $(E)/libvmexit.a $(E)/libipc.a $(E)/libept.a 
LIBS       = libacpi.a libvmx.a libc.a libhwcommon.a libhw.a \
	        libutils.a  libhost.a libdbg.a libmem.a \
		libarch.a libguest.a libguest_cpu.a libscheduler.a \
		libstartup.a libvmexit.a libipc.a libept.a 

CC=         gcc
LINK=       gcc
LIBMAKER=   ar

dobjs=      $(BINDIR)/vmm.o 

all: $(E)/evmm.bin
 
$(E)/evmm.bin: $(dobjs)
	@echo "evmm.bin"
	$(LINK) -o $(E)/evmm.bin -nostdlib -evmm_main $(dobjs) -L $(E)

#$(E)/libacpi.a: 
	#make -f acpi/acpi.mak
#
#$(E)/libvmx.a:
	#make -f vmx/vmx.mak
#
#$(E)/libc.a:
	#make -f libc/libc.mak
#
#$(E)/libhwcommon.a:
	#make -f host/hw/hw.mak
#
#$(E)/libhw.a:
	#make -f host/hw//em64t/em64t.mak
#
#$(E)/libutils.a:
	#make -f utils/utils.mak
#
#$(E)/libhost.a:
	#make -f host/host.mak
#
#$(E)/libdbg.a:
	#make -f dbg/dbg.mak
#
#$(E)/libmem.a:
	#make -f memory/memory_manager/memory_manager.mak
#
#$(E)/libarch.a:
	#make -f arch/arch.mak
#
#$(E)/libguest.a:
	#make -f guest/guest.mak
#
#$(E)/libguest_cpu.a:
	#make -f guest/guest_cpu/guest_cpu.mak
#
#$(E)/libscheduler.a:
	#make -f guest/scheduler/scheduler.mak
#
#$(E)/libstartup.a:
	#make -f startup/startup.mak

#$(E)/libvmexit.a:
#	make -f vmexit/vmexit.mak
#
#$(E)/libipc.a:
	#make -f ipc/ipc.mak

#$(E)/libept.a:
	#make -f memory/ept/ept.mak


$(BINDIR)/vmm.o: $(mainsrc)/vmm.c
	echo "vmm.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmm.o $(mainsrc)/vmm.c $(VM_LIBS)

#  vmm.c
#  output: evmm.bin,  ENTRY:vmm_main

# ifdef ENABLE_MULTI_GUEST_SUPPORT
#         OTHER_MAKEFILE += ./samples/guest_create_addon/guest_create_addon.mak
# endif

