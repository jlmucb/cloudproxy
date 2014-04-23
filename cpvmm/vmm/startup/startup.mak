#############################################################################
# Copyright (c) 2013 Intel Corporation
#
#  Author:    Rekha Bachwani from previous eVMM makefiles
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

# compile vmexit library
#   vmexit.c vmexit_io.c vmexit_cr_access.c vmexit_msr.c
#   vmexit_interrupt_exception_nmi.c vmexit_cpuid vmexit_triple_fault.c
#   vmexit_ud.c vmexit_task_switch.c vmexit_sipi.c vmexit_init.c
#   vmcall.c vmexit_invlpg.c vmexit_invd.c vmexit_dbg.c vmexit_ept.c
#   vmexit_analysis.c vmexit_dtr_tr_access.c vmexit_vmx.c vmx_teardown.c
#   teardown_thunk.asm
#   output: libvmexit.a

mainsrc=    $(S)/vmm/startup

B=		$(E)/vmmobjects/startup
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
    		-I$(S)/common/include/arch -I$(S)/vmm/include/hw -I$(S)/common/include/platform \
     		-I$(S)/vmm/guest/guest_cpu -I$(mainsrc)/hw -I$(S)/vmm/memory/ept  \
		-I$(S)/vmm/include/appliances -I$(S)/vmm -I$(S)/vmm/bootstrap

DEBUG_CFLAGS:=  -Wall -Wno-format -g -DDEBUG -nostartfiles -nostdlib -nodefaultlibs -D INVMM -D JLMDEBUG
RELEASE_CFLAGS:= -Wall -Wno-unknown-pragmas -Wno-format -O3  -nostartfiles -nostdlib -nodefaultlibs -D INVMM -D JLMDEBUG
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
AS=         as
LINK=       gcc
LIBMAKER=   ar

dobjs=	$(B)/copy_input_structs.o $(B)/create_guests.o \
	$(B)/layout_host_memory_for_mbr_loader.o \
	$(B)/addons.o $(B)/vmm_extension.o

#ifeq ($(call find_opt,ENABLE_VMM_EXTENSION),1)
#SOURCE +=    vmm_extension.c                        
#endif

all: $(E)/libstartup.a
 
$(E)/libstartup.a: $(dobjs)
	@echo "libstartup.a"
	#$(LIBMAKER) -static -o $(E)/libstartup.a $(dobjs)
	$(LIBMAKER) -r $(E)/libstartup.a $(dobjs)

$(B)/copy_input_structs.o: $(mainsrc)/copy_input_structs.c
	echo "copy_input_structs.o"
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/copy_input_structs.o $(mainsrc)/copy_input_structs.c

$(B)/create_guests.o: $(mainsrc)/create_guests.c
	echo "create_guests.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/create_guests.o $(mainsrc)/create_guests.c

$(B)/layout_host_memory_for_mbr_loader.o: $(mainsrc)/layout_host_memory_for_mbr_loader.c
	echo "layout_host_memory_for_mbr_loader.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/layout_host_memory_for_mbr_loader.o $(mainsrc)/layout_host_memory_for_mbr_loader.c

$(B)/parse_pe_image.o: $(mainsrc)/parse_pe_image.c
	echo "parse_pe_image.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/parse_pe_image.o $(mainsrc)/parse_pe_image.c

$(B)/vmm_extension.o: $(mainsrc)/vmm_extension.c
	echo "vmm_extension" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/vmm_extension.o $(mainsrc)/vmm_extension.c

$(B)/addons.o: $(mainsrc)/addons.c
	echo "addons" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/addons.o $(mainsrc)/addons.c
