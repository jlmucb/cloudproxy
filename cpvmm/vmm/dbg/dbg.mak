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

mainsrc=    $(S)/vmm/dbg

B=		$(E)/vmmobjects/dbg
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
    		-I$(S)/common/include/arch -I$(S)/vmm/include/hw -I$(S)/common/include/platform \
     		-I$(S)/vmm/guest/guest_cpu -I$(mainsrc)/hw -I$(S)/vmm/memory/ept  \
		-I$(S)/vmm/include/appliances

DEBUG_CFLAGS:=  -Wall -Wno-format -g -DDEBUG -nostartfiles -nostdlib -nodefaultlibs 
RELEASE_CFLAGS:= -Wall -Wno-unknown-pragmas -Wno-format -O3  -nostartfiles -nostdlib -nodefaultlibs 
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
AS=         as
LINK=       gcc
LIBMAKER=   ar

dobjs= 	$(B)/vmx_trace.o	$(B)/trace.o $(B)/cli_libc.o	\
	$(B)/vmdb.o $(B)/vt100.o $(B)/vmm_dbg.o

all: $(E)/libdbg.a
 
$(E)/libdbg.a: $(dobjs)
	@echo "libdbg.a"
	$(LIBMAKER) -r $(E)/libdbg.a $(dobjs)

$(B)/trace.o: $(mainsrc)/trace.c
	echo "trace.o"
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/trace.o $(mainsrc)/trace.c

$(B)/vmx_trace.o: $(mainsrc)/vmx_trace.c
	echo "vmx_trace.o"
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/vmx_trace.o $(mainsrc)/vmx_trace.c

$(B)/cli_libc.o: $(mainsrc)/cli_libc.c
	echo "cli_libc.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/cli_libc.o $(mainsrc)/cli_libc.c

$(B)/vmdb.o: $(mainsrc)/vmdb.c
	echo "vmdb.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/vmdb.o $(mainsrc)/vmdb.c

$(B)/vt100.o: $(mainsrc)/vt100.c
	echo "vt100.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/vt100.o $(mainsrc)/vt100.c

$(B)/vmm_dbg.o: $(mainsrc)/vmm_dbg.c
	echo "vmm_dbg" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/vmm_dbg.o $(mainsrc)/vmm_dbg.c
