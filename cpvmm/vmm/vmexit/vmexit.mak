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

# compile vmexit library
#   vmexit.c vmexit_io.c vmexit_cr_access.c vmexit_msr.c
#   vmexit_interrupt_exception_nmi.c vmexit_cpuid vmexit_triple_fault.c
#   vmexit_ud.c vmexit_task_switch.c vmexit_sipi.c vmexit_init.c
#   vmcall.c vmexit_invlpg.c vmexit_invd.c vmexit_dbg.c vmexit_ept.c
#   vmexit_analysis.c vmexit_dtr_tr_access.c vmexit_vmx.c vmx_teardown.c
#   teardown_thunk.asm
#   output: libvmexit.a

mainsrc=    $(S)/vmm/vmexit

B=		$(E)/vmmobjects
BINDIR=	        $(B)/vmexit
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
    		-I$(S)/common/include/arch -I$(S)/vmm/include/hw \
		-I$(S)/common/include/platform -I$(S)/vmm/guest/guest_cpu \
		-I$(mainsrc)/hw -I$(S)/vmm/memory/ept \
		-I$(S)/vmm -I$(S)/vmm/bootstrap


DEBUG_CFLAGS:=  -Wall -Wno-format -fwrapv -Wall -Werror -g -DDEBUG -nostartfiles -nostdlib  -fno-tree-loop-distribute-patterns -nodefaultlibs -D INVMM -D JLMDEBUG
RELEASE_CFLAGS:= -Wall -Wno-unknown-pragmas -Wno-format -fwrapv -Wall -Werror -O3  -nostartfiles -nostdlib  -fno-tree-loop-distribute-patterns -nodefaultlibs -D INVMM -D JLMDEBUG
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
AS=         as
LINK=       gcc
#LIBMAKER=   libtool
LIBMAKER=   ar

dobjs=      $(BINDIR)/vmexit.o $(BINDIR)/vmexit_io.o \
	    $(BINDIR)/vmexit_interrupt_exception_nmi.o \
	    $(BINDIR)/vmexit_cpuid.o $(BINDIR)/vmexit_triple_fault.o \
	    $(BINDIR)/vmexit_ud.o $(BINDIR)/vmexit_task_switch.o \
	    $(BINDIR)/vmexit_sipi.o $(BINDIR)/vmexit_init.o \
	    $(BINDIR)/vmcall.o $(BINDIR)/vmexit_invlpg.o \
	    $(BINDIR)/vmexit_invd.o $(BINDIR)/vmexit_dbg.o \
	    $(BINDIR)/vmexit_dtr_tr_access.o $(BINDIR)/vmexit_vmx.o \
	    $(BINDIR)/vmexit_vmx.o $(BINDIR)/vmx_teardown.o \
	    $(BINDIR)/teardown_thunk2.o $(BINDIR)/vmexit_analysis.o \
	    $(BINDIR)/vmexit_cr_access.o \
	    $(BINDIR)/vmexit_msr.o \
	    $(BINDIR)/vmexit_ept.o 

all: $(E)/libvmexit.a
 
$(E)/libvmexit.a: $(dobjs)
	@echo "libvmexit.a"
	#$(LIBMAKER) -static -o $(E)/libvmexit.a $(dobjs)
	$(LIBMAKER) -r $(E)/libvmexit.a $(dobjs)

$(BINDIR)/teardown_thunk2.o: $(mainsrc)/teardown_thunk2.c
	echo "teardown_thunk2.o"
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/teardown_thunk2.o $(mainsrc)/teardown_thunk2.c

$(BINDIR)/vmexit.o: $(mainsrc)/vmexit.c
	echo "vmexit.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmexit.o $(mainsrc)/vmexit.c

$(BINDIR)/vmexit_io.o: $(mainsrc)/vmexit_io.c
	echo "vmexit_io.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmexit_io.o $(mainsrc)/vmexit_io.c

$(BINDIR)/vmexit_cr_access.o: $(mainsrc)/vmexit_cr_access.c
	echo "vmexit_cr_access.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmexit_cr_access.o $(mainsrc)/vmexit_cr_access.c

$(BINDIR)/vmexit_msr.o: $(mainsrc)/vmexit_msr.c
	echo "vmexit_msr.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmexit_msr.o $(mainsrc)/vmexit_msr.c

$(BINDIR)/vmexit_interrupt_exception_nmi.o: $(mainsrc)/vmexit_interrupt_exception_nmi.c
	echo "vmexit_interrupt_exception_nmi.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmexit_interrupt_exception_nmi.o $(mainsrc)/vmexit_interrupt_exception_nmi.c

$(BINDIR)/vmexit_cpuid.o: $(mainsrc)/vmexit_cpuid.c
	echo "vmexit_cpuid.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmexit_cpuid.o $(mainsrc)/vmexit_cpuid.c

$(BINDIR)/vmexit_triple_fault.o: $(mainsrc)/vmexit_triple_fault.c
	echo "vmexit_triple_fault.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmexit_triple_fault.o $(mainsrc)/vmexit_triple_fault.c

$(BINDIR)/vmexit_ud.o: $(mainsrc)/vmexit_ud.c
	echo "vmexit_ud.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmexit_ud.o $(mainsrc)/vmexit_ud.c

$(BINDIR)/vmexit_task_switch.o: $(mainsrc)/vmexit_task_switch.c
	echo "vmexit_task_switch.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmexit_task_switch.o $(mainsrc)/vmexit_task_switch.c

$(BINDIR)/vmexit_sipi.o: $(mainsrc)/vmexit_sipi.c
	echo "vmexit_sipi.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmexit_sipi.o $(mainsrc)/vmexit_sipi.c

$(BINDIR)/vmexit_init.o: $(mainsrc)/vmexit_init.c
	echo "vmexit_init.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmexit_init.o $(mainsrc)/vmexit_init.c

$(BINDIR)/vmcall.o: $(mainsrc)/vmcall.c
	echo "vmcall.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmcall.o $(mainsrc)/vmcall.c

$(BINDIR)/vmexit_invlpg.o: $(mainsrc)/vmexit_invlpg.c
	echo "vmexit_invlpg.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmexit_invlpg.o $(mainsrc)/vmexit_invlpg.c

$(BINDIR)/vmexit_invd.o: $(mainsrc)/vmexit_invd.c
	echo "vmexit_invd.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmexit_invd.o $(mainsrc)/vmexit_invd.c

$(BINDIR)/vmexit_dbg.o: $(mainsrc)/vmexit_dbg.c
	echo "vmexit_dbg.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmexit_dbg.o $(mainsrc)/vmexit_dbg.c

$(BINDIR)/vmexit_ept.o: $(mainsrc)/vmexit_ept.c
	echo "vmexit_ept.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmexit_ept.o $(mainsrc)/vmexit_ept.c

$(BINDIR)/vmexit_analysis.o: $(mainsrc)/vmexit_analysis.c
	echo "vmexit_analysis.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmexit_analysis.o $(mainsrc)/vmexit_analysis.c

$(BINDIR)/vmexit_dtr_tr_access.o: $(mainsrc)/vmexit_dtr_tr_access.c
	echo "vmexit_dtr_tr_access.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmexit_dtr_tr_access.o $(mainsrc)/vmexit_dtr_tr_access.c

$(BINDIR)/vmexit_vmx.o: $(mainsrc)/vmexit_vmx.c
	echo "vmexit_vmx.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmexit_vmx.o $(mainsrc)/vmexit_vmx.c

$(BINDIR)/vmx_teardown.o: $(mainsrc)/vmx_teardown.c
	echo "vmx_teardown.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmx_teardown.o $(mainsrc)/vmx_teardown.c

clean: 
	rm -f $(E)/libvmexit.a
