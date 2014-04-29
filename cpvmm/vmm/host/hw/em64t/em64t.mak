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
E=              /home/jlm/jlmcrypt
else
E=              $(CPProgramDirectory)
endif
ifndef VMSourceDirectory
S=              /home/jlm/fpDev/fileProxy/cpvmm
else
S=              $(VMSourceDirectory)
endif
ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

# compile em64t library
# em64t_interlocked.asm em64t_isr.asm em64t_utils.asm em64t_gcpu_regs_save_restore.asm
# em64t_vmx.asm em64t_fpu.asm em64t_setjmp.asm em64t_idt.c em64t_gdt.c
# output: libhw.a

mainsrc=    	$(S)/vmm/host/hw/em64t

B=              $(E)/vmmobjects/host/hw/em64t
INCLUDES=       -I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
		-I$(S)/common/include/arch -I$(S)/vmm/include/hw \
		-I$(S)/common/include/platform  -I$(S)/vmm/guest/guest_cpu\
    		-I$(mainsrc)/hw -I$(S)/vmm/memory/ept \
		-I$(S)/vmm -I$(S)/vmm/bootstrap

DEBUG_CFLAGS:=  -Wall -Wno-format -g -DDEBUG -nostartfiles -nostdlib  -fno-tree-loop-distribute-patterns -nodefaultlibs -D INVMM -D JLMDEBUG
RELEASE_CFLAGS:= -Wall -Wno-unknown-pragmas -Wno-format -O3  -nostartfiles -nostdlib  -fno-tree-loop-distribute-patterns -nodefaultlibs -D INVMM -D JLMDEBUG
CFLAGS=         $(RELEASE_CFLAGS) 
LDFLAGS=        

CC=         gcc
AS=         as
LINK=       gcc
LIBMAKER=   ar

dobjs=      $(B)/em64t_idt.o $(B)/em64t_gdt.o $(B)/em64t_setjmp.o \
	    $(B)/em64t_vmx2.o $(B)/em64t_isr.o  

all: $(E)/libhw.a
 
$(E)/libhw.a: $(dobjs)
	@echo "libhw.a"
	$(LIBMAKER) -r $(E)/libhw.a $(dobjs)


$(B)/em64t_idt.o: $(mainsrc)/em64t_idt.c
	echo "em64t_idt.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/em64t_idt.o $(mainsrc)/em64t_idt.c

$(B)/em64t_gdt.o: $(mainsrc)/em64t_gdt.c
	echo "em64t_gdt.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/em64t_gdt.o $(mainsrc)/em64t_gdt.c

$(B)/em64t_isr.o: $(mainsrc)/em64t_isr.s
	echo "em64t_isr.o" 
	$(AS) -o $(B)/em64t_isr.o $(mainsrc)/em64t_isr.s

$(B)/em64t_setjmp.o: $(mainsrc)/em64t_setjmp.s
	echo "em64t_setjmp.o"
	$(AS) -o $(B)/em64t_setjmp.o $(mainsrc)/em64t_setjmp.s

$(B)/em64t_vmx2.o: $(mainsrc)/em64t_vmx2.c
	echo "em64t_vmx.o"
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/em64t_vmx2.o $(mainsrc)/em64t_vmx2.c
