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

DEBUG_CFLAGS:=  -Wno-format -g -DDEBUG -nostartfiles -nostdlib -nodefaultlibs
RELEASE_CFLAGS:= -Wno-unknown-pragmas -Wno-format -O3  -nostartfiles -nostdlib -nodefaultlibs -Wunused-function
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	
VM_LIBS       = $(E)/libacpi.a $(E)/libvmx.a $(E)/libc.a $(E)/libhwcommon.a $(E)/libhw.a \
	        $(E)/libutils.a  $(E)/libhost.a $(E)/libdbg.a $(E)/libmem.a \
		$(E)/libarch.a $(E)/libguest.a $(E)/libguest_cpu.a $(E)/libscheduler.a \
		$(E)/libstartup.a $(E)/libvmexit.a $(E)/libipc.a $(E)/libept.a 

CC=         gcc
LINK=       gcc
LIBMAKER=   ar

ACPIOBJ=	$(B)/acpi/vmm_acpi.o  $(B)/acpi/vmm_acpi_pm.o

ARCHOBJ=	$(B)/arch/e820_abstraction.o  $(B)/arch/efer_msr_abstraction.o  \
		$(B)/arch/mtrrs_abstraction.o  $(B)/arch/pat_manager.o

DBGOBJ=		$(B)/dbg/cli_libc.o  $(B)/dbg/vmdb.o  $(B)/dbg/vmm_dbg.o  \
		$(B)/dbg/vmx_trace.o  $(B)/dbg/vt100.o

EMTOBJ= 	$(B)/host/hw/em64t/em64t_idt.o $(B)/host/hw/em64t/em64t_setjmp.o \
		$(B)/host/hw/em64t/em64t_interlocked2.o  \
		$(B)/host/hw/em64t/em64t_utils2.o \
		$(B)/host/hw/em64t/em64t_fpu2.o \
		$(B)/host/hw/em64t/em64t_gcpu_regs_save_restore.o  \
		$(B)/host/hw/em64t/em64t_vmx.o $(B)/host/hw/em64t/em64t_gdt.o \
		$(B)/host/hw/em64t/em64t_isr2.o

GUESTOBJ=	$(B)/guest/guest_control.o  $(B)/guest/guest.o  \
		$(B)/guest/guest_pci_configuration.o

GUESTCPUOBJ=	$(B)/guest/guest_cpu/guest_cpu_control.o  \
		$(B)/guest/guest_cpu/guest_cpu_switch.o  \
		$(B)/guest/guest_cpu/unrestricted_guest.o \
		$(B)/guest/guest_cpu/guest_cpu.o  \
		$(B)/guest/guest_cpu/guest_cpu_access.o  \
		$(B)/guest/guest_cpu/guest_cpu_vmenter_event.o


GUESTSCHEDOBJ=	$(B)/guest/scheduler/scheduler.o

HOSTOBJ=	$(B)/host/host_cpu.o  $(B)/host/isr.o  $(B)/host/policy_manager.o  \
		$(B)/host/trial_exec.o  $(B)/host/vmm_globals.o

HOSTHW=		$(B)/host/hw/host_pci_configuration.o  $(B)/host/hw/hw_utils.o  \
		$(B)/host/hw/local_apic.o  $(B)/host/hw/reset.o  \
		$(B)/host/hw/vmcs_init.o

IPCOBJ=		$(B)/ipc/ipc_api.o  $(B)/ipc/ipc.o

LIBCOBJ=	$(B)/libc/bitarray_utilities.o  $(B)/libc/common_libc.o  \
		$(B)/libc/libc.o  $(B)/libc/sprintf.o  $(B)/libc/vmm_io.o \
		$(B)/libc/vmm_serial.o
EPTOBJ=		$(B)/memory/ept/ept_hw_layer.o  $(B)/memory/ept/ept.o  \
		$(B)/memory/ept/fvs.o  $(B)/memory/ept/invept2.o  \
		$(B)/memory/ept/ve.o

MEMMGROBJ=	$(B)/memory/memory_manager/flat_page_tables.o  \
		$(B)/memory/memory_manager/host_memory_manager.o \
		$(B)/memory/memory_manager/page_walker.o  \
		$(B)/memory/memory_manager/vmm_stack.o \
		$(B)/memory/memory_manager/gpm.o \
		$(B)/memory/memory_manager/memory_address_mapper.o  \
		$(B)/memory/memory_manager/pool.o

STARTOBJ=	$(B)/startup/addons.o $(B)/startup/create_guests.o \
		$(B)/startup/parse_pe_image.o $(B)/startup/copy_input_structs.o  \
		$(B)/startup/layout_host_memory_for_mbr_loader.o

VMEXITOBJ=	$(B)/vmexit/teardown_thunk.o $(B)/vmexit/vmexit_ept.o \
		$(B)/vmexit/vmexit.o $(B)/vmexit/vmcall.o \
		$(B)/vmexit/vmexit_init.o $(B)/vmexit/vmexit_sipi.o \
		$(B)/vmexit/vmexit_analysis.o  \
		$(B)/vmexit/vmexit_interrupt_exception_nmi.o  \
		$(B)/vmexit/vmexit_task_switch.o \
		$(B)/vmexit/vmexit_cpuid.o $(B)/vmexit/vmexit_invd.o \
		$(B)/vmexit/vmexit_triple_fault.o \
		$(B)/vmexit/vmexit_cr_access.o $(B)/vmexit/vmexit_invlpg.o \
		$(B)/vmexit/vmexit_ud.o $(B)/vmexit/vmexit_dbg.o \
		$(B)/vmexit/vmexit_io.o $(B)/vmexit/vmexit_vmx.o \
		$(B)/vmexit/vmexit_dtr_tr_access.o  $(B)/vmexit/vmexit_msr.o \
		$(B)/vmexit/vmx_teardown.o

VMXOBJ=		$(B)/vmx/vmcs_actual.o $(B)/vmx/vmcs_merge_split.o  \
		$(B)/vmx/vmcs_sw_object.o $(B)/vmx/vmcs_hierarchy.o  \
		$(B)/vmx/vmcs.o $(B)/vmx/vmx_nmi.o

UTILOBJ=	$(B)/utils/address.o $(B)/utils/cache64.o \
		$(B)/utils/hash64.o  $(B)/utils/lock.o \
		$(B)/utils/memory_allocator.o $(B)/utils/array_list.o  \
		$(B)/utils/event_mgr.o  $(B)/utils/heap.o \
		$(B)/utils/math_utils.o  $(B)/utils/utils_asm.o





dobjs=      $(BINDIR)/vmm.o 

all: $(E)/evmm.bin
 
$(E)/evmm.bin: $(dobjs)
	@echo "evmm.bin"
	make -f $(S)/vmm/acpi/acpi.mak
	make -f $(S)/vmm/vmx/vmx.mak
	make -f $(S)/vmm/libc/libc.mak
	make -f $(S)/vmm/host/hw/hw.mak
	make -f $(S)/vmm/host/hw/em64t/em64t.mak
	make -f $(S)/vmm/utils/utils.mak
	make -f $(S)/vmm/host/host.mak
	make -f $(S)/vmm/dbg/dbg.mak
	make -f $(S)/vmm/memory/memory_manager/memory_manager.mak
	make -f $(S)/vmm/arch/arch.mak
	make -f $(S)/vmm/guest/guest.mak
	make -f $(S)/vmm/guest/guest_cpu/guest_cpu.mak
	make -f $(S)/vmm/guest/scheduler/scheduler.mak
	make -f $(S)/vmm/startup/startup.mak
	make -f $(S)/vmm/vmexit/vmexit.mak
	make -f $(S)/vmm/ipc/ipc.mak
	make -f $(S)/vmm/memory/ept/ept.mak
	$(LINK) -o $(E)/evmm.bin -nostdlib -evmm_main \
		$(ACPIOBJ) $(ARCHOBJ) $(DBGOBJ) $(EMTOBJ) \
		$(GUESTOBJ) $(GUESTCPUOBJ) $(GUESTSCHEDOBJ) \
		$(IPCOBJ) $(LIBCOBJ) $(EPTOBJ) $(MEMMGROBJ) \
		$(HOSTOBJ) $(STARTOBJ) $(VMEXITOBJ) $(VMXOBJ) \
		$(HOSTHW) $(UTILOBJ) $(dobjs) 


$(BINDIR)/vmm.o: $(mainsrc)/vmm.c
	echo "vmm.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmm.o $(mainsrc)/vmm.c 

#  vmm.c
#  output: evmm.bin,  ENTRY:vmm_main

# ifdef ENABLE_MULTI_GUEST_SUPPORT
#         OTHER_MAKEFILE += ./samples/guest_create_addon/guest_create_addon.mak
# endif

