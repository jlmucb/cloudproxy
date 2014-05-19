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

# compile vmx library
# 	vmcs.c vmcs_sw_object.c vmcs_merge_split.c vmcs_actual.c vmcs_hierarchy.c 
# 	vmx_nmi.c vmx_timer.c
# output: libvmx.a

mainsrc=    $(S)/vmm/vmx

B=		$(E)/vmmobjects/vmx
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
    		-I$(S)/common/include/arch -I$(S)/vmm/include/hw -I$(S)/common/include/platform \
    		-I$(mainsrc)/hw -I$(S)/vmm/memory/ept \
		-I$(S)/vmm -I$(S)/vmm/bootstrap
DEBUG_CFLAGS:=  -Wall -Wno-format -fwrapv -Wall -Werror -g -DDEBUG -nostartfiles -nostdlib  -fno-tree-loop-distribute-patterns -nodefaultlibs -D INVMM -DJLMDEBUG
RELEASE_CFLAGS:= -Wall -Wno-unknown-pragmas -Wno-format -fwrapv -Wall -Werror -O3  -nostartfiles -nostdlib  -fno-tree-loop-distribute-patterns -nodefaultlibs -D INVMM -DJLMDEBUG
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
LINK=       gcc
LIBMAKER=   ar

dobjs=     $(B)/vmx.o $(B)/vmcs.o $(B)/vmcs_sw_object.o $(B)/vmcs_merge_split.o \
	   $(B)/vmcs_actual.o $(B)/vmcs_hierarchy.o $(B)/vmx_nmi.o 

all: $(E)/libvmx.a
 
$(E)/libvmx.a: $(dobjs)
	@echo "libvmx.a"
	#$(LIBMAKER) -static -o $(E)/libutils.a $(dobjs)
	$(LIBMAKER) -r $(E)/libvmx.a $(dobjs)

$(B)/vmx.o: $(mainsrc)/vmx.c
	echo "vmx.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/vmx.o $(mainsrc)/vmx.c

$(B)/vmcs.o: $(mainsrc)/vmcs.c
	echo "vmcs.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/vmcs.o $(mainsrc)/vmcs.c

$(B)/vmcs_sw_object.o: $(mainsrc)/vmcs_sw_object.c
	echo "vmcs_sw_object.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/vmcs_sw_object.o $(mainsrc)/vmcs_sw_object.c

$(B)/vmcs_merge_split.o: $(mainsrc)/vmcs_merge_split.c
	echo "vmcs_merge_split.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/vmcs_merge_split.o $(mainsrc)/vmcs_merge_split.c

$(B)/vmcs_actual.o: $(mainsrc)/vmcs_actual.c
	echo "vmcs_actual.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/vmcs_actual.o $(mainsrc)/vmcs_actual.c

$(B)/vmcs_hierarchy.o: $(mainsrc)/vmcs_hierarchy.c
	echo "vmcs_hierarchy.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/vmcs_hierarchy.o $(mainsrc)/vmcs_hierarchy.c

$(B)/vmx_nmi.o: $(mainsrc)/vmx_nmi.c
	echo "vmx_nmi.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/vmx_nmi.o $(mainsrc)/vmx_nmi.c

clean:
	rm -f $(E)/vmmobjects/vmx/*.o $(E)/vmmobjects/vmx/libvmx.a $(E)/libvmx.a
