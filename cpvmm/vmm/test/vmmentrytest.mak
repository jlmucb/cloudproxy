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

mainsrc=    $(S)/vmm

B=		$(E)/vmmobjects/test
INCLUDES=	-I$(S)/vmm -I$(S)/common/include -I$(S)/vmm/include -I../bootstrap

DEBUG_CFLAGS:=  -Wall -Wextra -fwrapv -std=c99 -Wno-format -g -DDEBUG -D INVMM_BLOCKER -D INCLUDE_LAYERING -nostartfiles -nostdlib  -fno-tree-loop-distribute-patterns -nodefaultlibs  -fno-tree-loop-distribute-patterns  -fPIE
RELEASE_CFLAGS:= -Wall -Wextra -fwrapv -std=c99 -Wno-unknown-pragmas -Wno-format -O3  -Wunused-function -D INVMM_BLOCKER -D INCLUDE_LAYERING -nostartfiles -nostdlib  -fno-tree-loop-distribute-patterns -nodefaultlibs  -fno-tree-loop-distribute-patterns  -fPIE
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
LINK=       gcc
LIBMAKER=   ar

dobjs=      $(B)/bootstrap_string.o $(B)/bootstrap_print.o $(B)/vmmstub.o

all: $(E)/evmm.bin
 
$(E)/evmm.bin: $(dobjs)
	@echo "evmm.bin"
	$(LINK) -o $(E)/evmm.bin -static -nostdlib  -fno-tree-loop-distribute-patterns -T ../evmm.script -fPIE -e vmm_main $(dobjs) 

$(B)/vmmstub.o: $(mainsrc)/test/vmmstub.c
	echo "vmmstub.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/vmmstub.o $(mainsrc)/test/vmmstub.c 

$(B)/bootstrap_print.o: $(mainsrc)/bootstrap/bootstrap_print.c
	$(CC)  $(CFLAGS) $(INCLUDES) -fno-stack-protector -c -o $(B)/bootstrap_print.o $(mainsrc)/bootstrap/bootstrap_print.c 

$(B)/bootstrap_string.o: $(mainsrc)/bootstrap/bootstrap_string.c
	$(CC)  $(CFLAGS) $(INCLUDES) -fno-stack-protector -c -o $(B)/bootstrap_string.o $(mainsrc)/bootstrap/bootstrap_string.c 


clean:
	rm -f $(E)/evmm.bin 
	rm -f $(E)/vmmobjects/test/*.o
