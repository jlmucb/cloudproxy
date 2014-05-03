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

# compile scheduler library 
#	scheduler.c
# output: libscheduler.a

mainsrc=    	$(S)/vmm/guest/scheduler

B=		$(E)/vmmobjects/guest/scheduler
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
    		-I$(S)/common/include/arch -I$(S)/vmm/include/hw \
		-I$(S)/vmm/guest -I$(S)/vmm/guest/guest_cpu \
		-I$(S)/common/include/platform -I$(mainsrc) \
		-I$(S)/vmm/bootstrap -I$(S)/vmm
#FIX: got rid of -O3 in release
DEBUG_CFLAGS:=  -Wall -Werror -Wno-format -g -DDEBUG -nostartfiles -nostdlib  -fno-tree-loop-distribute-patterns -nodefaultlibs -DJLMDEBUG -DINVMM
RELEASE_CFLAGS:= -Wall -Werror -Wno-unknown-pragmas -Wno-format -nostartfiles -nostdlib  -fno-tree-loop-distribute-patterns -nodefaultlibs -DJLMDEBUG -DINVMM
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
LINK=       gcc
#LIBMAKER=   libtool
LIBMAKER=   ar

dobjs=      $(B)/scheduler.o

all: $(E)/libscheduler.a
 
$(E)/libscheduler.a: $(dobjs)
	@echo "libscheduler.a"
	#$(LIBMAKER) -static -o $(E)/libscheduler.a $(dobjs)
	$(LIBMAKER) -r $(E)/libscheduler.a $(dobjs)

$(B)/scheduler.o: $(mainsrc)/scheduler.c
	echo "scheduler.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/scheduler.o $(mainsrc)/scheduler.c

