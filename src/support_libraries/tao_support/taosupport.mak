#
#    Copyright 2014 John Manferdelli, All Rights Reserved.
#    Licensed under the Apache License, Version 2.0 (the "License");
#    you may not use this file except in compliance with the License.
#    You may obtain a copy of the License at
#        http://www.apache.org/licenses/LICENSE-2.0
#    or in the the file LICENSE-2.0.txt in the top level sourcedirectory
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS,
#    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    See the License for the specific language governing permissions and
#    limitations under the License
#    Project: New Cloudproxy Crypto
#    File: symmetric.mak

ifndef SRC_DIR
SRC_DIR=$(HOME)/src/github.com/jlmucb/cloudproxy/src
endif
ifndef OBJ_DIR
OBJ_DIR=$(HOME)/cryptoobj
endif
ifndef EXE_DIR
EXE_DIR=$(HOME)/cryptobin
endif
ifndef GOOGLE_INCLUDE
GOOGLE_INCLUDE=/usr/local/include/google
endif
ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
endif
ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

S= $(SRC_DIR)/support_libraries
ST= $(S)/tao_support
SP= $(S)/protos
INCLUDE= -I$(ST) -I$(SP) -I/usr/local/include -I$(GOOGLE_INCLUDE) -I/usr/local/ssl/include

CFLAGS=$(INCLUDE) -O3 -g -std=c++11  -Wno-deprecated-declarations #-Wall

OSName = YOSEMITE
ifdef YOSEMITE
	CC=clang++
	LINK=clang++
	PROTO=protoc
	AR=ar
	LDFLAGS= -L$(LOCAL_LIB) -lgtest -lgflags -lprotobuf -lpthread
else
	CC=g++
	LINK=g++
	PROTO=protoc
	AR=ar
	export LD_LIBRARY_PATH=/usr/local/lib
	LDFLAGS= -L$(LD_LIBRARY_PATH) -lprotobuf -lgtest -lgflags -lpthread
endif

O= $(OBJ_DIR)
dobj=	$(O)/taosupport_test.o $(O)/agile_crypto_support.o # $(O)/taosupport.o

all:	taosupport_test.exe
clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/taosupport_test.exe

taosupport_test.exe: $(dobj) 
	@echo "linking executable files"
	$(LINK) -o $(EXE_DIR)/taosupport_test.exe $(dobj) $(LDFLAGS)

$(O)/taosupport_test.o: $(ST)/taosupport_test.cc
	@echo "compiling taosupport_test.cc"
	$(CC) $(CFLAGS) -c -o $(O)/taosupport_test.o $(ST)/taosupport_test.cc

$(O)/agile_crypto_support.o: $(ST)/agile_crypto_support.cc
	@echo "compiling agile_crypto_support.cc"
	$(CC) $(CFLAGS) -c -o $(O)/agile_crypto_support.o $(ST)/agile_crypto_support.cc

$(O)/keys.pb.o: $(SP)/keys.pb.cc
	@echo "compiling keys.pb.cc"
	$(CC) $(CFLAGS) -c -o $(O)/keys.pb.o $(S)/keys.pb.cc

#$(O)/taosupport.pb.o: $(ST)/taosupport.pb.cc
#	@echo "compiling taosupport.pb.cc"
#	$(CC) $(CFLAGS) -c -o $(O)/taosupport.pb.o $(ST)/taosupport.pb.cc
#
#$(O)/taosupport.o: $(ST)/taosupport.cc
#	@echo "compiling taosupport.cc"
#	$(CC) $(CFLAGS) -c -o $(O)/taosupport.o $(ST)/taosupport.cc
#
