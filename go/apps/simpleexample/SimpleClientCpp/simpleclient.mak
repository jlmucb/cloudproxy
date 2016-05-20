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
#    File: simpleclient.mak

#ifndef SRC_DIR
SRC_DIR=$(HOME)
#endif
#ifndef OBJ_DIR
OBJ_DIR=/Domains
#endif
#ifndef EXE_DIR
EXE_DIR=/Domains
#endif
#ifndef GOOGLE_INCLUDE
GOOGLE_INCLUDE=/usr/local/include/google
#endif
#ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
#endif
#ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
#endif

S= $(SRC_DIR)/src/github.com/jlmucb/cloudproxy/go/apps/simpleexample/SimpleClientCpp
SL= $(SRC_DIR)/src/github.com/jlmucb/cloudproxy/src
O= $(OBJ_DIR)/simpleclient_obj
INCLUDE= -I$(S) -I/usr/local/include -I$(GOOGLE_INCLUDE) -I$(SL) -I/usr/local/ssl/include

CFLAGS=$(INCLUDE) -DOS_POSIX -O3 -g -Wall -std=c++11 -Wno-strict-aliasing -Wno-deprecated # -DGFLAGS_NS=google
CFLAGS1=$(INCLUDE) -DOS_POSIX -O1 -g -Wall -std=c++11

CC=g++
LINK=g++
PROTO=protoc
AR=ar
export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread -lcrypto -lssl -lchromium -lglog -lmodp

dobj_simpleclient=$(O)/taosupport.o $(O)/helpers.o \
	$(O)/ca.pb.o $(O)/attestation.pb.o $(O)/datalog_guard.pb.o \
	$(O)/acl_guard.pb.o $(O)/taosupport.pb.o $(O)/simpleclient_cc.o

all:	$(EXE_DIR)/simpleclient_cc.exe

clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/simpleclient_cc.exe

$(EXE_DIR)/simpleclient_cc.exe: $(dobj_simpleclient)
	@echo "linking simpleclient"
	$(LINK) -o $(EXE_DIR)/simpleclient_cc.exe $(dobj_simpleclient) \
	-L/Domains -lauth -ltao $(LDFLAGS)

$(O)/helpers.o: $(S)/helpers.cc
	@echo "compiling helpers.cc"
	$(CC) $(CFLAGS) -c -o $(O)/helpers.o $(S)/helpers.cc

$(O)/ca.pb.o: $(S)/ca.pb.cc
	@echo "compiling ca.pb.cc"
	$(CC) $(CFLAGS) -c -o $(O)/ca.pb.o $(S)/ca.pb.cc

$(O)/taosupport.pb.o: $(S)/taosupport.pb.cc
	@echo "compiling taosupport.pb.cc"
	$(CC) $(CFLAGS) -c -o $(O)/taosupport.pb.o $(S)/taosupport.pb.cc

$(O)/attestation.pb.o: $(S)/attestation.pb.cc
	@echo "compiling attestation.pb.cc"
	$(CC) $(CFLAGS) -c -o $(O)/attestation.pb.o $(S)/attestation.pb.cc

$(O)/datalog_guard.pb.o: $(S)/datalog_guard.pb.cc
	@echo "compiling datalog_guard.pb.cc"
	$(CC) $(CFLAGS) -c -o $(O)/datalog_guard.pb.o $(S)/datalog_guard.pb.cc

$(O)/acl_guard.pb.o: $(S)/acl_guard.pb.cc
	@echo "compiling acl_guard.pb.cc"
	$(CC) $(CFLAGS) -c -o $(O)/acl_guard.pb.o $(S)/acl_guard.pb.cc

$(O)/taosupport.o: $(S)/taosupport.cc
	@echo "compiling taosupport.cc"
	$(CC) $(CFLAGS) -c -o $(O)/taosupport.o $(S)/taosupport.cc

$(O)/simpleclient_cc.o: $(S)/simpleclient_cc.cc
	@echo "compiling simpleclient_cc.cc"
	$(CC) $(CFLAGS) -c -o $(O)/simpleclient_cc.o $(S)/simpleclient_cc.cc


