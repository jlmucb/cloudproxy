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
LIB_SOURCE= $(SL)/support_libraries
O= $(OBJ_DIR)/simpleclient_obj
INCLUDE=-I$(S) -I/usr/local/include -I$(GOOGLE_INCLUDE) -I$(SL) -I/usr/local/ssl/include -I/Domains/include \
-I$(LIB_SOURCE)/tao_support -I$(LIB_SOURCE)/protos

CFLAGS=-DOS_POSIX -O3 -g -Wall -std=c++11 -Wno-strict-aliasing -Wno-deprecated
CFLAGS1=-DOS_POSIX -O1 -g -Wall -std=c++11

CC=g++
LINK=g++
PROTO=protoc
AR=ar
export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS_SHORT=-lprotobuf -lgtest -lgflags -lpthread -lssl -lglog -lcrypto
LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread -lcrypto -lssl -lchromium -lglog -lmodp

#ifdef MAC_OS
LIB_EXTRA_MAC=-L/usr/local/ssl/lib  -L$(LD_LIBRARY_PATH)
#endif

dobj_simpleclient=$(O)/taosupport.o $(O)/helpers.o $(O)/ca.pb.o $(O)/attestation.pb.o \
	$(O)/datalog_guard.pb.o $(O)/acl_guard.pb.o $(O)/messages.pb.o \
	$(O)/domain_policy.pb.o $(O)/keys.pb.o $(O)/simpleclient_cc.o

dobj_test=$(O)/helpers.o $(O)/messages.pb.o $(O)/helpers_test.o
dobj_simple_server=$(O)/helpers.o $(O)/messages.pb.o $(O)/simple_server_test.o
dobj_simple_client=$(O)/helpers.o $(O)/messages.pb.o $(O)/simple_client_test.o
dobj_gen_keys=$(O)/helpers.o $(O)/messages.pb.o $(O)/gen_keys.o
dobj_gen_keys_test=$(O)/helpers.o $(O)/messages.pb.o $(O)/gen_keys_test.o
dobj_server=$(O)/helpers.o $(O)/messages.pb.o $(O)/server_test.o
dobj_client=$(O)/helpers.o $(O)/messages.pb.o $(O)/client_test.o

all:	$(EXE_DIR)/helpers_test.exe $(EXE_DIR)/simple_server_test.exe $(EXE_DIR)/simple_client_test.exe $(EXE_DIR)/simpleclient_cc.exe $(EXE_DIR)/gen_keys.exe $(EXE_DIR)/gen_keys_test.exe $(EXE_DIR)/server_test.exe $(EXE_DIR)/client_test.exe

clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/simpleclient_cc.exe

$(EXE_DIR)/simpleclient_cc.exe: $(dobj_simpleclient)
	@echo "linking simpleclient"
	$(LINK) -o $(EXE_DIR)/simpleclient_cc.exe $(dobj_simpleclient) \
	$(LIB_EXTRA_MAC) -L/Domains -lauth -ltao $(LDFLAGS)

$(EXE_DIR)/helpers_test.exe: $(dobj_test)
	@echo "linking helpers_test"
	$(LINK) -o $(EXE_DIR)/helpers_test.exe $(dobj_test) $(LIB_EXTRA_MAC) -L/Domains $(LDFLAGS_SHORT)

$(EXE_DIR)/simple_client_test.exe: $(dobj_simple_client)
	@echo "linking simple_client_test"
	$(LINK) -o $(EXE_DIR)/simple_client_test.exe $(dobj_simple_client) $(LIB_EXTRA_MAC) -L/Domains $(LDFLAGS_SHORT)

$(EXE_DIR)/simple_server_test.exe: $(dobj_simple_server)
	@echo "linking simple_server_test"
	$(LINK) -o $(EXE_DIR)/simple_server_test.exe $(dobj_simple_server) $(LIB_EXTRA_MAC) -L/Domains $(LDFLAGS_SHORT)

$(EXE_DIR)/client_test.exe: $(dobj_client)
	@echo "linking client_test"
	$(LINK) -o $(EXE_DIR)/client_test.exe $(dobj_client) $(LIB_EXTRA_MAC) -L/Domains $(LDFLAGS_SHORT)

$(EXE_DIR)/server_test.exe: $(dobj_server)
	@echo "linking server_test"
	$(LINK) -o $(EXE_DIR)/server_test.exe $(dobj_server) $(LIB_EXTRA_MAC) -L/Domains $(LDFLAGS_SHORT)

$(EXE_DIR)/gen_keys_test.exe: $(dobj_gen_keys_test)
	@echo "linking gen_keys_test"
	$(LINK) -o $(EXE_DIR)/gen_keys_test.exe $(dobj_gen_keys_test) $(LIB_EXTRA_MAC) -L/Domains $(LDFLAGS_SHORT)

$(EXE_DIR)/gen_keys.exe: $(dobj_gen_keys)
	@echo "linking gen_keys"
	$(LINK) -o $(EXE_DIR)/gen_keys.exe $(dobj_gen_keys) $(LIB_EXTRA_MAC) -L/Domains $(LDFLAGS_SHORT)

$(O)/helpers.o: $(S)/helpers.cc
	@echo "compiling helpers.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/helpers.o $(S)/helpers.cc

$(O)/domain_policy.pb.o: $(LIB_SOURCE)/protos/domain_policy.pb.cc
	@echo "compiling domain_policy.pb.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/domain_policy.pb.o $(LIB_SOURCE)/protos/domain_policy.pb.cc

$(O)/keys.pb.o: $(S)/keys.pb.cc
	@echo "compiling keys.pb.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/keys.pb.o $(S)/keys.pb.cc

$(O)/ca.pb.o: $(S)/ca.pb.cc
	@echo "compiling ca.pb.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/ca.pb.o $(S)/ca.pb.cc

$(O)/messages.pb.o: $(S)/messages.pb.cc
	@echo "compiling messages.pb.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/messages.pb.o $(S)/messages.pb.cc

$(O)/attestation.pb.o: $(S)/attestation.pb.cc
	@echo "compiling attestation.pb.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/attestation.pb.o $(S)/attestation.pb.cc

$(O)/datalog_guard.pb.o: $(S)/datalog_guard.pb.cc
	@echo "compiling datalog_guard.pb.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/datalog_guard.pb.o $(S)/datalog_guard.pb.cc

$(O)/acl_guard.pb.o: $(S)/acl_guard.pb.cc
	@echo "compiling acl_guard.pb.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/acl_guard.pb.o $(S)/acl_guard.pb.cc

$(O)/taosupport.o: $(LIB_SOURCE)/tao_support/taosupport.cc
	@echo "compiling taosupport.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/taosupport.o $(LIB_SOURCE)/tao_support/taosupport.cc

$(O)/simpleclient_cc.o: $(S)/simpleclient_cc.cc
	@echo "compiling simpleclient_cc.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/simpleclient_cc.o $(S)/simpleclient_cc.cc

$(O)/helpers_test.o: $(S)/helpers_test.cc
	@echo "compiling helpers_test.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/helpers_test.o $(S)/helpers_test.cc

$(O)/simple_server_test.o: $(S)/simple_server_test.cc
	@echo "compiling simple_server_test.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/simple_server_test.o $(S)/simple_server_test.cc

$(O)/simple_client_test.o: $(S)/simple_client_test.cc
	@echo "compiling simple_client_test.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/simple_client_test.o $(S)/simple_client_test.cc

$(O)/server_test.o: $(S)/server_test.cc
	@echo "compiling server_test.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/server_test.o $(S)/server_test.cc

$(O)/client_test.o: $(S)/client_test.cc
	@echo "compiling client_test.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/client_test.o $(S)/client_test.cc

$(O)/gen_keys.o: $(S)/gen_keys.cc
	@echo "compiling gen_keys.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/gen_keys.o $(S)/gen_keys.cc

$(O)/gen_keys_test.o: $(S)/gen_keys_test.cc
	@echo "compiling gen_keys_test.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/gen_keys_test.o $(S)/gen_keys_test.cc

