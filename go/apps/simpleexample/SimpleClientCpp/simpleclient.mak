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
#ifndef GFLAGS_INCLUDE
GFLAGS_INCLUDE=$(SRC_DIR)/src/github.com/jlmucb/cloudproxy/src/third_party/gflags/src
#endif
#ifndef GLOG_INCLUDE
GLOG_INCLUDE=$(SRC_DIR)/src/github.com/jlmucb/cloudproxy/src/third_party/google-glog/src
#endif
#ifndef CHROMIUM_INCLUDE
CHROMIUM_INCLUDE=$(SRC_DIR)/src/github.com/jlmucb/cloudproxy/src/third_party/chromium/include
#endif
#ifndef TAO_INCLUDE
TAO_INCLUDE=$(SRC_DIR)/src/github.com/jlmucb/cloudproxy/src/out
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
INCLUDE= -I$(S) -I/usr/local/include -I$(GFLAGS_INCLUDE) -I$(GLOG_INCLUDE) -I$(CHROMIUM_INCLUDE) -I$(TAO_INCLUDE) -I$(SL) -I/usr/local/ssl/include

CFLAGS=$(INCLUDE) -DOS_POSIX -O3 -g -Wall -std=c++11 -Wno-strict-aliasing -Wno-deprecated # -DGFLAGS_NS=google
CFLAGS1=$(INCLUDE) -DOS_POSIX -O1 -g -Wall -std=c++11

LIBS=-L$(SL)/out/third_party/googlemock/gtest -L$(SL)/out/third_party/google-glog 
CC=g++
LINK=g++
PROTO=protoc
AR=ar
export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS_SHORT=$(LIBS) -lprotobuf -lgtest -lgflags -lpthread -lssl -lglog -lcrypto
LDFLAGS=$(LIBS) -lprotobuf -lgtest -lgflags -lpthread -lcrypto -lssl -lchromium -lglog -lmodp

dobj_simpleclient=$(O)/taosupport.o $(O)/helpers.o $(O)/ca.pb.o $(O)/attestation.pb.o \
	$(O)/datalog_guard.pb.o $(O)/acl_guard.pb.o $(O)/taosupport.pb.o \
	$(O)/keys.pb.o $(O)/simpleclient_cc.o

dobj_test=$(O)/helpers.o $(O)/taosupport.pb.o $(O)/helpers_test.o
dobj_simple_server=$(O)/helpers.o $(O)/taosupport.pb.o $(O)/simple_server_test.o
dobj_simple_client=$(O)/helpers.o $(O)/taosupport.pb.o $(O)/simple_client_test.o
dobj_gen_keys=$(O)/helpers.o $(O)/taosupport.pb.o $(O)/gen_keys.o
dobj_gen_keys_test=$(O)/helpers.o $(O)/taosupport.pb.o $(O)/gen_keys_test.o
dobj_server=$(O)/helpers.o $(O)/taosupport.pb.o $(O)/server_test.o
dobj_client=$(O)/helpers.o $(O)/taosupport.pb.o $(O)/client_test.o

all:	$(EXE_DIR)/helpers_test.exe $(EXE_DIR)/simple_server_test.exe $(EXE_DIR)/simple_client_test.exe $(EXE_DIR)/simpleclient_cc.exe $(EXE_DIR)/gen_keys.exe $(EXE_DIR)/gen_keys_test.exe $(EXE_DIR)/server_test.exe $(EXE_DIR)/client_test.exe
#For Macs
#all:	$(EXE_DIR)/helpers_test.exe $(EXE_DIR)/simple_server_test.exe $(EXE_DIR)/simple_client_test.exe#$(EXE_DIR)/simpleclient_cc.exe

clean:
	@echo "removing object files"
	rm -f $(O)/*.o
	@echo "removing executable file"
	rm -f $(EXE_DIR)/simpleclient_cc.exe

$(EXE_DIR)/simpleclient_cc.exe: $(dobj_simpleclient)
	@echo "linking simpleclient"
	$(LINK) -o $(EXE_DIR)/simpleclient_cc.exe $(dobj_simpleclient) \
	-L/Domains -lauth -ltao $(LDFLAGS)

$(EXE_DIR)/helpers_test.exe: $(dobj_test)
	@echo "linking helpers_test"
	$(LINK) -o $(EXE_DIR)/helpers_test.exe $(dobj_test) -L/Domains $(LDFLAGS_SHORT)
#For Macs
#	$(LINK) -o $(EXE_DIR)/helpers_test.exe $(dobj_test) -L/usr/local/ssl/lib  -L$(LD_LIBRARY_PATH) -L/Domains $(LDFLAGS_SHORT)

$(EXE_DIR)/simple_client_test.exe: $(dobj_simple_client)
	@echo "linking simple_client_test"
	$(LINK) -o $(EXE_DIR)/simple_client_test.exe $(dobj_simple_client) -L/Domains $(LDFLAGS_SHORT)
#For Macs
#	$(LINK) -o $(EXE_DIR)/simple_client_test.exe $(dobj_simple_client) -L/usr/local/ssl/lib  -L$(LD_LIBRARY_PATH) -L/Domains $(LDFLAGS_SHORT)

$(EXE_DIR)/simple_server_test.exe: $(dobj_simple_server)
	@echo "linking simple_server_test"
	$(LINK) -o $(EXE_DIR)/simple_server_test.exe $(dobj_simple_server) -L/usr/local/ssl/lib  -L$(LD_LIBRARY_PATH) -L/Domains $(LDFLAGS_SHORT)

$(EXE_DIR)/client_test.exe: $(dobj_client)
	@echo "linking client_test"
	$(LINK) -o $(EXE_DIR)/client_test.exe $(dobj_client) -L/Domains $(LDFLAGS_SHORT)
#For Macs
#	$(LINK) -o $(EXE_DIR)/client_test.exe $(dobj_client) -L/usr/local/ssl/lib  -L$(LD_LIBRARY_PATH) -L/Domains $(LDFLAGS_SHORT)

$(EXE_DIR)/server_test.exe: $(dobj_server)
	@echo "linking server_test"
	$(LINK) -o $(EXE_DIR)/server_test.exe $(dobj_server) -L/usr/local/ssl/lib  -L$(LD_LIBRARY_PATH) -L/Domains $(LDFLAGS_SHORT)

$(EXE_DIR)/gen_keys_test.exe: $(dobj_gen_keys_test)
	@echo "linking gen_keys_test"
	$(LINK) -o $(EXE_DIR)/gen_keys_test.exe $(dobj_gen_keys_test) -L/usr/local/ssl/lib  -L$(LD_LIBRARY_PATH) -L/Domains $(LDFLAGS_SHORT)

$(EXE_DIR)/gen_keys.exe: $(dobj_gen_keys)
	@echo "linking gen_keys"
	$(LINK) -o $(EXE_DIR)/gen_keys.exe $(dobj_gen_keys) -L/usr/local/ssl/lib  -L$(LD_LIBRARY_PATH) -L/Domains $(LDFLAGS_SHORT)

$(O)/helpers.o: $(S)/helpers.cc
	@echo "compiling helpers.cc"
	$(CC) $(CFLAGS) -c -o $(O)/helpers.o $(S)/helpers.cc

$(O)/keys.pb.o: $(S)/keys.pb.cc
	@echo "compiling keys.pb.cc"
	$(CC) $(CFLAGS) -c -o $(O)/keys.pb.o $(S)/keys.pb.cc

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

$(O)/helpers_test.o: $(S)/helpers_test.cc
	@echo "compiling helpers_test.cc"
	$(CC) $(CFLAGS) -c -o $(O)/helpers_test.o $(S)/helpers_test.cc

$(O)/simple_server_test.o: $(S)/simple_server_test.cc
	@echo "compiling simple_server_test.cc"
	$(CC) $(CFLAGS) -c -o $(O)/simple_server_test.o $(S)/simple_server_test.cc

$(O)/simple_client_test.o: $(S)/simple_client_test.cc
	@echo "compiling simple_client_test.cc"
	$(CC) $(CFLAGS) -c -o $(O)/simple_client_test.o $(S)/simple_client_test.cc

$(O)/server_test.o: $(S)/server_test.cc
	@echo "compiling server_test.cc"
	$(CC) $(CFLAGS) -c -o $(O)/server_test.o $(S)/server_test.cc

$(O)/client_test.o: $(S)/client_test.cc
	@echo "compiling client_test.cc"
	$(CC) $(CFLAGS) -c -o $(O)/client_test.o $(S)/client_test.cc

$(O)/gen_keys.o: $(S)/gen_keys.cc
	@echo "compiling gen_keys.cc"
	$(CC) $(CFLAGS) -c -o $(O)/gen_keys.o $(S)/gen_keys.cc

$(O)/gen_keys_test.o: $(S)/gen_keys_test.cc
	@echo "compiling gen_keys_test.cc"
	$(CC) $(CFLAGS) -c -o $(O)/gen_keys_test.o $(S)/gen_keys_test.cc

