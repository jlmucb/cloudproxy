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

#ifndef SRC_DIR
SRC_DIR=$(HOME)
#endif
#ifndef OBJ_DIR
OBJ_DIR=$(HOME)/cryptoobj
#endif
#ifndef EXE_DIR
EXE_DIR=$(HOME)/cryptobin
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

S= $(SRC_DIR)/src/github.com/jlmucb/cloudproxy/src/tpm2
O= $(OBJ_DIR)/tpm20
INCLUDE= -I$(S) -I$(SRC_DIR)/keys -I/usr/local/include -I$(GOOGLE_INCLUDE)

CFLAGS=$(INCLUDE) -O3 -g -Wall -std=c++11 -Wno-strict-aliasing
CFLAGS1=$(INCLUDE) -O1 -g -Wall -std=c++11

CC=g++
LINK=g++
PROTO=protoc
AR=ar
export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread

dobj_tpm2_util=					$(O)/tpm2_lib.o $(O)/tpm2_util.o
dobj_GeneratePolicyKey=				$(O)/tpm2_lib.o $(O)/tpm2.pb.o $(O)/conversions.o $(O)/GeneratePolicyKey.o
dobj_CloudProxySignEndorsementKey=		$(O)/tpm2_lib.o $(O)/tpm2.pb.o $(O)/CloudProxySignEndorsementKey.o
dobj_CloudproxySignProgramKey=			$(O)/tpm2_lib.o $(O)/tpm2.pb.o $(O)/CloudproxySignProgramKey.o
dobj_GetEndorsementKey=				$(O)/tpm2_lib.o $(O)/tpm2.pb.o $(O)/GetEndorsementKey.o
dobj_CreateAndSaveCloudProxyKeyHierarchy=	$(O)/tpm2_lib.o $(O)/tpm2.pb.o $(O)/CreateAndSaveCloudProxyKeyHierarchy.o
dobj_RestoreCloudProxyKeyHierarchy=		$(O)/tpm2_lib.o $(O)/tpm2.pb.o $(O)/RestoreCloudProxyKeyHierarchy.o
dobj_ClientCreateInterimSigningKey=		$(O)/tpm2_lib.o $(O)/tpm2.pb.o $(O)/ClientCreateInterimSigningKey.o
dobj_ServerSignInterimSigningKeyWithCredential=	$(O)/tpm2_lib.o $(O)/tpm2.pb.o $(O)/ServerSignInterimSigningKeyWithCredential.o
dobj_ClientRetrieveInterimSigningKey=		$(O)/tpm2_lib.o $(O)/tpm2.pb.o $(O)/ClientRetrieveInterimSigningKey.o

all:	$(EXE_DIR)/tpm2_util.exe \
	$(EXE_DIR)/GeneratePolicyKey.exe \
	$(EXE_DIR)/GetEndorsementKey.exe \
	$(EXE_DIR)/CloudProxySignEndorsementKey.exe \
	$(EXE_DIR)/CloudproxySignProgramKey.exe \
	$(EXE_DIR)/CreateAndSaveCloudProxyKeyHierarchy.exe \
	$(EXE_DIR)/CloudProxySignEndorsementKey.exe \
	$(EXE_DIR)/RestoreCloudProxyKeyHierarchy.exe \
	$(EXE_DIR)/ClientCreateInterimSigningKey.exe \
	$(EXE_DIR)/ServerSignInterimSigningKeyWithCredential.exe \
	$(EXE_DIR)/ClientRetrieveInterimSigningKey.exe \

clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing executable file"
	rm $(EXE_DIR)/tpm2_util.exe
	rm $(EXE_DIR)/GeneratePolicyKey.exe
	rm $(EXE_DIR)/CloudProxySignEndorsementKey.exe
	rm $(EXE_DIR)/CloudproxySignProgramKey.exe
	rm $(EXE_DIR)/GetEndorsementKey.exe
	rm $(EXE_DIR)/CreateAndSaveCloudProxyKeyHierarchy.exe
	rm $(EXE_DIR)/RestoreCloudProxyKeyHierarchy.exe
	rm $(EXE_DIR)/ClientCreateInterimSigningKey.exe
	rm $(EXE_DIR)/ServerSignInterimSigningKeyWithCredential.exe
	rm $(EXE_DIR)/ClientRetrieveInterimSigningKey.exe

$(EXE_DIR)/tpm2_util.exe: $(dobj_tpm2_util)
	@echo "linking tpm2_util"
	$(LINK) -o $(EXE_DIR)/tpm2_util.exe $(dobj_tpm2_util) $(LDFLAGS)

$(EXE_DIR)/GeneratePolicyKey.exe: $(dobj_GeneratePolicyKey)
	@echo "linking GeneratePolicyKey"
	$(LINK) -o $(EXE_DIR)/GeneratePolicyKey.exe $(dobj_GeneratePolicyKey) $(LDFLAGS) -lcrypto

$(EXE_DIR)/CloudProxySignEndorsementKey.exe: $(dobj_CloudProxySignEndorsementKey)
	@echo "linking CloudProxySignEndorsementKey"
	$(LINK) -o $(EXE_DIR)/CloudProxySignEndorsementKey.exe $(dobj_CloudProxySignEndorsementKey) $(LDFLAGS) -lcrypto

$(EXE_DIR)/CloudproxySignProgramKey.exe: $(dobj_CloudproxySignProgramKey)
	@echo "linking CloudproxySignProgramKey"
	$(LINK) -o $(EXE_DIR)/CloudproxySignProgramKey.exe $(dobj_CloudproxySignProgramKey) $(LDFLAGS) -lcrypto

$(EXE_DIR)/GetEndorsementKey.exe: $(dobj_GetEndorsementKey)
	@echo "linking GetEndorsementKey"
	$(LINK) -o $(EXE_DIR)/GetEndorsementKey.exe $(dobj_GetEndorsementKey) $(LDFLAGS) -lcrypto

$(EXE_DIR)/CreateAndSaveCloudProxyKeyHierarchy.exe: $(dobj_CreateAndSaveCloudProxyKeyHierarchy)
	@echo "linking CreateAndSaveCloudProxyKeyHierarchy"
	$(LINK) -o $(EXE_DIR)/CreateAndSaveCloudProxyKeyHierarchy.exe $(dobj_CreateAndSaveCloudProxyKeyHierarchy) $(LDFLAGS) -lcrypto

$(EXE_DIR)/RestoreCloudProxyKeyHierarchy.exe: $(dobj_RestoreCloudProxyKeyHierarchy)
	@echo "linking RestoreCloudProxyKeyHierarchy"
	$(LINK) -o $(EXE_DIR)/RestoreCloudProxyKeyHierarchy.exe $(dobj_RestoreCloudProxyKeyHierarchy) $(LDFLAGS) -lcrypto

$(EXE_DIR)/ClientCreateInterimSigningKey.exe: $(dobj_ClientCreateInterimSigningKey)
	@echo "linking ClientCreateInterimSigningKey"
	$(LINK) -o $(EXE_DIR)/ClientCreateInterimSigningKey.exe $(dobj_ClientCreateInterimSigningKey) $(LDFLAGS) -lcrypto

$(EXE_DIR)/ServerSignInterimSigningKeyWithCredential.exe: $(dobj_ServerSignInterimSigningKeyWithCredential)
	@echo "linking ServerSignInterimSigningKeyWithCredential"
	$(LINK) -o $(EXE_DIR)/ServerSignInterimSigningKeyWithCredential.exe $(dobj_ServerSignInterimSigningKeyWithCredential) $(LDFLAGS) -lcrypto

$(EXE_DIR)/ClientRetrieveInterimSigningKey.exe: $(dobj_ClientRetrieveInterimSigningKey)
	@echo "linking ClientRetrieveInterimSigningKey"
	$(LINK) -o $(EXE_DIR)/ClientRetrieveInterimSigningKey.exe $(dobj_ClientRetrieveInterimSigningKey) $(LDFLAGS) -lcrypto

$(O)/tpm2.pb.o: $(S)/tpm2.pb.cc
	@echo "compiling protobuf object"
	$(CC) $(CFLAGS) -c -o $(O)/tpm2.pb.o $(S)/tpm2.pb.cc

$(S)/tpm2.pb.cc tpm2.pb.h: $(S)/tpm2.proto
	@echo "creating protobuf files"
	$(PROTO) -I=$(S) --cpp_out=$(S) $(S)/tpm2.proto

$(O)/tpm2_lib.o: $(S)/tpm2_lib.cc
	@echo "compiling tpm2_lib.cc"
	$(CC) $(CFLAGS) -c -o $(O)/tpm2_lib.o $(S)/tpm2_lib.cc

$(O)/conversions.o: $(S)/conversions.cc
	@echo "compiling conversions.cc"
	$(CC) $(CFLAGS) -c -o $(O)/conversions.o $(S)/conversions.cc

$(O)/tpm2_util.o: $(S)/tpm2_util.cc
	@echo "compiling tpm2_util.cc"
	$(CC) $(CFLAGS) -c -o $(O)/tpm2_util.o $(S)/tpm2_util.cc

$(O)/GeneratePolicyKey.o: $(S)/GeneratePolicyKey.cc
	@echo "compiling GeneratePolicyKey.cc"
	$(CC) $(CFLAGS) -c -o $(O)/GeneratePolicyKey.o $(S)/GeneratePolicyKey.cc

$(O)/CloudProxySignEndorsementKey.o: $(S)/CloudProxySignEndorsementKey.cc
	@echo "compiling CloudProxySignEndorsementKey.cc"
	$(CC) $(CFLAGS) -c -o $(O)/CloudProxySignEndorsementKey.o $(S)/CloudProxySignEndorsementKey.cc

$(O)/CloudproxySignProgramKey.o: $(S)/CloudproxySignProgramKey.cc
	@echo "compiling CloudproxySignProgramKey.cc"
	$(CC) $(CFLAGS) -c -o $(O)/CloudproxySignProgramKey.o $(S)/CloudproxySignProgramKey.cc

$(O)/CreateAndSaveCloudProxyKeyHierarchy.o: $(S)/CreateAndSaveCloudProxyKeyHierarchy.cc
	@echo "compiling CreateAndSaveCloudProxyKeyHierarchy.cc"
	$(CC) $(CFLAGS) -c -o $(O)/CreateAndSaveCloudProxyKeyHierarchy.o $(S)/CreateAndSaveCloudProxyKeyHierarchy.cc

$(O)/RestoreCloudProxyKeyHierarchy.o: $(S)/RestoreCloudProxyKeyHierarchy.cc
	@echo "compiling RestoreCloudProxyKeyHierarchy.cc"
	$(CC) $(CFLAGS) -c -o $(O)/RestoreCloudProxyKeyHierarchy.o $(S)/RestoreCloudProxyKeyHierarchy.cc

$(O)/ClientCreateInterimSigningKey.o: $(S)/ClientCreateInterimSigningKey.cc
	@echo "compiling ClientCreateInterimSigningKey.cc"
	$(CC) $(CFLAGS) -c -o $(O)/ClientCreateInterimSigningKey.o $(S)/ClientCreateInterimSigningKey.cc

$(O)/ServerSignInterimSigningKeyWithCredential.o: $(S)/ServerSignInterimSigningKeyWithCredential.cc
	@echo "compiling ServerSignInterimSigningKeyWithCredential.cc"
	$(CC) $(CFLAGS) -c -o $(O)/ServerSignInterimSigningKeyWithCredential.o $(S)/ServerSignInterimSigningKeyWithCredential.cc

$(O)/ClientRetrieveInterimSigningKey.o: $(S)/ClientRetrieveInterimSigningKey.cc
	@echo "compiling ClientRetrieveInterimSigningKey.cc"
	$(CC) $(CFLAGS) -c -o $(O)/ClientRetrieveInterimSigningKey.o $(S)/ClientRetrieveInterimSigningKey.cc

$(O)/GetEndorsementKey.o: $(S)/GetEndorsementKey.cc
	@echo "compiling GetEndorsementKey.cc"
	$(CC) $(CFLAGS) -c -o $(O)/GetEndorsementKey.o $(S)/GetEndorsementKey.cc


