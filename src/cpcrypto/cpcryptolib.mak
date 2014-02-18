#############################################################################
# Copyright (c) 2013 Intel Corporation
#
#  Author:    John Manferdelli
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
ifndef CryptoSourceDirectory
S=		/home/jlm/fpDev/fileProxy/src/cpcrypto
else
S=      	$(CryptoSourceDirectory)
endif
ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

# compile cloudproxy crypto library
mainsrc=    	$(S)
B=		$(E)/cpcryptolibobjects
INCLUDES=	-I$(S) -I$(S)/bignum -I$(S)/symmetric -I$(S)/ecc \
		-I$(S)/support
DEBUG_CFLAGS     := -Wall -Wno-format -g -DDEBUG
CFLAGS   := -Wall -Wno-unknown-pragmas -Wno-format -O3 -D NOAESNI -D FAST -D TEST
CFLAGS1   := -Wall -Wno-unknown-pragmas -Wno-format  -O3 -D NOAESNI -D FAST -D TEST
LDFLAGSXML      := ${RELEASE_LDFLAGS}


CC=         g++
AS=         as
LINK=       g++
LIBMAKER=   ar

dobjs= 	$(B)/aes.o $(B)/aesni.o $(B)/hmacsha256.o $(B)/sha1.o $(B)/sha256.o \
	$(B)/fastArith.o $(B)/mpBasicArith.o $(B)/mpModArith.o $(B)/mpNumTheory.o \
	$(B)/eccops.o $(B)/ecccrypt.o $(B)/nist.o $(B)/modesandpadding.o

all: $(E)/cpcryptolib.a
 
$(E)/cpcryptolib.a: $(dobjs)
	@echo "cpcryptolib.a"
	$(LIBMAKER) -r $(E)/cpcryptolib.a $(dobjs)

$(B)/modesandpadding.o: $(S)/symmetric/modesandpadding.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/modesandpadding.o $(S)/symmetric/modesandpadding.cpp

$(B)/aes.o: $(S)/symmetric/aes.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/aes.o $(S)/symmetric/aes.cpp

$(B)/aesni.o: $(S)/symmetric/aes.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/aesni.o $(S)/symmetric/aesni.cpp

$(B)/hmacsha256.o: $(S)/symmetric/hmacsha256.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/hmacsha256.o $(S)/symmetric/hmacsha256.cpp

$(B)/sha1.o: $(S)/symmetric/sha1.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/sha1.o $(S)/symmetric/sha1.cpp

$(B)/sha256.o: $(S)/symmetric/sha256.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/sha256.o $(S)/symmetric/sha256.cpp

$(B)/fastArith.o: $(S)/bignum/fastArith.cpp
	$(CC) $(CFLAGS1) $(INCLUDES) -c -o $(B)/fastArith.o $(S)/bignum/fastArith.cpp

$(B)/mpBasicArith.o: $(S)/bignum/mpBasicArith.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/mpBasicArith.o $(S)/bignum/mpBasicArith.cpp

$(B)/mpModArith.o: $(S)/bignum/mpModArith.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/mpModArith.o $(S)/bignum/mpModArith.cpp

$(B)/mpNumTheory.o: $(S)/bignum/mpNumTheory.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/mpNumTheory.o $(S)/bignum/mpNumTheory.cpp

$(B)/eccops.o: $(S)/ecc/eccops.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/eccops.o $(S)/ecc/eccops.cpp

$(B)/ecccrypt.o: $(S)/ecc/ecccrypt.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/ecccrypt.o $(S)/ecc/ecccrypt.cpp

$(B)/nist.o: $(S)/ecc/nist.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/nist.o $(S)/ecc/nist.cpp

