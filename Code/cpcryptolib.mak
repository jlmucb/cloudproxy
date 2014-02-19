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
S=		/home/jlm/fpDev/fileProxy/Code
else
S=      	$(CryptoSourceDirectory)
endif
ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

# compile cloudproxy crypto library
mainsrc=    	$(S)/
B=		$(E)/cpcryptolibobjects
INCLUDES=	-I$(S)/jlmbignum -I$(S)/jlmcrypto -I$(S)/ecc \
		-I$(S)/commonCode
DEBUG_CFLAGS     := -Wall -Wno-format -g -DDEBUG
CFLAGS   := -Wall -Wno-unknown-pragmas -Wno-format -O3 -D NOAESNI -D FAST -D TEST
CFLAGS1   := -Wall -Wno-unknown-pragmas -Wno-format  -O3 -D NOAESNI -D FAST -D TEST
LDFLAGSXML      := ${RELEASE_LDFLAGS}


CC=         gcc
AS=         as
LINK=       gcc
LIBMAKER=   ar

dobjs= 	$(B)/aes.o $(B)/aesni.o $(B)/hmacsha256.o $(B)/sha1.o $(B)/sha256.o \
	$(B)/fastArith.o $(B)/mpBasicArith.o $(B)/mpModArith.o $(B)/mpNumTheory.o \
	$(B)/eccops.o $(B)/ecccrypt.o $(B)/nist.o

all: $(E)/cpcryptolib.a
 
$(E)/cpcryptolib.a: $(dobjs)
	@echo "cpcryptolib.a"
	$(LIBMAKER) -r $(E)/cpcryptolib.a $(dobjs)

$(B)/modesandpadding.o: $(S)/jlmcrypto/modesandpadding.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/modesandpadding.o $(S)/jlmcrypto/modesandpadding.cpp

$(B)/aes.o: $(S)/jlmcrypto/aes.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/aes.o $(S)/jlmcrypto/aes.cpp

$(B)/aesni.o: $(S)/jlmcrypto/aes.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/aesni.o $(S)/jlmcrypto/aesni.cpp

$(B)/hmacsha256.o: $(S)/jlmcrypto/hmacsha256.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/hmacsha256.o $(S)/jlmcrypto/hmacsha256.cpp

$(B)/sha1.o: $(S)/jlmcrypto/sha1.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/sha1.o $(S)/jlmcrypto/sha1.cpp

$(B)/sha256.o: $(S)/jlmcrypto/sha256.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/sha256.o $(S)/jlmcrypto/sha256.cpp

$(B)/fastArith.o: $(S)/jlmbignum/fastArith.cpp
	$(CC) $(CFLAGS1) $(INCLUDES) -c -o $(B)/fastArith.o $(S)/jlmbignum/fastArith.cpp

$(B)/mpBasicArith.o: $(S)/jlmbignum/mpBasicArith.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/mpBasicArith.o $(S)/jlmbignum/mpBasicArith.cpp

$(B)/mpModArith.o: $(S)/jlmbignum/mpModArith.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/mpModArith.o $(S)/jlmbignum/mpModArith.cpp

$(B)/mpNumTheory.o: $(S)/jlmbignum/mpNumTheory.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/mpNumTheory.o $(S)/jlmbignum/mpNumTheory.cpp

$(B)/eccops.o: $(S)/ecc/eccops.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/eccops.o $(S)/ecc/eccops.cpp

$(B)/ecccrypt.o: $(S)/ecc/ecccrypt.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/ecccrypt.o $(S)/ecc/ecccrypt.cpp

$(B)/nist.o: $(S)/ecc/nist.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/nist.o $(S)/ecc/nist.cpp

