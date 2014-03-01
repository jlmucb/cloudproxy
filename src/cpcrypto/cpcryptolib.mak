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

$(B)/modesandpadding.o: $(S)/symmetric/modesandpadding.cc
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/modesandpadding.o $(S)/symmetric/modesandpadding.cc

$(B)/aes.o: $(S)/symmetric/aes.cc
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/aes.o $(S)/symmetric/aes.cc

$(B)/aesni.o: $(S)/symmetric/aesni.cc
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/aesni.o $(S)/symmetric/aesni.cc

$(B)/hmacsha256.o: $(S)/symmetric/hmacsha256.cc
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/hmacsha256.o $(S)/symmetric/hmacsha256.cc

$(B)/sha1.o: $(S)/symmetric/sha1.cc
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/sha1.o $(S)/symmetric/sha1.cc

$(B)/sha256.o: $(S)/symmetric/sha256.cc
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/sha256.o $(S)/symmetric/sha256.cc

$(B)/fastArith.o: $(S)/bignum/fastArith.cc
	$(CC) $(CFLAGS1) $(INCLUDES) -c -o $(B)/fastArith.o $(S)/bignum/fastArith.cc

$(B)/mpBasicArith.o: $(S)/bignum/mpBasicArith.cc
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/mpBasicArith.o $(S)/bignum/mpBasicArith.cc

$(B)/mpModArith.o: $(S)/bignum/mpModArith.cc
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/mpModArith.o $(S)/bignum/mpModArith.cc

$(B)/mpNumTheory.o: $(S)/bignum/mpNumTheory.cc
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/mpNumTheory.o $(S)/bignum/mpNumTheory.cc

$(B)/eccops.o: $(S)/ecc/eccops.cc
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/eccops.o $(S)/ecc/eccops.cc

$(B)/ecccrypt.o: $(S)/ecc/ecccrypt.cc
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/ecccrypt.o $(S)/ecc/ecccrypt.cc

$(B)/nist.o: $(S)/ecc/nist.cc
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/nist.o $(S)/ecc/nist.cc

clean:
	rm $(B)/*.o
	rm $(E)/cpcryptolib.a
