ifndef CPProgramDirectory
E=              /home/jlm/jlmcrypt
else
E=              $(CPProgramDirectory)
endif
ifndef CryptoSourceDirectory
S=              /home/jlm/fpDev/fileProxy/src/cpcrypto
else
S=              $(CryptoSourceDirectory)
endif
ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

# compile aesspeedtest
mainsrc=        $(S)
B=              $(E)/aesspeedtestobjects
INCLUDES=       -I$(S) -I$(S)/bignum -I$(S)/symmetric -I$(S)/ecc \
                -I$(S)/support -I$(s)/Test 
DEBUG_CFLAGS     := -Wall -Wno-format -g -DDEBUG
CFLAGS   := -Wall -Wno-unknown-pragmas -Wno-format -O3 -D NOAESNI -D FAST -D TEST
CFLAGS1   := -Wall -Wno-unknown-pragmas -Wno-format  -O3 -D NOAESNI -D FAST -D TEST
LDFLAGSXML      := ${RELEASE_LDFLAGS}

CC=         g++
LINK=       g++

dobjs=  $(B)/aesspeedtest.o $(B)/logging.o $(B)/jlmcrypto.o

all: $(E)/aesspeedtest.exe

$(E)/aesspeedtest.exe: $(dobjs) $(E)/cpcryptolib.a
	@echo "aesspeedtest"
	$(LINK) -o $(E)/aesspeedtest.exe $(dobjs) $(E)/cpcryptolib.a

$(B)/aesspeedtest.o: aesspeedtest.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/aesspeedtest.o aesspeedtest.cpp

$(B)/jlmcrypto.o: $(S)/support/jlmcrypto.cpp $(S)/support/jlmcrypto.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/jlmcrypto.o $(S)/support/jlmcrypto.cpp

$(B)/logging.o: $(S)/support/logging.cpp $(S)/support/logging.h
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/logging.o $(S)/support/logging.cpp
