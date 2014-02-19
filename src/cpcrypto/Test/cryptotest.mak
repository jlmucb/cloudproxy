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

# compile crypto test
mainsrc=        $(S)
B=              $(E)/cryptotestobjects
INCLUDES=       -I$(S) -I$(S)/bignum -I$(S)/symmetric -I$(S)/ecc \
                -I$(S)/support -I$(s)/Test 
DEBUG_CFLAGS     := -Wall -Wno-format -g -DDEBUG
CFLAGS   := -Wall -Wno-unknown-pragmas -Wno-format -O3 -D NOAESNI -D FAST -D TEST
CFLAGS1   := -Wall -Wno-unknown-pragmas -Wno-format  -O3 -D NOAESNI -D FAST -D TEST
LDFLAGSXML      := ${RELEASE_LDFLAGS}

CC=         g++
LINK=       g++

aesobjs=      $(B)/aestest.o $(B)/logging.o 
shaobjs=      $(B)/shatest.o $(B)/logging.o 
sha256objs=   $(B)/sha256test.o $(B)/logging.o 

all: $(E)/aestest.exe $(E)/sha256test.exe $(E)/shatest.exe

$(E)/aestest.exe: $(aesobjs) $(E)/cpcryptolib.a
	@echo "aestest"
	$(LINK) -o $(E)/aestest.exe $(aesobjs) $(E)/cpcryptolib.a

$(E)/shatest.exe: $(shaobjs) $(E)/cpcryptolib.a
	@echo "shatest"
	$(LINK) -o $(E)/shatest.exe $(shaobjs) $(E)/cpcryptolib.a

$(E)/sha256test.exe: $(sha256objs) $(E)/cpcryptolib.a
	@echo "shatest"
	$(LINK) -o $(E)/sha256test.exe $(sha256objs) $(E)/cpcryptolib.a

$(B)/logging.o: $(S)/support/logging.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/logging.o $(S)/support/logging.cc

$(B)/aestest.o: aestest.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/aestest.o aestest.cc

$(B)/shatest.o: shatest.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/shatest.o shatest.cc

$(B)/sha256test.o: sha256test.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/sha256test.o sha256test.cc


