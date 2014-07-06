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
                -I$(S)/ecc/pointcount -I$(S)/support -I$(S)/Test 
DEBUG_CFLAGS     := -Wall -Wno-format -g -DDEBUG
CFLAGS   := -Wall -Wno-unknown-pragmas -Wno-format -O3 -D NOAESNI -D FAST -D TEST
CFLAGS1   := -Wall -Wno-unknown-pragmas -Wno-format  -O3 -D NOAESNI -D FAST -D TEST
LDFLAGSXML      := ${RELEASE_LDFLAGS}

CC=         g++
LINK=       g++

aesobjs=      $(B)/aestest.o $(B)/logging.o 
shaobjs=      $(B)/shatest.o $(B)/logging.o 
sha256objs=   $(B)/sha256test.o $(B)/logging.o 
polyobjs=     $(B)/polytest.o $(B)/polyarith.o $(B)/logging.o $(B)/bsgs.o \
		$(B)/divpolys.o $(B)/schoof.o

all: $(E)/aestest.exe $(E)/sha256test.exe $(E)/shatest.exe $(E)/polytest.exe

$(E)/aestest.exe: $(aesobjs) $(E)/cpcryptolib.a
	@echo "aestest"
	$(LINK) -o $(E)/aestest.exe $(aesobjs) $(E)/cpcryptolib.a

$(E)/shatest.exe: $(shaobjs) $(E)/cpcryptolib.a
	@echo "shatest"
	$(LINK) -o $(E)/shatest.exe $(shaobjs) $(E)/cpcryptolib.a

$(E)/sha256test.exe: $(sha256objs) $(E)/cpcryptolib.a
	@echo "shatest"
	$(LINK) -o $(E)/sha256test.exe $(sha256objs) $(E)/cpcryptolib.a

$(E)/polytest.exe: $(polyobjs) $(E)/cpcryptolib.a
	@echo "polytest"
	$(LINK) -o $(E)/polytest.exe $(polyobjs) $(E)/cpcryptolib.a

$(B)/logging.o: $(S)/support/logging.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/logging.o $(S)/support/logging.cc

$(B)/aestest.o: aestest.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/aestest.o aestest.cc

$(B)/shatest.o: shatest.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/shatest.o shatest.cc

$(B)/sha256test.o: sha256test.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/sha256test.o sha256test.cc

$(B)/polytest.o: polytest.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/polytest.o polytest.cc

$(B)/polyarith.o: $(S)/ecc/pointcount/polyarith.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/polyarith.o $(S)/ecc/pointcount/polyarith.cc

$(B)/bsgs.o: $(S)/ecc/pointcount/bsgs.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/bsgs.o $(S)/ecc/pointcount/bsgs.cc

$(B)/divpolys.o: $(S)/ecc/pointcount/divpolys.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/divpolys.o $(S)/ecc/pointcount/divpolys.cc

$(B)/schoof.o: $(S)/ecc/pointcount/schoof.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/schoof.o $(S)/ecc/pointcount/schoof.cc

clean:
	rm $(B)/*.o
	rm $(E)/aestest.exe
	rm $(E)/shatest.exe
	rm $(E)/sha256test.exe
	rm $(E)/polytest.exe
