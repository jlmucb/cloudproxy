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

# compile rsa speed test
mainsrc=        $(S)
B=              $(E)/rsaspeedtestobjects
INCLUDES=       -I$(S) -I$(S)/bignum -I$(S)/symmetric -I$(S)/ecc \
                -I$(S)/support -I$(s)/Test 
DEBUG_CFLAGS     := -Wall -Wno-format -g -DDEBUG
CFLAGS   := -Wall -Wno-unknown-pragmas -Wno-format -O3 -D NOAESNI -D FAST -D TEST
CFLAGS1   := -Wall -Wno-unknown-pragmas -Wno-format  -O3 -D NOAESNI -D FAST -D TEST
LDFLAGSXML      := ${RELEASE_LDFLAGS}

CC=         g++
LINK=       g++


dobjs=  $(B)/rsaspeedtest.o $(B)/keys.o $(B)/jlmcrypto.o \
	$(B)/tinystr.o $(B)/tinyxmlerror.o $(B)/tinyxml.o \
	$(B)/tinyxmlparser.o $(B)/logging.o 

all: $(E)/rsaspeedtest.exe

$(E)/rsaspeedtest.exe: $(dobjs) $(E)/cpcryptolib.a
	@echo "rsaspeedtest"
	$(LINK) -o $(E)/rsaspeedtest.exe $(dobjs) $(E)/cpcryptolib.a

$(B)/rsaspeedtest.o: rsaspeedtest.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/rsaspeedtest.o rsaspeedtest.cc

$(B)/keys.o: $(S)/support/keys.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/keys.o $(S)/support/keys.cc

$(B)/jlmErrors.o: $(S)/support/jlmErrors.cc
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/jlmErrors.o $(S)/support/jlmErrors.cc


$(B)/tinyxml.o : $(S)/support/tinyxml.cc
	$(CC) $(CFLAGS) $(RELEASECFLAGS) $(INCLUDES) -c -o $(B)/tinyxml.o $(S)/support/tinyxml.cc

$(B)/tinyxmlparser.o : $(S)/support/tinyxmlparser.cc
	$(CC) $(CFLAGS) $(RELEASECFLAGS) $(INCLUDES) -c -o $(B)/tinyxmlparser.o $(S)/support/tinyxmlparser.cc

$(B)/tinyxmlerror.o : $(S)/support/tinyxmlerror.cc
	$(CC) $(CFLAGS) $(RELEASECFLAGS) $(INCLUDES) -c -o $(B)/tinyxmlerror.o $(S)/support/tinyxmlerror.cc

$(B)/tinystr.o : $(S)/support/tinystr.cc 
	$(CC) $(CFLAGS) $(RELEASECFLAGS) $(INCLUDES) -c -o $(B)/tinystr.o $(S)/support/tinystr.cc

$(B)/jlmcrypto.o: $(S)/support/jlmcrypto.cc
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/jlmcrypto.o $(S)/support/jlmcrypto.cc

$(B)/logging.o: $(S)/support/logging.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/logging.o $(S)/support/logging.cc

clean:
	rm $(B)/*.o
	rm $(E)/rsaspeedtest.exe
