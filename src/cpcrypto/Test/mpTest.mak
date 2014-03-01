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

# compile mp tests
mainsrc=        $(S)
B=              $(E)/mptestobjects
INCLUDES=       -I$(S) -I$(S)/bignum -I$(S)/symmetric -I$(S)/ecc \
                -I$(S)/support -I$(s)/Test 
DEBUG_CFLAGS     := -Wall -Wno-format -g -DDEBUG
CFLAGS   := -Wall -Wno-unknown-pragmas -Wno-format -O3 -D NOAESNI -D FAST -D TEST
CFLAGS1   := -Wall -Wno-unknown-pragmas -Wno-format  -O3 -D NOAESNI -D FAST -D TEST
LDFLAGSXML      := ${RELEASE_LDFLAGS}

CC=         g++
LINK=       g++


B=          $(E)/mptestobjects

tobjs=  $(B)/mpTest.o $(B)/logging.o $(B)/cryptoHelper.o $(B)/jlmcrypto.o \
	$(B)/tinystr.o $(B)/tinyxmlerror.o $(B)/tinyxml.o $(B)/tinyxmlparser.o \
	$(B)/jlmUtility.o $(B)/keys.o 

all: $(E)/mpTest.exe

$(E)/mpTest.exe: $(tobjs) $(E)/cpcryptolib.a
	@echo "mpTest"
	$(LINK) -o $(E)/mpTest.exe $(tobjs) $(E)/cpcryptolib.a

$(B)/mpTest.o: mpTest.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -D TEST -c -o $(B)/mpTest.o mpTest.cc

$(B)/jlmErrors.o: $(S)/support/jlmErrors.cc
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/jlmErrors.o $(S)/support/jlmErrors.cc

$(B)/cryptoHelper.o: $(S)/support/cryptoHelper.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/cryptoHelper.o $(S)/support/cryptoHelper.cc

$(B)/jlmcrypto.o: $(S)/support/jlmcrypto.cc
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/jlmcrypto.o $(S)/support/jlmcrypto.cc


$(B)/keys.o: $(S)/support/keys.cc
	$(CC) $(CFLAGS) $(INCLUDES) -D TEST -c -o $(B)/keys.o $(S)/support/keys.cc

$(B)/jlmUtility.o : $(S)/support/jlmUtility.cc
	$(CC) $(CFLAGS) $(RELEASECFLAGS) $(INCLUDES) -c -o $(B)/jlmUtility.o $(S)/support/jlmUtility.cc

$(B)/tinyxmlparser.o : $(S)/support/tinyxmlparser.cc
	$(CC) $(CFLAGS) $(RELEASECFLAGS) $(INCLUDES) -c -o $(B)/tinyxmlparser.o $(S)/support/tinyxmlparser.cc

$(B)/tinyxml.o : $(S)/support/tinyxml.cc 
	$(CC) $(CFLAGS) $(RELEASECFLAGS) $(INCLUDES) -c -o $(B)/tinyxml.o $(S)/support/tinyxml.cc

$(B)/tinyxmlerror.o : $(S)/support/tinyxmlerror.cc 
	$(CC) $(CFLAGS) $(RELEASECFLAGS) $(INCLUDES) -c -o $(B)/tinyxmlerror.o $(S)/support/tinyxmlerror.cc

$(B)/tinystr.o : $(S)/support/tinystr.cc 
	$(CC) $(CFLAGS) $(RELEASECFLAGS) $(INCLUDES) -c -o $(B)/tinystr.o $(S)/support/tinystr.cc

$(B)/logging.o: $(S)/support/logging.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/logging.o $(S)/support/logging.cc

clean:
	rm $(B)/*.o
	rm $(E)/mpTest.exe
