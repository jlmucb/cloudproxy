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

$(B)/mpTest.o: mpTest.cpp 
	$(CC) $(CFLAGS) $(INCLUDES) -D TEST -c -o $(B)/mpTest.o mpTest.cpp

$(B)/jlmErrors.o: $(S)/support/jlmErrors.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/jlmErrors.o $(S)/support/jlmErrors.cpp

$(B)/cryptoHelper.o: $(S)/support/cryptoHelper.cpp 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/cryptoHelper.o $(S)/support/cryptoHelper.cpp

$(B)/jlmcrypto.o: $(S)/support/jlmcrypto.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/jlmcrypto.o $(S)/support/jlmcrypto.cpp


$(B)/keys.o: $(S)/support/keys.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -D TEST -c -o $(B)/keys.o $(S)/support/keys.cpp

$(B)/jlmUtility.o : $(S)/support/jlmUtility.cpp
	$(CC) $(CFLAGS) $(RELEASECFLAGS) $(INCLUDES) -c -o $(B)/jlmUtility.o $(S)/support/jlmUtility.cpp

$(B)/tinyxmlparser.o : $(S)/support/tinyxmlparser.cpp
	$(CC) $(CFLAGS) $(RELEASECFLAGS) $(INCLUDES) -c -o $(B)/tinyxmlparser.o $(S)/support/tinyxmlparser.cpp

$(B)/tinyxml.o : $(S)/support/tinyxml.cpp 
	$(CC) $(CFLAGS) $(RELEASECFLAGS) $(INCLUDES) -c -o $(B)/tinyxml.o $(S)/support/tinyxml.cpp

$(B)/tinyxmlerror.o : $(S)/support/tinyxmlerror.cpp 
	$(CC) $(CFLAGS) $(RELEASECFLAGS) $(INCLUDES) -c -o $(B)/tinyxmlerror.o $(S)/support/tinyxmlerror.cpp

$(B)/tinystr.o : $(S)/support/tinystr.cpp 
	$(CC) $(CFLAGS) $(RELEASECFLAGS) $(INCLUDES) -c -o $(B)/tinystr.o $(S)/support/tinystr.cpp

$(B)/logging.o: $(S)/support/logging.cpp 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/logging.o $(S)/support/logging.cpp
