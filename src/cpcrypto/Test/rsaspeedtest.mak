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

$(B)/rsaspeedtest.o: rsaspeedtest.cpp 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/rsaspeedtest.o rsaspeedtest.cpp

$(B)/keys.o: $(S)/support/keys.cpp 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/keys.o $(S)/support/keys.cpp

$(B)/jlmErrors.o: $(S)/support/jlmErrors.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/jlmErrors.o $(S)/support/jlmErrors.cpp


$(B)/tinyxml.o : $(S)/support/tinyxml.cpp
	$(CC) $(CFLAGS) $(RELEASECFLAGS) $(INCLUDES) -c -o $(B)/tinyxml.o $(S)/support/tinyxml.cpp

$(B)/tinyxmlparser.o : $(S)/support/tinyxmlparser.cpp
	$(CC) $(CFLAGS) $(RELEASECFLAGS) $(INCLUDES) -c -o $(B)/tinyxmlparser.o $(S)/support/tinyxmlparser.cpp

$(B)/tinyxmlerror.o : $(S)/support/tinyxmlerror.cpp
	$(CC) $(CFLAGS) $(RELEASECFLAGS) $(INCLUDES) -c -o $(B)/tinyxmlerror.o $(S)/support/tinyxmlerror.cpp

$(B)/tinystr.o : $(S)/support/tinystr.cpp 
	$(CC) $(CFLAGS) $(RELEASECFLAGS) $(INCLUDES) -c -o $(B)/tinystr.o $(S)/support/tinystr.cpp

$(B)/jlmcrypto.o: $(S)/support/jlmcrypto.cpp
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/jlmcrypto.o $(S)/support/jlmcrypto.cpp

$(B)/logging.o: $(S)/support/logging.cpp 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/logging.o $(S)/support/logging.cpp

