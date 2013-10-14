ifndef CPProgramDirectory
E=/home/jlm/jlmcrypt
else
E=      $(CPProgramDirectory)
endif

B=          $(E)/vTCIobjects
SC=         ../commonCode
BN=         ../jlmbignum
CR=         ../jlmcrypto
TPU=	    ../TPMUser
S=          .
# CFLAGS=     -D UNIXRANDBITS -D TPMTEST

DEBUG_CFLAGS     := -Wall -Wno-format -g -DDEBUG
RELEASE_CFLAGS   := -Wall -Wno-unknown-pragmas -Wno-format -O3
CFLAGS=     -D UNIXRANDBITS -D TPMTEST -D QUOTE2_DEFINED -D PCR18
LDFLAGSXML      := ${RELEASE_LDFLAGS}

CC=         g++
LINK=       g++

dobjs=      $(B)/vTCI.o $(B)/sha1.o $(B)/fastArith.o $(B)/mpBasicArith.o $(B)/mpModArith.o \
	    $(B)/mpNumTheory.o $(B)/mpRand.o $(B)/jlmUtility.o $(B)/tinyxml.o \
	    $(B)/tinyxmlparser.o $(B)/tinyxmlerror.o $(B)/tinystr.o \
	    $(B)/hashprep.o $(B)/sha256.o $(B)/logging.o

all: $(E)/vTCI.exe

$(E)/vTCI.exe: $(dobjs)
	@echo "vTCI"
	$(LINK) -o $(E)/vTCI.exe $(dobjs) -ltspi

$(B)/sha1.o: $(CR)/sha1.cpp $(CR)/sha1.h
	$(CC) $(CFLAGS) -I$(CR) -I$(SC) -I/usr/include/tss -c -o $(B)/sha1.o $(CR)/sha1.cpp

$(B)/vTCI.o: $(S)/vTCI.cpp $(S)/vTCI.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(CR) -I$(TPU) -I$(BN) -I/usr/include/tss -c -o $(B)/vTCI.o $(S)/vTCI.cpp

$(B)/fastArith.o: $(BN)/fastArith.cpp
	$(CC) $(CFLAGS) -I$(SC) -I$(BN) -c -o $(B)/fastArith.o $(BN)/fastArith.cpp

$(B)/mpBasicArith.o: $(BN)/mpBasicArith.cpp
	$(CC) $(CFLAGS) -I$(SC) -I$(BN) -c -o $(B)/mpBasicArith.o $(BN)/mpBasicArith.cpp

$(B)/mpModArith.o: $(BN)/mpModArith.cpp
	$(CC) $(CFLAGS) -I$(SC) -I$(BN) -c -o $(B)/mpModArith.o $(BN)/mpModArith.cpp

$(B)/mpNumTheory.o: $(BN)/mpNumTheory.cpp
	$(CC) $(CFLAGS) -I$(SC) -I$(CR) -I$(BN) -c -o $(B)/mpNumTheory.o $(BN)/mpNumTheory.cpp

$(B)/mpRand.o: $(BN)/mpRand.cpp
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BN) -c -o $(B)/mpRand.o $(BN)/mpRand.cpp

$(B)/jlmUtility.o: $(SC)/jlmUtility.cpp
	$(CC) $(CFLAGS) -I$(SC) -I$(CR) -I$(BN) -c -o $(B)/jlmUtility.o $(SC)/jlmUtility.cpp

$(B)/tinyxml.o : $(SC)/tinyxml.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) -I$(SC) -c -o $(B)/tinyxml.o $(SC)/tinyxml.cpp

$(B)/tinyxmlparser.o : $(SC)/tinyxmlparser.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) -I$(SC) -c -o $(B)/tinyxmlparser.o $(SC)/tinyxmlparser.cpp

$(B)/tinyxmlerror.o : $(SC)/tinyxmlerror.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) -I$(SC) -c -o $(B)/tinyxmlerror.o $(SC)/tinyxmlerror.cpp

$(B)/tinystr.o : $(SC)/tinystr.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) -I$(SC) -c -o $(B)/tinystr.o $(SC)/tinystr.cpp

$(B)/sha256.o: $(CR)/sha256.cpp $(CR)/sha256.h
	$(CC) $(CFLAGS) -I$(SC) -I$(CR) -c -o $(B)/sha256.o $(CR)/sha256.cpp

$(B)/hashprep.o: $(TPU)/hashprep.cpp $(TPU)/hashprep.h
	$(CC) $(CFLAGS) -D TEST -I$(SC) -I$(TPU) -I$(CR) -c -o $(B)/hashprep.o $(TPU)/hashprep.cpp

$(B)/logging.o: $(SC)/logging.cpp $(SC)/logging.h
	$(CC) $(CFLAGS) -I$(SC) -c -o $(B)/logging.o $(SC)/logging.cpp

