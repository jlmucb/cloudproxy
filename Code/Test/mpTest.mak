E=          ~/jlmcrypt
B=          $(E)/mptestobjects
SC=         ../commonCode
SCC=	    ../jlmcrypto
SCD=	    ../newjlmcrypto
SBM=	    ../jlmbignum

DEBUG_CFLAGS     := -Wall -Wno-format -g -DDEBUG
#CFLAGS   := -Wall -Wno-unknown-pragmas -Wno-format -O3 -D NOAESNI -D FAST -D DEBUGUDIV
#CFLAGS1   := -Wall -Wno-unknown-pragmas -Wno-format  -O1 -D NOAESNI -D FAST -D DEBUGUDIV
CFLAGS   := -Wall -Wno-unknown-pragmas -Wno-format -O3 -D NOAESNI -D FAST -D TEST
CFLAGS1   := -Wall -Wno-unknown-pragmas -Wno-format  -O1 -D NOAESNI -D FAST -D TEST
LDFLAGSXML      := ${RELEASE_LDFLAGS}

CC=         g++
LINK=       g++

tobjs=  $(B)/mpTest.o $(B)/logging.o $(B)/mpBasicArith.o  $(B)/mpModArith.o \
	$(B)/mpNumTheory.o $(B)/modesandpadding.o $(B)/cryptoHelper.o \
	$(B)/aes.o $(B)/sha256.o $(B)/jlmcrypto.o $(B)/hmacsha256.o \
	$(B)/tinystr.o $(B)/tinyxmlerror.o $(B)/tinyxml.o $(B)/tinyxmlparser.o \
	$(B)/jlmUtility.o $(B)/keys.o $(B)/fastArith.o

all: $(E)/mpTest.exe

$(E)/mpTest.exe: $(tobjs)
	@echo "mpTest"
	$(LINK) -o $(E)/mpTest.exe $(tobjs)

$(B)/mpTest.o: mpTest.cpp 
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(SCC) -I$(SBM) -c -o $(B)/mpTest.o mpTest.cpp

$(B)/jlmErrors.o: $(SC)/jlmErrors.cpp $(SC)/jlmErrors.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -c -o $(B)/jlmErrors.o $(SC)/jlmErrors.cpp

$(B)/modesandpadding.o: $(SCD)/modesandpadding.cpp $(SCD)/modesandpadding.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(SCC) -I$(SBM) -c -o $(B)/modesandpadding.o $(SCD)/modesandpadding.cpp

$(B)/cryptoHelper.o: $(SCD)/cryptoHelper.cpp $(SCD)/cryptoHelper.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(SCC) -I$(SBM) -c -o $(B)/cryptoHelper.o $(SCD)/cryptoHelper.cpp

$(B)/jlmcrypto.o: $(SCC)/jlmcrypto.cpp $(SCC)/jlmcrypto.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(SCC) -I$(SBM) -c -o $(B)/jlmcrypto.o $(SCC)/jlmcrypto.cpp

$(B)/aes.o: $(SCC)/aes.cpp $(SCC)/aes.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/aes.o $(SCC)/aes.cpp

$(B)/hmacsha256.o: $(SCC)/hmacsha256.cpp $(SCC)/hmacsha256.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/hmacsha256.o $(SCC)/hmacsha256.cpp

$(B)/sha256.o: $(SCC)/sha256.cpp $(SCC)/sha256.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/sha256.o $(SCC)/sha256.cpp

$(B)/keys.o: $(SCC)/keys.cpp $(SCC)/keys.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(SCC) -I$(SBM) -c -o $(B)/keys.o $(SCC)/keys.cpp

$(B)/jlmUtility.o : $(SC)/jlmUtility.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -I$(SCD) -I$(SCC) -I$(SBM) -c -o $(B)/jlmUtility.o $(SC)/jlmUtility.cpp

$(B)/tinyxmlparser.o : $(SC)/tinyxmlparser.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxmlparser.o $(SC)/tinyxmlparser.cpp

$(B)/tinyxml.o : $(SC)/tinyxml.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxml.o $(SC)/tinyxml.cpp

$(B)/tinyxmlerror.o : $(SC)/tinyxmlerror.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxmlerror.o $(SC)/tinyxmlerror.cpp

$(B)/tinystr.o : $(SC)/tinystr.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinystr.o $(SC)/tinystr.cpp

$(B)/fastArith.o: $(SBM)/fastArith.cpp
	$(CC) $(CFLAGS1) -I$(SC) -I$(SBM) -c -o $(B)/fastArith.o $(SBM)/fastArith.cpp
	$(CC) $(CFLAGS1) -I$(SC) -I$(SBM) -S -o $(B)/fastArith.s $(SBM)/fastArith.cpp

$(B)/mpBasicArith.o: $(SBM)/mpBasicArith.cpp
	$(CC) $(CFLAGS) -I$(SC) -I$(SBM) -c -o $(B)/mpBasicArith.o $(SBM)/mpBasicArith.cpp

$(B)/mpModArith.o: $(SBM)/mpModArith.cpp
	$(CC) $(CFLAGS) -I$(SC) -I$(SBM) -c -o $(B)/mpModArith.o $(SBM)/mpModArith.cpp

$(B)/mpNumTheory.o: $(SBM)/mpNumTheory.cpp
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/mpNumTheory.o $(SBM)/mpNumTheory.cpp

$(B)/logging.o: $(SC)/logging.cpp 
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/logging.o $(SC)/logging.cpp
