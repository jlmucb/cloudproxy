E=          ~/jlmcrypt
B=          $(E)/mptestobjects
SC=         ../commonCode
SCC=	    ../jlmcrypto
SBM=	    ../jlmbignum

DEBUG_CFLAGS     := -Wall -Wno-format -g -DDEBUG
CFLAGS   := -Wall -Wno-unknown-pragmas -Wno-format -O3 -D NOAESNI -D FAST
CFLAGS1   := -Wall -Wno-unknown-pragmas -Wno-format  -O1 -D NOAESNI -D FAST
LDFLAGSXML      := ${RELEASE_LDFLAGS}

CC=         g++
LINK=       g++

tobjs=  $(B)/mpTest.o $(B)/logging.o \
	$(B)/mpBasicArith.o  $(B)/mpModArith.o $(B)/mpNumTheory.o \
	$(B)/fastArith.o

all: $(E)/mpTest.exe

$(E)/mpTest.exe: $(tobjs)
	@echo "mpTest"
	$(LINK) -o $(E)/mpTest.exe $(tobjs)

$(B)/mpTest.o: mpTest.cpp 
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/mpTest.o mpTest.cpp

$(B)/jlmErrors.o: $(SC)/jlmErrors.cpp $(SC)/jlmErrors.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -c -o $(B)/jlmErrors.o $(SC)/jlmErrors.cpp

$(B)/modesandpadding.o: $(SCC)/modesandpadding.cpp $(SCC)/modesandpadding.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/modesandpadding.o $(SCC)/modesandpadding.cpp

$(B)/jlmcrypto.o: $(SCC)/jlmcrypto.cpp $(SCC)/jlmcrypto.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/jlmcrypto.o $(SCC)/jlmcrypto.cpp

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
