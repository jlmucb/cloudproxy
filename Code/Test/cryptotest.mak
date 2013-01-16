E=          ~/jlmcrypt
B=	    $(E)/cryptotestobjects
SC=         ../commonCode
SCC=	    ../jlmcrypto
SBM=	    ../jlmbignum

DEBUG_CFLAGS     := -Wall -Wno-format -g -DDEBUG
CFLAGS   := -Wall -Wno-unknown-pragmas -Wno-format -O3
LDFLAGSXML      := ${RELEASE_LDFLAGS}

CC=         g++
LINK=       g++

aesobjs=      $(B)/aestest.o $(B)/aes.o $(B)/logging.o $(B)/modesandpadding.o $(B)/hmacsha256.o \
	      $(B)/sha256.o
shaobjs=      $(B)/shatest.o $(B)/sha1.o 
sha256objs=   $(B)/sha256test.o $(B)/sha256.o 

all: $(E)/aestest.exe $(E)/sha256test.exe $(E)/shatest.exe

$(E)/aestest.exe: $(aesobjs)
	@echo "aestest"
	$(LINK) -o $(E)/aestest.exe $(aesobjs)

$(E)/shatest.exe: $(shaobjs)
	@echo "shatest"
	$(LINK) -o $(E)/shatest.exe $(shaobjs)

$(E)/sha256test.exe: $(sha256objs)
	@echo "shatest"
	$(LINK) -o $(E)/sha256test.exe $(sha256objs)

$(E)/aestest.exe: $(dobjs)
	@echo "aestest"
	$(LINK) -o $(E)/aestest.exe $(aesobjs)

$(B)/logging.o: $(SC)/logging.cpp 
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/logging.o $(SC)/logging.cpp

$(B)/aestest.o: aestest.cpp 
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/aestest.o aestest.cpp

$(B)/aes.o: $(SCC)/aes.cpp $(SCC)/aes.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -c -o $(B)/aes.o $(SCC)/aes.cpp

$(B)/sha1.o: $(SCC)/sha1.cpp $(SCC)/sha1.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -c -o $(B)/sha1.o $(SCC)/sha1.cpp

$(B)/sha256.o: $(SCC)/sha256.cpp $(SCC)/sha256.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -c -o $(B)/sha256.o $(SCC)/sha256.cpp

$(B)/shatest.o: shatest.cpp 
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/shatest.o shatest.cpp

$(B)/sha256test.o: sha256test.cpp 
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/sha256test.o sha256test.cpp

$(B)/modesandpadding.o: $(SCC)/modesandpadding.cpp 
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/modesandpadding.o $(SCC)/modesandpadding.cpp

$(B)/hmacsha256.o: $(SCC)/hmacsha256.cpp 
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/hmacsha256.o $(SCC)/hmacsha256.cpp

