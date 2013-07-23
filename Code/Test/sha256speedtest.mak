E=          ~/jlmcrypt
B=          ~/jlmcrypt/sha256speedtestobjects
SC=	    ../commonCode
SCC=	    ../jlmcrypto

DEBUG_CFLAGS     := -Wall -Wno-format -g -DDEBUG
CFLAGS   := -Wall -Wno-unknown-pragmas -Wno-format -O3
LDFLAGSXML      := ${RELEASE_LDFLAGS}

CC=         g++
LINK=       g++

dobjs=      $(B)/sha256speedtest.o $(B)/sha256.o

all: $(E)/sha256speedtest.exe

$(E)/sha256speedtest.exe: $(dobjs)
	@echo "sha256speedtest"
	$(LINK) -o $(E)/sha256speedtest.exe $(dobjs)

$(B)/sha256speedtest.o: sha256speedtest.cpp 
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -c -o $(B)/sha256speedtest.o sha256speedtest.cpp

$(B)/sha256.o: $(SCC)/sha256.cpp $(SCC)/sha256.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -c -o $(B)/sha256.o $(SCC)/sha256.cpp

