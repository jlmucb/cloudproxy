E=          ~/jlmcrypt
B=          $(E)/vTCIDirectobjects
SC=         ../commonCode
BN=         ../jlmbignum
CR=         ../jlmcrypto
S=          .

DEBUG_CFLAGS     := -Wall -Wno-format -g -DDEBUG
RELEASE_CFLAGS   := -Wall -Wno-unknown-pragmas -Wno-format -O3
LDFLAGSXML      := ${RELEASE_LDFLAGS}

CC=         g++
LINK=       g++

dobjs=      $(B)/hmactest.o $(B)/sha1.o $(B)/hmacsha1.o  $(B)/logging.o

all: $(E)/hmactest.exe

$(E)/hmactest.exe: $(dobjs)
	@echo "hmactest"
	$(LINK) -o $(E)/hmactest.exe $(dobjs) -lpthread

$(B)/sha1.o: $(CR)/sha1.cpp $(CR)/sha1.h
	$(CC) $(CFLAGS) -I$(CR) -I$(SC) -I/usr/include/tss -c -o $(B)/sha1.o $(CR)/sha1.cpp

$(B)/hmactest.o: $(S)/hmactest.cpp 
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(CR) -I$(TPD) -I$(TPU) -I$(BN) -c -o $(B)/hmactest.o $(S)/hmactest.cpp

$(B)/hmacsha1.o: $(S)/hmacsha1.cpp $(S)/hmacsha1.h
	$(CC) $(CFLAGS) -I$(SC) -I$(CR) -c -o $(B)/hmacsha1.o $(S)/hmacsha1.cpp

$(B)/logging.o: $(SC)/logging.cpp $(SC)/logging.h
	$(CC) $(CFLAGS) -I$(SC) -c -o $(B)/logging.o $(SC)/logging.cpp

