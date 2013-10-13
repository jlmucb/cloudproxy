E=          ~/jlmcrypt
B=          ~/jlmcrypt/kvmncpobjects
S=          ../kvmncp
SC=         ../../commonCode

DEBUG_CFLAGS     := -Wall -Werror -Wno-format -g -DDEBUG
RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3
O1RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O1
CFLAGS=     -D LINUX -D TEST -D TIXML_USE_STL $(RELEASE_CFLAGS)
LDFLAGS          := $(RELEASE_LDFLAGS)

CC=         g++
LINK=       g++

dobjs=      $(B)/kvmncp.o $(B)/logging.o 

all: $(E)/kvmncp.exe

$(E)/kvmncp.exe: $(dobjs)
	@echo "kvmncp"
	$(LINK) -o $(E)/kvmncp.exe $(dobjs) $(LDFLAGS) -lpthread

$(B)/logging.o: $(SC)/logging.cpp $(SC)/logging.h
	$(CC) $(CFLAGS) -I$(SC) -I$(S) -c -o $(B)/logging.o $(SC)/logging.cpp

$(B)/kvmncp.o: $(S)/kvmncp.cpp
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -c -o $(B)/kvmncp.o $(S)/kvmncp.cpp

