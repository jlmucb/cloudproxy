CC=g++
DEBUG_CFLAGS=-O0 -g
RELEASE_CFLAGS=-O3
CFLAGS=-Wall -Werror -std=c++0x $(RELEASE_CFLAGS)

LD=$(CC)
LDFLAGS=-lcrypto -lssl
RM=rm
EXE=dummyClient dummyServer

SRCS=server.cpp client.cpp
OBJS=${SRCS:.cpp=.o}

all: dummyServer dummyClient

.cpp.o:
	$(CC) $(CFLAGS) -c $<
  
dummyServer: server.o
	$(LD) -o $@ $< $(LDFLAGS)
  
dummyClient: client.o
	$(LD) -o $@ $< $(LDFLAGS)

clean:
	-$(RM) -f $(EXE) $(OBJS)
