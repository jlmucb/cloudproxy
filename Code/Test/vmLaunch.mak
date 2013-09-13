E=          ~/jlmcrypt
B=          ~/jlmcrypt/vmLaunchobjects
S=          ../Test
SC=         ../commonCode
SCD=        ../jlmcrypto
TAO=	    ../tao

DEBUG_CFLAGS     := -Wall -Werror -Wno-format -g -DDEBUG
RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3
O1RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O1
CFLAGS=     -D LINUX -D TEST -D TIXML_USE_STL $(RELEASE_CFLAGS)
LDFLAGS          := $(RELEASE_LDFLAGS)

CC=         g++
LINK=       g++

dobjs=      $(B)/tinyxml.o $(B)/tinyxmlparser.o $(B)/tinystr.o $(B)/tinyxmlerror.o \
	    $(B)/sha256.o $(B)/vmLaunch.o $(B)/logging.o $(B)/kvmHostsupport.o $(B)/fileHash.o

all: $(E)/vmLaunch.exe

$(E)/vmLaunch.exe: $(dobjs)
	@echo "vmLaunch"
	$(LINK) -o $(E)/vmLaunch.exe $(dobjs) $(LDFLAGS) -lpthread -lvirt

$(B)/logging.o: $(SC)/logging.cpp $(SC)/logging.h
	$(CC) $(CFLAGS) -I$(SC) -c -o $(B)/logging.o $(SC)/logging.cpp

$(B)/kvmHostsupport.o: $(TAO)/kvmHostsupport.cpp $(TAO)/kvmHostsupport.h
	$(CC) $(CFLAGS) -I$(SC) -D KVMTCSERVICE -I$(TAO) -c -o $(B)/kvmHostsupport.o $(TAO)/kvmHostsupport.cpp

$(B)/tinyxml.o : $(SC)/tinyxml.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxml.o $(SC)/tinyxml.cpp

$(B)/tinyxmlparser.o : $(SC)/tinyxmlparser.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxmlparser.o $(SC)/tinyxmlparser.cpp

$(B)/tinyxmlerror.o : $(SC)/tinyxmlerror.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxmlerror.o $(SC)/tinyxmlerror.cpp

$(B)/tinystr.o : $(SC)/tinystr.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinystr.o $(SC)/tinystr.cpp

$(B)/sha256.o: $(SCD)/sha256.cpp
	$(CC) $(CFLAGS) -I$(TAO) -I$(SC) -I$(SCD) -c -o $(B)/sha256.o $(SCD)/sha256.cpp

$(B)/fileHash.o: $(SCD)/fileHash.cpp
	$(CC) $(CFLAGS) -I$(TAO) -I$(SC) -I$(SCD) -c -o $(B)/fileHash.o $(SCD)/fileHash.cpp

$(B)/vmLaunch.o: $(S)/vmLaunch.cpp
	$(CC) $(CFLAGS) -I$(TAO) -I$(SC) -I$(SCD) -c -o $(B)/vmLaunch.o $(S)/vmLaunch.cpp

