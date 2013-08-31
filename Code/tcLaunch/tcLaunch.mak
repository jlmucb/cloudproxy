E=          ~/jlmcrypt
B=          ~/jlmcrypt/tcLaunchobjects
S=          ../tcLaunch
SC=         ../commonCode
BN=         ../jlmbignum
SCD=        ../jlmcrypto
TAO=	    ../tao
TRS=	    ../tcService
CH=	    ../channels
PROTO=	    ../protocolChannel
CLM=	    ../claims

DEBUG_CFLAGS     := -Wall -Werror -Wno-format -g -DDEBUG
RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3
O1RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O1
CFLAGS=     -D LINUX -D TEST -D TIXML_USE_STL $(RELEASE_CFLAGS)
LDFLAGS          := $(RELEASE_LDFLAGS)

CC=         g++
LINK=       g++

dobjs=      $(B)/jlmUtility.o $(B)/linuxHostsupport.o \
	    $(B)/tinyxml.o $(B)/tinyxmlparser.o $(B)/tinystr.o \
	    $(B)/tinyxmlerror.o $(B)/channel.o $(B)/request.o \
	    $(B)/buffercoding.o $(B)/tcIO.o $(B)/tcLaunch.o $(B)/logging.o 

all: $(E)/tcLaunch.exe

$(E)/tcLaunch.exe: $(dobjs)
	@echo "tcLaunch"
	$(LINK) -o $(E)/tcLaunch.exe $(dobjs) $(LDFLAGS) -lpthread

$(B)/logging.o: $(SC)/logging.cpp $(SC)/logging.h
	$(CC) $(CFLAGS) -I$(SC) -c -o $(B)/logging.o $(SC)/logging.cpp

$(B)/jlmUtility.o: $(SC)/jlmUtility.cpp $(SC)/jlmUtility.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(BN) -c -o $(B)/jlmUtility.o $(SC)/jlmUtility.cpp

$(B)/linuxHostsupport.o: $(TAO)/linuxHostsupport.cpp $(TAO)/linuxHostsupport.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(BN) -I$(TAO) -I$(TRS) -c -o $(B)/linuxHostsupport.o $(TAO)/linuxHostsupport.cpp

$(B)/kvmHostsupport.o: $(TAO)/kvmHostsupport.cpp $(TAO)/kvmHostsupport.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(BN) -I$(TAO) -c -o $(B)/kvmHostsupport.o $(TAO)/kvmHostsupport.cpp

$(B)/request.o: $(PROTO)/request.cpp $(PROTO)/request.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(BN) -I$(CH) -I$(CLM) -c -o $(B)/request.o $(PROTO)/request.cpp

$(B)/tinyxml.o : $(SC)/tinyxml.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxml.o $(SC)/tinyxml.cpp

$(B)/tinyxmlparser.o : $(SC)/tinyxmlparser.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxmlparser.o $(SC)/tinyxmlparser.cpp

$(B)/tinyxmlerror.o : $(SC)/tinyxmlerror.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxmlerror.o $(SC)/tinyxmlerror.cpp

$(B)/tinystr.o : $(SC)/tinystr.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinystr.o $(SC)/tinystr.cpp

$(B)/tcIO.o: $(TRS)/tcIO.cpp $(TRS)/tcIO.h
	$(CC) $(CFLAGS) -I$(TRS) -I$(SC) -c -o $(B)/tcIO.o $(TRS)/tcIO.cpp

$(B)/buffercoding.o: $(TRS)/buffercoding.cpp $(TRS)/buffercoding.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(TAO) -I$(BN) -I$(TRS) -c -o $(B)/buffercoding.o $(TRS)/buffercoding.cpp

$(B)/channel.o: $(CH)/channel.cpp $(CH)/channel.h
	$(CC) $(CFLAGS) -I$(SC) -c -o $(B)/channel.o $(CH)/channel.cpp

$(B)/tcLaunch.o: $(S)/tcLaunch.cpp
	$(CC) $(CFLAGS) -I$(BN) -I$(PROTO) -I$(CH) -I$(TAO) -I$(SCD) -I$(CLM) -I$(TRS) -I$(SC) -D LINUXTCSERVICE -c -o $(B)/tcLaunch.o $(S)/tcLaunch.cpp

