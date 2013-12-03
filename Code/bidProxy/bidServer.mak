E=          ~/jlmcrypt
B=          ~/jlmcrypt/bidServerobjects
S=          ../bidProxy
SC=         ../commonCode
SCC=        ../jlmcrypto
BSC=        ../jlmbignum
PROTO=      ../resources
TAO=	    ../tao
PROTO=	    ../protocolChannel
TRS=	    ../tcService
TS=	    ../TPMDirect
CH=	    ../channels
CLM=	    ../claims
FSR=	    ../fileProxy
ACC=	    ../accessControl
VLT=	    ../vault

DEBUG_CFLAGS     := -Wall -Werror -Wno-format -g
RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3 -g
O1RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O1
LDFLAGS          := $(RELEASE_LDFLAGS)
CFLAGS=     -D LINUX -D TEST -D TAOUSERSA2048 -D __FLUSHIO__ $(RELEASE_CFLAGS)
O1CFLAGS=    -D LINUX -D TEST -D __FLUSHIO__ $(O1RELEASE_CFLAGS)

CC=         g++
LINK=       g++

dobjs=      $(B)/bidServer.o $(B)/jlmcrypto.o $(B)/hashprep.o \
	    $(B)/session.o $(B)/request.o $(B)/jlmUtility.o $(B)/keys.o \
	    $(B)/aesni.o $(B)/sha256.o $(B)/mpBasicArith.o $(B)/mpModArith.o \
	    $(B)/mpNumTheory.o $(B)/fastArith.o $(B)/encryptedblockIO.o \
	    $(B)/cryptoHelper.o $(B)/hmacsha256.o $(B)/modesandpadding.o \
	    $(B)/trustedKeyNego.o $(B)/taoSupport.o $(B)/taoEnvironment.o \
	    $(B)/taoHostServices.o $(B)/taoInit.o $(B)/linuxHostsupport.o \
	    $(B)/tinystr.o $(B)/tinyxmlerror.o $(B)/tinyxml.o \
	    $(B)/channel.o $(B)/safeChannel.o $(B)/tinyxmlparser.o \
	    $(B)/cert.o $(B)/encapsulate.o $(B)/serviceChannel.o \
	    $(B)/sha1.o $(B)/logging.o $(B)/buffercoding.o $(B)/tcIO.o 

all: $(E)/bidServer.exe

$(E)/bidServer.exe: $(dobjs)
	@echo "bidServer"
	$(LINK) -o $(E)/bidServer.exe $(dobjs) $(LDFLAGS) -lpthread

$(B)/bidServer.o: $(S)/bidServer.cpp $(S)/bidServer.h
	$(CC) $(CFLAGS) -D LINUXHOSTSERVICE -I$(SC) -I$(ACC) -I$(SCC) -I$(CH) -I$(VLT) -I$(FSR) -I$(BSC) -I$(TRS) -I$(PROTO) -I$(TAO) -I$(CLM) -c -o $(B)/bidServer.o $(S)/bidServer.cpp

$(B)/keys.o: $(SCC)/keys.cpp $(SCC)/keys.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/keys.o $(SCC)/keys.cpp

$(B)/modesandpadding.o: $(SCC)/modesandpadding.cpp $(SCC)/modesandpadding.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/modesandpadding.o $(SCC)/modesandpadding.cpp

$(B)/hmacsha256.o: $(SCC)/hmacsha256.cpp $(SCC)/hmacsha256.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/hmacsha256.o $(SCC)/hmacsha256.cpp

$(B)/encryptedblockIO.o: $(SCC)/encryptedblockIO.cpp $(SCC)/encryptedblockIO.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/encryptedblockIO.o $(SCC)/encryptedblockIO.cpp

$(B)/jlmUtility.o: $(SC)/jlmUtility.cpp $(SC)/jlmUtility.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/jlmUtility.o $(SC)/jlmUtility.cpp

$(B)/session.o: $(PROTO)/session.cpp $(PROTO)/session.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -I$(TAO) -I$(PROTO) -I$(CH) -I$(CLM) -I$(TRS) -c -o $(B)/session.o $(PROTO)/session.cpp

$(B)/serviceChannel.o: $(PROTO)/serviceChannel.cpp $(PROTO)/serviceChannel.h
	$(CC) $(CFLAGS) -I$(ACC) -I$(S) -I$(VLT) -I$(SC) -I$(SCC) -I$(PROTO) -I$(BSC) -I$(CLM) -I$(CH) -I$(TRS) -I$(TAO) -I$(FSR) -c -o $(B)/serviceChannel.o $(PROTO)/serviceChannel.cpp

$(B)/logging.o: $(SC)/logging.cpp $(SC)/logging.h
	$(CC) $(CFLAGS) -I$(SC) -c -o $(B)/logging.o $(SC)/logging.cpp

$(B)/encapsulate.o: $(SCC)/encapsulate.cpp $(SCC)/encapsulate.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/encapsulate.o $(SCC)/encapsulate.cpp

$(B)/jlmcrypto.o: $(SCC)/jlmcrypto.cpp $(SCC)/jlmcrypto.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/jlmcrypto.o $(SCC)/jlmcrypto.cpp

$(B)/cryptoHelper.o: $(SCC)/cryptoHelper.cpp $(SCC)/cryptoHelper.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/cryptoHelper.o $(SCC)/cryptoHelper.cpp

$(B)/taoInit.o: $(TAO)/taoInit.cpp $(TAO)/tao.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(TAO) -I$(CLM) -I$(TRS) -c -o $(B)/taoInit.o $(TAO)/taoInit.cpp

$(B)/taoSupport.o: $(TAO)/taoSupport.cpp $(TAO)/tao.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(TRS) -I$(BSC) -I$(CLM) -I$(TAO) -c -o $(B)/taoSupport.o $(TAO)/taoSupport.cpp

$(B)/taoEnvironment.o: $(TAO)/taoEnvironment.cpp $(TAO)/tao.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(TS) -I$(CLM) -I$(TAO) -I$(TRS) -c -o $(B)/taoEnvironment.o $(TAO)/taoEnvironment.cpp

$(B)/taoHostServices.o: $(TAO)/taoHostServices.cpp $(TAO)/tao.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(TS) -I$(CLM) -I$(TAO) -I$(TRS) -c -o $(B)/taoHostServices.o $(TAO)/taoHostServices.cpp

$(B)/linuxHostsupport.o: $(TAO)/linuxHostsupport.cpp $(TAO)/linuxHostsupport.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(TAO) -I$(CLM) -I$(TRS) -c -o $(B)/linuxHostsupport.o $(TAO)/linuxHostsupport.cpp

$(B)/trustedKeyNego.o: $(TAO)/trustedKeyNego.cpp $(TAO)/trustedKeyNego.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(CH) -I$(BSC) -I$(TAO) -c -o $(B)/trustedKeyNego.o $(TAO)/trustedKeyNego.cpp

$(B)/cert.o: $(CLM)/cert.cpp $(CLM)/cert.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(CLM) -I$(TAO) -c -o $(B)/cert.o $(CLM)/cert.cpp

$(B)/request.o: $(PROTO)/request.cpp $(PROTO)/request.h 
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -I$(TAO) -I$(CLM) -I$(CH) -c -o $(B)/request.o $(PROTO)/request.cpp

#$(B)/claims.o: $(S)/claims.cpp $(S)/claims.h
#	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(TS) -I$(TAO) -I$(CLM) -c -o $(B)/claims.o $(S)/claims.cpp

$(B)/tinyxml.o : $(SC)/tinyxml.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxml.o $(SC)/tinyxml.cpp

$(B)/tinyxmlparser.o : $(SC)/tinyxmlparser.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxmlparser.o $(SC)/tinyxmlparser.cpp

$(B)/tinyxmlerror.o : $(SC)/tinyxmlerror.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxmlerror.o $(SC)/tinyxmlerror.cpp

$(B)/tinystr.o : $(SC)/tinystr.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinystr.o $(SC)/tinystr.cpp

$(B)/aesni.o: $(SCC)/aesni.cpp $(SCC)/aesni.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SCC) -c -o $(B)/aesni.o $(SCC)/aesni.cpp

$(B)/sha256.o: $(SCC)/sha256.cpp $(SCC)/sha256.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/sha256.o $(SCC)/sha256.cpp

$(B)/fastArith.o: $(BSC)/fastArith.cpp
	$(CC) $(O1CFLAGS) -I$(SC) -I$(BSC) -c -o $(B)/fastArith.o $(BSC)/fastArith.cpp

$(B)/mpBasicArith.o: $(BSC)/mpBasicArith.cpp
	$(CC) $(O1CFLAGS) -I$(SC) -I$(BSC) -c -o $(B)/mpBasicArith.o $(BSC)/mpBasicArith.cpp

$(B)/mpModArith.o: $(BSC)/mpModArith.cpp
	$(CC) $(O1CFLAGS) -I$(SC) -I$(BSC) -c -o $(B)/mpModArith.o $(BSC)/mpModArith.cpp

$(B)/mpNumTheory.o: $(BSC)/mpNumTheory.cpp
	$(CC) $(O1CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/mpNumTheory.o $(BSC)/mpNumTheory.cpp

$(B)/sha1.o: $(SCC)/sha1.cpp $(SCC)/sha1.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/sha1.o $(SCC)/sha1.cpp

$(B)/tcIO.o: $(TRS)/tcIO.cpp $(TRS)/tcIO.h
	$(CC) $(CFLAGS) -I$(TRS) -I$(SC) -c -o $(B)/tcIO.o $(TRS)/tcIO.cpp

$(B)/buffercoding.o: $(TRS)/buffercoding.cpp $(TRS)/buffercoding.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(TAO) -I$(BSC) -I$(TRS) -I$(CLM) -c -o $(B)/buffercoding.o $(TRS)/buffercoding.cpp

$(B)/channel.o: $(CH)/channel.cpp $(CH)/channel.h
	$(CC) $(CFLAGS) -I$(SC) -c -o $(B)/channel.o $(CH)/channel.cpp

$(B)/safeChannel.o: $(CH)/safeChannel.cpp $(CH)/safeChannel.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(CH) -c -o $(B)/safeChannel.o $(CH)/safeChannel.cpp

$(B)/hashprep.o: $(TS)/hashprep.cpp $(TS)/hashprep.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(TS) -c -o $(B)/hashprep.o $(TS)/hashprep.cpp

$(B)/serviceblobNames.o: $(TRS)/serviceblobNames.cpp $(TRS)/serviceblobNames.h
	$(CC) $(CFLAGS) -I$(TRS) -c -o $(B)/serviceblobNames.o $(TRS)/serviceblobNames.cpp

