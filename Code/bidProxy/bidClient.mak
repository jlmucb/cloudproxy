E=          ~/jlmcrypt
B=          ~/jlmcrypt/bidClientobjects
S=          ../bidProxy
SC=         ../commonCode
SCC=        ../jlmcrypto
BSC=        ../jlmbignum
PROTO=      ../protocolChannel
CLM=        ../claims
TAO=	    ../tao
TRS=	    ../tcService
TS=	    ../TPMDirect
CH=	    ../channels

DEBUG_CFLAGS     := -Wall -Werror -Wno-format -g -DDEBUG
RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3
O1RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O1
CFLAGS=     -D LINUX -D BIDCLIENT -D TEST -D TAOUSERSA2048 -D TIXML_USE_STL -D __FLUSHIO__ $(RELEASE_CFLAGS)
LDFLAGS          := $(RELEASE_LDFLAGS)
O1CFLAGS=    -D LINUX -D BIDCLIENT -D TEST -D TIXML_USE_STL -D __FLUSHIO__ $(O1RELEASE_CFLAGS)

CC=         g++
LINK=       g++

dobjs=      $(B)/bidClient.o $(B)/logging.o $(B)/jlmcrypto.o $(B)/jlmUtility.o \
	    $(B)/keys.o $(B)/aesni.o $(B)/sha256.o $(B)/cryptoHelper.o \
	    $(B)/validateEvidence.o  $(B)/attest.o $(B)/fastArith.o \
            $(B)/mpBasicArith.o $(B)/mpModArith.o $(B)/mpNumTheory.o \
            $(B)/hmacsha256.o $(B)/encryptedblockIO.o $(B)/modesandpadding.o \
	    $(B)/taoSupport.o $(B)/taoEnvironment.o $(B)/taoHostServices.o \
	    $(B)/taoInit.o $(B)/taoAttest.o $(B)/linuxHostsupport.o $(B)/tinyxml.o \
            $(B)/tinyxmlparser.o $(B)/tinystr.o $(B)/tinyxmlerror.o \
            $(B)/channel.o $(B)/safeChannel.o $(B)/session.o  $(B)/cert.o \
            $(B)/request.o $(B)/encapsulate.o $(B)/trustedKeyNego.o $(B)/sha1.o \
	    $(B)/buffercoding.o $(B)/tcIO.o $(B)/hashprep.o $(B)/bidTester.o \
	    $(B)/bidServices.o $(B)/channelServices.o $(B)/bidRequest.o 

all: $(E)/bidClient.exe

$(E)/bidClient.exe: $(dobjs)
	@echo "bidClient"
	$(LINK) -o $(E)/bidClient.exe $(dobjs) $(LDFLAGS) -lpthread

$(B)/bidClient.o: $(S)/bidClient.cpp $(S)/bidClient.h
	$(CC) $(CFLAGS) -D LINUXHOSTSERVICE -I$(SC) -I$(SCC) -I$(CLM) -I$(PROTO) -I$(BSC) -I$(TS) -I$(CH) -I$(TAO) -I$(TRS) -c -o $(B)/bidClient.o $(S)/bidClient.cpp

$(B)/bidTester.o: $(S)/bidTester.cpp $(S)/bidTester.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(PROTO) -I$(BSC) -I$(CLM) -I$(CH) -I$(TAO) -I$(TRS) -c -o $(B)/bidTester.o $(S)/bidTester.cpp

$(B)/jlmcrypto.o: $(SCC)/jlmcrypto.cpp $(SCC)/jlmcrypto.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/jlmcrypto.o $(SCC)/jlmcrypto.cpp

$(B)/bidServices.o: $(S)/bidServices.cpp $(S)/bidServices.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(CH) -I$(BSC) -I$(TRS) -I$(PROTO) -I$(TAO) -I$(CLM) -c -o $(B)/bidServices.o $(S)/bidServices.cpp

$(B)/encapsulate.o: $(SCC)/encapsulate.cpp $(SCC)/encapsulate.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/encapsulate.o $(SCC)/encapsulate.cpp

$(B)/logging.o: $(SC)/logging.cpp $(SC)/logging.h
	$(CC) $(CFLAGS) -I$(SC) -c -o $(B)/logging.o $(SC)/logging.cpp

$(B)/keys.o: $(SCC)/keys.cpp $(SCC)/keys.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/keys.o $(SCC)/keys.cpp

$(B)/hmacsha256.o: $(SCC)/hmacsha256.cpp $(SCC)/hmacsha256.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/hmacsha256.o $(SCC)/hmacsha256.cpp

$(B)/bidRequest.o: $(S)/bidRequest.cpp $(S)/bidRequest.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(CH) -I$(BSC) -I$(TRS) -I$(PROTO) -I$(TAO) -I$(CLM) -c -o $(B)/bidRequest.o $(S)/bidRequest.cpp

$(B)/channelServices.o: $(PROTO)/channelServices.cpp $(PROTO)/channelServices.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(PROTO) -I$(BSC) -I$(CLM) -I$(CH) -I$(TAO) -c -o $(B)/channelServices.o $(PROTO)/channelServices.cpp

$(B)/encryptedblockIO.o: $(SCC)/encryptedblockIO.cpp $(SCC)/encryptedblockIO.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/encryptedblockIO.o $(SCC)/encryptedblockIO.cpp

$(B)/validateEvidence.o: $(CLM)/validateEvidence.cpp $(CLM)/validateEvidence.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(VLT) -I$(TAO) -I$(ACC) -I$(CLM) -c -o $(B)/validateEvidence.o $(CLM)/validateEvidence.cpp

$(B)/modesandpadding.o: $(SCC)/modesandpadding.cpp $(SCC)/modesandpadding.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/modesandpadding.o $(SCC)/modesandpadding.cpp

$(B)/cryptoHelper.o: $(SCC)/cryptoHelper.cpp $(SCC)/cryptoHelper.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/cryptoHelper.o $(SCC)/cryptoHelper.cpp

$(B)/jlmUtility.o: $(SC)/jlmUtility.cpp $(SC)/jlmUtility.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/jlmUtility.o $(SC)/jlmUtility.cpp

$(B)/bidChannel.o: $(S)/bidChannel.cpp $(S)/bidChannel.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(CLM) -c -o $(B)/bidChannel.o $(S)/bidChannel.cpp

$(B)/taoInit.o: $(TAO)/taoInit.cpp $(TAO)/tao.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(CLM) -I$(TAO) -I$(TRS) -c -o $(B)/taoInit.o $(TAO)/taoInit.cpp

$(B)/taoSupport.o: $(TAO)/taoSupport.cpp $(TAO)/tao.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(CLM) -I$(TAO) -I$(TRS) -c -o $(B)/taoSupport.o $(TAO)/taoSupport.cpp

$(B)/taoEnvironment.o: $(TAO)/taoEnvironment.cpp $(TAO)/tao.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(CLM) -I$(TAO) -I$(TS) -I$(TRS) -c -o $(B)/taoEnvironment.o $(TAO)/taoEnvironment.cpp

$(B)/taoHostServices.o: $(TAO)/taoHostServices.cpp $(TAO)/tao.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(CLM) -I$(TS) -I$(TAO) -I$(TRS) -c -o $(B)/taoHostServices.o $(TAO)/taoHostServices.cpp

$(B)/linuxHostsupport.o: $(TAO)/linuxHostsupport.cpp $(TAO)/linuxHostsupport.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(CLM) -I$(BSC) -I$(TAO) -I$(TRS) -c -o $(B)/linuxHostsupport.o $(TAO)/linuxHostsupport.cpp

$(B)/taoAttest.o: $(TAO)/taoAttest.cpp $(TAO)/tao.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(TRS) -I$(BSC) -I$(TS) -I$(CLM) -I$(TAO) -c -o $(B)/taoAttest.o $(TAO)/taoAttest.cpp

$(B)/attest.o: $(CLM)/attest.cpp $(CLM)/attest.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(BSC) -I$(TRS) -I$(VLT) -I$(TRS) -I$(TAO) -I$(CLM) -I$(TS) -I$(SCC) -c -o $(B)/attest.o $(CLM)/attest.cpp

$(B)/cert.o: $(CLM)/cert.cpp $(CLM)/cert.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(VLT) -I$(TAO) -I$(S) -c -o $(B)/cert.o $(CLM)/cert.cpp

$(B)/session.o: $(PROTO)/session.cpp $(PROTO)/session.h
	$(CC) $(CFLAGS) -I$(SC) -I$(CH) -I$(SCC) -I$(BSC) -I$(TAO) -I$(CLM) -I$(VLT) -I$(TRS) -c -o $(B)/session.o $(PROTO)/session.cpp

$(B)/trustedKeyNego.o: $(TAO)/trustedKeyNego.cpp $(TAO)/trustedKeyNego.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(CH) -I$(BSC) -I$(CLM) -I$(TAO) -c -o $(B)/trustedKeyNego.o $(TAO)/trustedKeyNego.cpp

$(B)/request.o: $(PROTO)/request.cpp $(PROTO)/request.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(CH) -I$(TAO) -I$(BSC) -I$(CLM) -c -o $(B)/request.o $(PROTO)/request.cpp

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
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(CLM) -I$(TAO) -I$(BSC) -I$(TRS) -c -o $(B)/buffercoding.o $(TRS)/buffercoding.cpp

$(B)/channel.o: $(CH)/channel.cpp $(CH)/channel.h
	$(CC) $(CFLAGS) -I$(SC) -c -o $(B)/channel.o $(CH)/channel.cpp

$(B)/safeChannel.o: $(CH)/safeChannel.cpp $(CH)/safeChannel.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(CH) -c -o $(B)/safeChannel.o $(CH)/safeChannel.cpp

$(B)/hashprep.o: $(TS)/hashprep.cpp $(TS)/hashprep.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(TS) -c -o $(B)/hashprep.o $(TS)/hashprep.cpp



