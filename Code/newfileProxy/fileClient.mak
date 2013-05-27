E=          ~/jlmcrypt
B=          ~/jlmcrypt/newfileClientobjects
S=          ../newfileProxy
SC=         ../commonCode
SCD=        ../newjlmcrypto
BSC=        ../jlmbignum
CLM=        ../newclaims
TAO=	    ../tao
TRS=	    ../tcService
TS=	    ../TPMDirect
CH=	    ../channels
PROTO=	    ../protocolChannel
ACC=	    ../accessControl
VLT=	    ../newvault

DEBUG_CFLAGS     := -Wall -Werror -Wno-format -g -DDEBUG
RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3
O1RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O1
CFLAGS=     -D LINUX -D FILECLIENT -D NEWANDREORGANIZED -D TEST -D TIXML_USE_STL -D __FLUSHIO__ $(RELEASE_CFLAGS)
LDFLAGS          := $(RELEASE_LDFLAGS)
O1CFLAGS=    -D LINUX -D FILECLIENT -D TEST -D TIXML_USE_STL -D __FLUSHIO__ $(O1RELEASE_CFLAGS)

CC=         g++
LINK=       g++

dobjs=      $(B)/jlmUtility.o $(B)/keys.o $(B)/cryptoHelper.o $(B)/jlmcrypto.o \
	    $(B)/mpBasicArith.o $(B)/mpModArith.o $(B)/mpNumTheory.o $(B)/fastArith.o \
	    $(B)/aesni.o $(B)/sha256.o $(B)/sha1.o $(B)/hmacsha256.o \
	    $(B)/encryptedblockIO.o $(B)/modesandpadding.o \
	    $(B)/taoSupport.o $(B)/taoEnvironment.o $(B)/taoHostServices.o \
	    $(B)/taoInit.o $(B)/linuxHostsupport.o $(B)/cert.o $(B)/quote.o \
	    $(B)/tinyxml.o $(B)/tinyxmlparser.o $(B)/tinystr.o \
	    $(B)/tinyxmlerror.o $(B)/channel.o $(B)/safeChannel.o \
	    $(B)/session.o $(B)/request.o $(B)/fileServices.o $(B)/validateEvidence.o \
	    $(B)/trustedKeyNego.o $(B)/buffercoding.o $(B)/tcIO.o $(B)/hashprep.o \
	    $(B)/fileTester.o $(B)/fileClient.o $(B)/logging.o 

all: $(E)/newfileClient.exe

$(E)/newfileClient.exe: $(dobjs)
	@echo "fileClient"
	$(LINK) -o $(E)/newfileClient.exe $(dobjs) $(LDFLAGS) -lpthread

$(B)/jlmcrypto.o: $(SCD)/jlmcrypto.cpp $(SCD)/jlmcrypto.h
	$(CC) $(CFLAGS) -I$(SCD) -I$(BSC) -I$(SC) -c -o $(B)/jlmcrypto.o $(SCD)/jlmcrypto.cpp

$(B)/logging.o: $(SC)/logging.cpp $(SC)/logging.h
	$(CC) $(CFLAGS) -I$(SC) -c -o $(B)/logging.o $(SC)/logging.cpp

$(B)/keys.o: $(SCD)/keys.cpp $(SCD)/keys.h
	$(CC) $(CFLAGS) -I$(SCD) -I$(BSC) -I$(SC) -c -o $(B)/keys.o $(SCD)/keys.cpp

$(B)/hmacsha256.o: $(SCD)/hmacsha256.cpp $(SCD)/hmacsha256.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(BSC) -c -o $(B)/hmacsha256.o $(SCD)/hmacsha256.cpp

$(B)/encryptedblockIO.o: $(SCD)/encryptedblockIO.cpp $(SCD)/encryptedblockIO.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(BSC) -c -o $(B)/encryptedblockIO.o $(SCD)/encryptedblockIO.cpp

$(B)/modesandpadding.o: $(SCD)/modesandpadding.cpp $(SCD)/modesandpadding.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(BSC) -c -o $(B)/modesandpadding.o $(SCD)/modesandpadding.cpp

$(B)/cryptoHelper.o: $(SCD)/cryptoHelper.cpp $(SCD)/cryptoHelper.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(BSC) -c -o $(B)/cryptoHelper.o $(SCD)/cryptoHelper.cpp

$(B)/jlmUtility.o: $(SC)/jlmUtility.cpp $(SC)/jlmUtility.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(BSC) -c -o $(B)/jlmUtility.o $(SC)/jlmUtility.cpp

$(B)/taoInit.o: $(TAO)/taoInit.cpp $(TAO)/tao.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCD) -I$(BSC) -I$(CLM) -I$(TAO) -I$(TRS) -c -o $(B)/taoInit.o $(TAO)/taoInit.cpp

$(B)/taoSupport.o: $(TAO)/taoSupport.cpp $(TAO)/tao.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCD) -I$(BSC) -I$(TAO) -I$(TRS) -c -o $(B)/taoSupport.o $(TAO)/taoSupport.cpp

$(B)/taoEnvironment.o: $(TAO)/taoEnvironment.cpp $(TAO)/tao.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCD) -I$(BSC) -I$(TAO) -I$(TS) -I$(TRS) -c -o $(B)/taoEnvironment.o $(TAO)/taoEnvironment.cpp

$(B)/taoHostServices.o: $(TAO)/taoHostServices.cpp $(TAO)/tao.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCD) -I$(BSC) -I$(TS) -I$(TAO) -I$(TRS) -c -o $(B)/taoHostServices.o $(TAO)/taoHostServices.cpp

$(B)/linuxHostsupport.o: $(TAO)/linuxHostsupport.cpp $(TAO)/linuxHostsupport.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCD) -I$(BSC) -I$(TAO) -I$(TRS) -c -o $(B)/linuxHostsupport.o $(TAO)/linuxHostsupport.cpp

$(B)/cert.o: $(CLM)/cert.cpp $(CLM)/cert.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCD) -I$(BSC) -I$(CLM) -I$(TAO) -I$(TS) -c -o $(B)/cert.o $(CLM)/cert.cpp

$(B)/validateEvidence.o: $(CLM)/validateEvidence.cpp $(CLM)/validateEvidence.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCD) -I$(BSC) -I$(ACC) -I$(CLM) -I$(TAO) -I$(TS) -c -o $(B)/validateEvidence.o $(CLM)/validateEvidence.cpp

$(B)/quote.o: $(CLM)/quote.cpp $(CLM)/quote.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCD) -I$(BSC) -I$(CLM) -I$(TAO) -I$(TS) -c -o $(B)/quote.o $(CLM)/quote.cpp

$(B)/request.o: $(PROTO)/request.cpp $(PROTO)/request.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(CH) -I$(TAO) -I$(BSC) -I$(CLM) -I$(S) -c -o $(B)/request.o $(PROTO)/request.cpp

$(B)/tinyxml.o : $(SC)/tinyxml.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxml.o $(SC)/tinyxml.cpp

$(B)/tinyxmlparser.o : $(SC)/tinyxmlparser.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxmlparser.o $(SC)/tinyxmlparser.cpp

$(B)/tinyxmlerror.o : $(SC)/tinyxmlerror.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxmlerror.o $(SC)/tinyxmlerror.cpp

$(B)/tinystr.o : $(SC)/tinystr.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinystr.o $(SC)/tinystr.cpp

$(B)/aesni.o: $(SCD)/aesni.cpp $(SCD)/aesni.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -c -o $(B)/aesni.o $(SCD)/aesni.cpp

$(B)/sha256.o: $(SCD)/sha256.cpp $(SCD)/sha256.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(BSC) -c -o $(B)/sha256.o $(SCD)/sha256.cpp

$(B)/fastArith.o: $(BSC)/fastArith.cpp
	$(CC) $(O1CFLAGS) -I$(SC) -I$(BSC) -c -o $(B)/fastArith.o $(BSC)/fastArith.cpp

$(B)/mpBasicArith.o: $(BSC)/mpBasicArith.cpp
	$(CC) $(O1CFLAGS) -I$(SC) -I$(BSC) -c -o $(B)/mpBasicArith.o $(BSC)/mpBasicArith.cpp

$(B)/mpModArith.o: $(BSC)/mpModArith.cpp
	$(CC) $(O1CFLAGS) -I$(SC) -I$(BSC) -c -o $(B)/mpModArith.o $(BSC)/mpModArith.cpp

$(B)/mpNumTheory.o: $(BSC)/mpNumTheory.cpp
	$(CC) $(O1CFLAGS) -I$(SC) -I$(SCD) -I$(BSC) -c -o $(B)/mpNumTheory.o $(BSC)/mpNumTheory.cpp

$(B)/sha1.o: $(SCD)/sha1.cpp $(SCD)/sha1.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(BSC) -c -o $(B)/sha1.o $(SCD)/sha1.cpp

$(B)/tcIO.o: $(TRS)/tcIO.cpp $(TRS)/tcIO.h
	$(CC) $(CFLAGS) -I$(TRS) -I$(SC) -c -o $(B)/tcIO.o $(TRS)/tcIO.cpp

$(B)/buffercoding.o: $(TRS)/buffercoding.cpp $(TRS)/buffercoding.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(TAO) -I$(BSC) -I$(TRS) -c -o $(B)/buffercoding.o $(TRS)/buffercoding.cpp

$(B)/channel.o: $(CH)/channel.cpp $(CH)/channel.h
	$(CC) $(CFLAGS) -I$(SC) -c -o $(B)/channel.o $(CH)/channel.cpp

$(B)/safeChannel.o: $(CH)/safeChannel.cpp $(CH)/safeChannel.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCD) -I$(BSC) -I$(CH) -c -o $(B)/safeChannel.o $(CH)/safeChannel.cpp

$(B)/hashprep.o: $(TS)/hashprep.cpp $(TS)/hashprep.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCD) -I$(BSC) -I$(TS) -c -o $(B)/hashprep.o $(TS)/hashprep.cpp

$(B)/fileClient.o: $(S)/fileClient.cpp $(S)/fileClient.h
	$(CC) $(CFLAGS) -I$(SCD) -I$(PROTO) -I$(CH) -I$(TAO) -I$(SCD) -I$(BSC) -I$(CLM) -I$(TS) -I$(TRS) -I$(SC) -c -o $(B)/fileClient.o $(S)/fileClient.cpp

$(B)/fileTester.o: $(S)/fileTester.cpp $(S)/fileTester.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(BSC) -I$(CLM) -I$(TS) -I$(CH) -I$(TAO) -I$(VLT) -I$(TRS) -I$(ACC) -I$(PROTO) -I$(S) -c -o $(B)/fileTester.o $(S)/fileTester.cpp

$(B)/fileChannel.o: $(S)/fileChannel.cpp $(S)/fileChannel.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCD) -I$(BSC) -I$(CLM) -c -o $(B)/fileChannel.o $(S)/fileChannel.cpp

$(B)/session.o: $(PROTO)/session.cpp $(PROTO)/session.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(CH) -I$(PROTO) -I$(BSC) -I$(TAO) -I$(CLM) -I$(S) -c -o $(B)/session.o $(PROTO)/session.cpp

$(B)/trustedKeyNego.o: $(TAO)/trustedKeyNego.cpp $(TAO)/trustedKeyNego.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(CH) -I$(BSC) -I$(CLM) -I$(TAO) -c -o $(B)/trustedKeyNego.o $(TAO)/trustedKeyNego.cpp

$(B)/fileServices.o: $(S)/fileServices.cpp $(S)/fileServices.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(CH) -I$(S) -I$(BSC) -I$(VLT) -I$(ACC) -I$(CLM) -I$(PROTO) -c -o $(B)/fileServices.o $(S)/fileServices.cpp

