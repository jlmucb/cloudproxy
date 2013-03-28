E=          ~/jlmcrypt
B=          ~/jlmcrypt/bidServerobjects
S=          ../bidProxy
SC=         ../commonCode
SCC=        ../jlmcrypto
BSC=        ../oldjlmbignum
RMM=        ../resources
TH=	    ../tao
VLT=	    ../vault
TRS=	    ../tcService
TS=	    ../TPMDirect
CH=	    ../channels

DEBUG_CFLAGS     := -Wall -Werror -Wno-format -g
RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3 -g
O1RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O1
LDFLAGS          := $(RELEASE_LDFLAGS)
CFLAGS=     -D LINUX -D TEST -D __FLUSHIO__ $(RELEASE_CFLAGS)
O1CFLAGS=    -D LINUX -D TEST -D __FLUSHIO__ $(O1RELEASE_CFLAGS)

CC=         g++
LINK=       g++

dobjs=      $(B)/bidServer.o $(B)/jlmcrypto.o $(B)/hashprep.o \
	    $(B)/session.o $(B)/request.o $(B)/jlmUtility.o $(B)/keys.o \
	    $(B)/aesni.o $(B)/sha256.o $(B)/mpBasicArith.o $(B)/mpModArith.o \
	    $(B)/mpNumTheory.o $(B)/fastArith.o $(B)/encryptedblockIO.o \
	    $(B)/rsaHelper.o $(B)/hmacsha256.o $(B)/modesandpadding.o \
	    $(B)/trustedKeyNego.o $(B)/taoSupport.o $(B)/taoEnvironment.o \
	    $(B)/taoHostServices.o $(B)/taoInit.o $(B)/linuxHostsupport.o \
	    $(B)/tinystr.o $(B)/tinyxmlerror.o $(B)/tinyxml.o \
	    $(B)/channel.o $(B)/safeChannel.o $(B)/tinyxmlparser.o \
	    $(B)/secPrincipal.o $(B)/claims.o $(B)/encapsulate.o \
	    $(B)/sha1.o $(B)/logging.o $(B)/buffercoding.o $(B)/tcIO.o 

all: $(E)/bidServer.exe

$(E)/bidServer.exe: $(dobjs)
	@echo "bidServer"
	$(LINK) -o $(E)/bidServer.exe $(dobjs) $(LDFLAGS) -lpthread

$(B)/bidServer.o: $(S)/bidServer.cpp $(S)/bidServer.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(CH) -I$(BSC) -I$(TRS) -I$(RMM) -I$(TH) -I$(VLT) -c -o $(B)/bidServer.o $(S)/bidServer.cpp

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

$(B)/session.o: $(S)/session.cpp $(S)/session.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -I$(TH) -I$(RMM) -I$(VLT) -I$(TRS) -c -o $(B)/session.o $(S)/session.cpp

$(B)/logging.o: $(SC)/logging.cpp $(SC)/logging.h
	$(CC) $(CFLAGS) -I$(SC) -c -o $(B)/logging.o $(SC)/logging.cpp

$(B)/encapsulate.o: $(SCC)/encapsulate.cpp $(SCC)/encapsulate.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/encapsulate.o $(SCC)/encapsulate.cpp

$(B)/jlmcrypto.o: $(SCC)/jlmcrypto.cpp $(SCC)/jlmcrypto.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/jlmcrypto.o $(SCC)/jlmcrypto.cpp

$(B)/rsaHelper.o: $(SCC)/rsaHelper.cpp $(SCC)/rsaHelper.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/rsaHelper.o $(SCC)/rsaHelper.cpp

#$(B)/vault.o: $(VLT)/vault.cpp $(VLT)/vault.h
#	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -I$(CH) -I$(RMM) -I$(TRS) -I$(TH) -I$(VLT) -c -o $(B)/vault.o $(VLT)/vault.cpp

$(B)/taoInit.o: $(TH)/taoInit.cpp $(TH)/tao.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(TH) -I$(TRS) -c -o $(B)/taoInit.o $(TH)/taoInit.cpp

$(B)/taoSupport.o: $(TH)/taoSupport.cpp $(TH)/tao.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(TRS) -I$(BSC) -I$(TH) -c -o $(B)/taoSupport.o $(TH)/taoSupport.cpp

$(B)/taoEnvironment.o: $(TH)/taoEnvironment.cpp $(TH)/tao.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(TS) -I$(TH) -I$(TRS) -c -o $(B)/taoEnvironment.o $(TH)/taoEnvironment.cpp

$(B)/taoHostServices.o: $(TH)/taoHostServices.cpp $(TH)/tao.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(TS) -I$(TH) -I$(TRS) -c -o $(B)/taoHostServices.o $(TH)/taoHostServices.cpp

$(B)/linuxHostsupport.o: $(TH)/linuxHostsupport.cpp $(TH)/linuxHostsupport.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(TH) -I$(TRS) -c -o $(B)/linuxHostsupport.o $(TH)/linuxHostsupport.cpp

$(B)/trustedKeyNego.o: $(TH)/trustedKeyNego.cpp $(TH)/trustedKeyNego.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(CH) -I$(BSC) -I$(TH) -c -o $(B)/trustedKeyNego.o $(TH)/trustedKeyNego.cpp

$(B)/secPrincipal.o: $(S)/secPrincipal.cpp $(S)/secPrincipal.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(VLT) -I$(TH) -c -o $(B)/secPrincipal.o $(S)/secPrincipal.cpp

$(B)/request.o: $(S)/request.cpp $(S)/request.h 
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -I$(TH) -I$(CH) -c -o $(B)/request.o $(S)/request.cpp

$(B)/claims.o: $(S)/claims.cpp $(S)/claims.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(TS) -I$(TH) -I$(VLT) -c -o $(B)/claims.o $(S)/claims.cpp

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
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(TH) -I$(BSC) -I$(TRS) -c -o $(B)/buffercoding.o $(TRS)/buffercoding.cpp

$(B)/channel.o: $(CH)/channel.cpp $(CH)/channel.h
	$(CC) $(CFLAGS) -I$(SC) -c -o $(B)/channel.o $(CH)/channel.cpp

$(B)/safeChannel.o: $(CH)/safeChannel.cpp $(CH)/safeChannel.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(CH) -c -o $(B)/safeChannel.o $(CH)/safeChannel.cpp

$(B)/hashprep.o: $(TS)/hashprep.cpp $(TS)/hashprep.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(TS) -c -o $(B)/hashprep.o $(TS)/hashprep.cpp

$(B)/inittrustedapp.o: $(TRS)/inittrustedapp.cpp 
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(TH) -I$(BSC) -I$(TRS) -c -o $(B)/inittrustedapp.o $(TRS)/inittrustedapp.cpp

$(B)/serviceblobNames.o: $(TRS)/serviceblobNames.cpp $(TRS)/serviceblobNames.h
	$(CC) $(CFLAGS) -I$(TRS) -c -o $(B)/serviceblobNames.o $(TRS)/serviceblobNames.cpp

