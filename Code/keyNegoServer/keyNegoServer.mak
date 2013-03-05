E=          ~/jlmcrypt
B=          ~/jlmcrypt/keyNegoServerobjects
S=          ../keyNegoServer
SC=         ../commonCode
OC=         ../fileProxy
SCC=        ../jlmcrypto
BSC=        ../jlmbignum
CLM=        ../claims
TH=         ../tao
CH=         ../channels
TPD=        ../TPMDirect
VLT=        ../vault
RMM=        ../resources
TRS=        ../tcService
        


DEBUG_CFLAGS     := -Wall -Werror -Wno-format -g -DDEBUG
RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3
LDFLAGSXML      := ${RELEASE_LDFLAGS}
CFLAGS=     -D LINUX -D QUOTE2_DEFINED -D TEST -D __FLUSHIO__ $(RELEASE_CFLAGS)

CC=         g++
LINK=       g++

dobjs=      $(B)/keyNegoServer.o $(B)/logging.o $(B)/jlmcrypto.o $(B)/jlmUtility.o \
	    $(B)/keys.o $(B)/aesni.o $(B)/sha256.o  $(B)/sha1.o $(B)/channel.o \
            $(B)/hmacsha256.o $(B)/mpBasicArith.o $(B)/mpModArith.o $(B)/hashprep.o \
	    $(B)/mpNumTheory.o  $(B)/rsaHelper.o $(B)/secPrincipal.o  $(B)/resource.o \
            $(B)/modesandpadding.o $(B)/claims.o $(B)/tinystr.o $(B)/vault.o \
            $(B)/tinyxmlerror.o $(B)/tinyxml.o $(B)/tinyxmlparser.o $(B)/encryptedblockIO.o 

all: $(E)/keyNegoServer.exe

$(E)/keyNegoServer.exe: $(dobjs)
	@echo "keyNegoServer"
	$(LINK) -o $(E)/keyNegoServer.exe $(dobjs) -lpthread

$(B)/keyNegoServer.o: $(S)/keyNegoServer.cpp $(S)/keyNegoServer.h
	$(CC) $(CFLAGS) -I$(S) -I$(RMM) -I$(TRS) -I$(OC) -I$(TPD) -I$(VLT) -I$(SC) -I$(TH) -I$(SCC) -I$(BSC) -I$(CH) -I$(CLM) -c -o $(B)/keyNegoServer.o $(S)/keyNegoServer.cpp

$(B)/keys.o: $(SCC)/keys.cpp $(SCC)/keys.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/keys.o $(SCC)/keys.cpp

$(B)/hmacsha256.o: $(SCC)/hmacsha256.cpp $(SCC)/hmacsha256.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/hmacsha256.o $(SCC)/hmacsha256.cpp

$(B)/modesandpadding.o: $(SCC)/modesandpadding.cpp $(SCC)/modesandpadding.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/modesandpadding.o $(SCC)/modesandpadding.cpp

$(B)/resource.o: $(RMM)/resource.cpp $(RMM)/resource.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -I$(CLM) -I$(RMM) -c -o $(B)/resource.o $(RMM)/resource.cpp

$(B)/claims.o: $(CLM)/claims.cpp $(CLM)/claims.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(TPD) -I$(CLM) -I$(TH) -c -o $(B)/claims.o $(CLM)/claims.cpp

$(B)/vault.o: $(VLT)/vault.cpp $(VLT)/vault.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(CH) -I$(TRS) -I$(SCC) -I$(BSC) -I$(VLT) -I$(RMM) -I$(TPD) -I$(CLM) -I$(TH) -c -o $(B)/vault.o $(VLT)/vault.cpp

$(B)/secPrincipal.o: $(CLM)/secPrincipal.cpp $(CLM)/secPrincipal.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(VLT) -I$(RMM) -I$(TPD) -I$(CLM) -I$(TH) -c -o $(B)/secPrincipal.o $(CLM)/secPrincipal.cpp

$(B)/logging.o: $(SC)/logging.cpp $(SC)/logging.h
	$(CC) $(CFLAGS) -I$(SC) -c -o $(B)/logging.o $(SC)/logging.cpp

$(B)/jlmUtility.o: $(SC)/jlmUtility.cpp $(SC)/jlmUtility.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/jlmUtility.o $(SC)/jlmUtility.cpp

$(B)/jlmcrypto.o: $(SCC)/jlmcrypto.cpp $(SCC)/jlmcrypto.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/jlmcrypto.o $(SCC)/jlmcrypto.cpp

$(B)/rsaHelper.o: $(SCC)/rsaHelper.cpp $(SCC)/rsaHelper.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/rsaHelper.o $(SCC)/rsaHelper.cpp

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

$(B)/sha1.o: $(SCC)/sha1.cpp $(SCC)/sha1.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/sha1.o $(SCC)/sha1.cpp

$(B)/sha256.o: $(SCC)/sha256.cpp $(SCC)/sha256.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/sha256.o $(SCC)/sha256.cpp

$(B)/hashprep.o: $(TPD)/hashprep.cpp $(TPD)/hashprep.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(TPD) -c -o $(B)/hashprep.o $(TPD)/hashprep.cpp

$(B)/mpBasicArith.o: $(BSC)/mpBasicArith.cpp
	$(CC) $(CFLAGS) -I$(SC) -I$(BSC) -c -o $(B)/mpBasicArith.o $(BSC)/mpBasicArith.cpp

$(B)/mpModArith.o: $(BSC)/mpModArith.cpp
	$(CC) $(CFLAGS) -I$(SC) -I$(BSC) -c -o $(B)/mpModArith.o $(BSC)/mpModArith.cpp

$(B)/mpNumTheory.o: $(BSC)/mpNumTheory.cpp
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/mpNumTheory.o $(BSC)/mpNumTheory.cpp

$(B)/channel.o: $(CH)/channel.cpp $(CH)/channel.h
	$(CC) $(CFLAGS) -I$(SC) -I$(CH) -c -o $(B)/channel.o $(CH)/channel.cpp

$(B)/encryptedblockIO.o: $(SCC)/encryptedblockIO.cpp $(SCC)/encryptedblockIO.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/encryptedblockIO.o $(SCC)/encryptedblockIO.cpp


