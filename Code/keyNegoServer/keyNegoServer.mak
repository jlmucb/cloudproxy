ifndef CPProgramDirectory
E=/home/jlm/jlmcrypt
else
E=      $(CPProgramDirectory)
endif

B=          $(E)/keyNegoServerobjects
S=          ../keyNegoServer
SC=         ../commonCode
FPX=        ../fileProxy
SCC=        ../jlmcrypto
ACC=        ../accessControl
BSC=        ../jlmbignum
CLM=        ../claims
TH=         ../tao
CH=         ../channels
TPD=        ../TPMDirect
VLT=        ../vault
TRS=        ../tcService
        


DEBUG_CFLAGS     := -Wall -Werror -Wno-format -g -DDEBUG
RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3
O1RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O1
LDFLAGSXML      := ${RELEASE_LDFLAGS}
CFLAGS=     -D FILECLIENT -D LINUX -D TEST -D __FLUSHIO__ $(RELEASE_CFLAGS)
CFLAGS1=    -D FILECLIENT -D LINUX -D TEST -D __FLUSHIO__ $(O1RELEASE_CFLAGS)
# -D NOQUOTE2  -  define this if you want legacy quote
# -D MACTHENENCRYPT  -  define this if you want MAC then Encrypt, you shouldn't ever
# add -D PCR18

CC=         g++
LINK=       g++

dobjs=      $(B)/keyNegoServer.o $(B)/logging.o $(B)/jlmcrypto.o $(B)/jlmUtility.o \
	    $(B)/keys.o $(B)/aesni.o $(B)/sha256.o  $(B)/sha1.o $(B)/channel.o \
            $(B)/hmacsha256.o $(B)/mpBasicArith.o $(B)/mpModArith.o $(B)/hashprep.o \
	    $(B)/mpNumTheory.o  $(B)/cryptoHelper.o $(B)/quote.o $(B)/cert.o  \
	    $(B)/attest.o $(B)/resource.o $(B)/modesandpadding.o $(B)/validateEvidence.o \
	    $(B)/tinystr.o $(B)/tinyxmlerror.o $(B)/tinyxml.o $(B)/tinyxmlparser.o \
	    $(B)/fastArith.o $(B)/encryptedblockIO.o $(B)/taoAttest.o

all: $(E)/keyNegoServer.exe

$(E)/keyNegoServer.exe: $(dobjs)
	@echo "keyNegoServer"
	$(LINK) -o $(E)/keyNegoServer.exe $(dobjs) -lpthread

$(B)/keyNegoServer.o: $(S)/keyNegoServer.cpp $(S)/keyNegoServer.h
	$(CC) $(CFLAGS) -I$(S) -I$(TRS) -I$(FPX) -I$(TPD) -I$(VLT) -I$(SC) -I$(TH) -I$(SCC) -I$(BSC) -I$(CH) -I$(CLM) -c -o $(B)/keyNegoServer.o $(S)/keyNegoServer.cpp

$(B)/keys.o: $(SCC)/keys.cpp $(SCC)/keys.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/keys.o $(SCC)/keys.cpp

$(B)/hmacsha256.o: $(SCC)/hmacsha256.cpp $(SCC)/hmacsha256.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/hmacsha256.o $(SCC)/hmacsha256.cpp

$(B)/modesandpadding.o: $(SCC)/modesandpadding.cpp $(SCC)/modesandpadding.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/modesandpadding.o $(SCC)/modesandpadding.cpp

$(B)/resource.o: $(FPX)/resource.cpp $(FPX)/resource.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -I$(CLM) -I$(FPX) -c -o $(B)/resource.o $(FPX)/resource.cpp

$(B)/claims.o: $(CLM)/claims.cpp $(CLM)/claims.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(TPD) -I$(CLM) -I$(TH) -c -o $(B)/claims.o $(CLM)/claims.cpp

$(B)/validateEvidence.o: $(CLM)/validateEvidence.cpp $(CLM)/validateEvidence.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(TPD) -I$(ACC) -I$(CLM) -I$(TH) -c -o $(B)/validateEvidence.o $(CLM)/validateEvidence.cpp

$(B)/cert.o: $(CLM)/cert.cpp $(CLM)/cert.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(TPD) -I$(CLM) -I$(TH) -c -o $(B)/cert.o $(CLM)/cert.cpp

$(B)/quote.o: $(CLM)/quote.cpp $(CLM)/quote.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(TRS) -I$(VLT) -I$(FPX) -I$(TPD) -I$(CLM) -I$(TH) -c -o $(B)/quote.o $(CLM)/quote.cpp

$(B)/attest.o: $(CLM)/attest.cpp $(CLM)/attest.h
	$(CC) $(CFLAGS) -I$(S) -I$(SC) -I$(SCC) -I$(BSC) -I$(TRS) -I$(VLT) -I$(FPX) -I$(TPD) -I$(CLM) -I$(TH) -c -o $(B)/attest.o $(CLM)/attest.cpp

$(B)/logging.o: $(SC)/logging.cpp $(SC)/logging.h
	$(CC) $(CFLAGS) -I$(SC) -c -o $(B)/logging.o $(SC)/logging.cpp

$(B)/jlmUtility.o: $(SC)/jlmUtility.cpp $(SC)/jlmUtility.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/jlmUtility.o $(SC)/jlmUtility.cpp

$(B)/jlmcrypto.o: $(SCC)/jlmcrypto.cpp $(SCC)/jlmcrypto.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/jlmcrypto.o $(SCC)/jlmcrypto.cpp

$(B)/cryptoHelper.o: $(SCC)/cryptoHelper.cpp $(SCC)/cryptoHelper.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/cryptoHelper.o $(SCC)/cryptoHelper.cpp

$(B)/taoAttest.o: $(TH)/taoAttest.cpp
	$(CC) $(O1CFLAGS) -I$(SC) -I$(BSC) -I$(SCC) -I$(TH) -I$(CLM) -I$(TRS) -I$(TPD) -c -o $(B)/taoAttest.o $(TH)/taoAttest.cpp

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

$(B)/fastArith.o: $(BSC)/fastArith.cpp
	$(CC) $(O1CFLAGS) -I$(SC) -I$(BSC) -c -o $(B)/fastArith.o $(BSC)/fastArith.cpp

$(B)/mpBasicArith.o: $(BSC)/mpBasicArith.cpp
	$(CC) $(O1CFLAGS) -I$(SC) -I$(BSC) -c -o $(B)/mpBasicArith.o $(BSC)/mpBasicArith.cpp

$(B)/mpModArith.o: $(BSC)/mpModArith.cpp
	$(CC) $(O1CFLAGS) -I$(SC) -I$(BSC) -c -o $(B)/mpModArith.o $(BSC)/mpModArith.cpp

$(B)/mpNumTheory.o: $(BSC)/mpNumTheory.cpp
	$(CC) $(O1CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/mpNumTheory.o $(BSC)/mpNumTheory.cpp

$(B)/channel.o: $(CH)/channel.cpp $(CH)/channel.h
	$(CC) $(CFLAGS) -I$(SC) -I$(CH) -c -o $(B)/channel.o $(CH)/channel.cpp

$(B)/encryptedblockIO.o: $(SCC)/encryptedblockIO.cpp $(SCC)/encryptedblockIO.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(BSC) -c -o $(B)/encryptedblockIO.o $(SCC)/encryptedblockIO.cpp


