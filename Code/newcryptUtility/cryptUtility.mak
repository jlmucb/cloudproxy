E=          ~/jlmcrypt
B=          ~/jlmcrypt/newcryptUtilityobjects
S=          ../newcryptUtility
SC=         ../commonCode
SCC=	    ../jlmcrypto
SCD=	    ../newjlmcrypto
SBM=	    ../jlmbignum
TPM=	    ../TPMDirect

DEBUG_CFLAGS     := -Wall -Wno-format -g -DDEBUG
RELEASE_CFLAGS   := -Wall -Wno-unknown-pragmas -Wno-format -O3
LDFLAGSXML      := ${RELEASE_LDFLAGS}
CFLAGS=	    -D TEST  -D NOAESNI $(DEBUG_CFLAGS)
CFLAGS1=    -D TEST -D NOAESNI -Wall -Wno-unknown-pragmas -Wno-format -O1

CC=         g++
LINK=       g++

dobjs=      $(B)/cryptUtility.o $(B)/logging.o $(B)/jlmcrypto.o $(B)/aes.o \
	    $(B)/sha256.o $(B)/modesandpadding.o $(B)/hmacsha256.o $(B)/encapsulate.o \
	    $(B)/keys.o $(B)/cryptSupport.o $(B)/sha1.o $(B)/hashprep.o \
            $(B)/jlmUtility.o $(B)/cryptoHelper.o $(B)/fastArith.o \
	    $(B)/mpBasicArith.o $(B)/mpModArith.o $(B)/mpNumTheory.o  \
	    $(B)/fileHash.o $(B)/tinystr.o $(B)/tinyxmlerror.o \
	    $(B)/tinyxml.o $(B)/tinyxmlparser.o 

all: $(E)/newcryptUtility.exe

$(E)/newcryptUtility.exe: $(dobjs)
	@echo "newcryptUtility"
	$(LINK) -o $(E)/newcryptUtility.exe $(dobjs) -lpthread

$(B)/logging.o: $(SC)/logging.cpp $(SC)/logging.h 
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/logging.o $(SC)/logging.cpp

$(B)/jlmUtility.o: $(SC)/jlmUtility.cpp $(SC)/jlmUtility.h 
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/jlmUtility.o $(SC)/jlmUtility.cpp

$(B)/cryptUtility.o: $(S)/cryptUtility.cpp $(S)/cryptUtility.h $(SCC)/jlmcrypto.h $(SCC)/keys.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -I $(TPM) -c -o $(B)/cryptUtility.o $(S)/cryptUtility.cpp

$(B)/cryptSupport.o: $(S)/cryptSupport.cpp $(S)/cryptSupport.h $(SCC)/jlmcrypto.h $(SCC)/keys.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(SCC) -I$(SBM) -I$(TPM) -c -o $(B)/cryptSupport.o $(S)/cryptSupport.cpp

$(B)/hashprep.o: $(TPM)/hashprep.cpp $(TPM)/hashprep.h
	$(CC) $(CFLAGS) -D TEST -I$(SC) -I$(SCC) -I$(TPM) -c -o $(B)/hashprep.o $(TPM)/hashprep.cpp

$(B)/aes.o: $(SCC)/aes.cpp $(SCC)/aes.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SCC) -c -o $(B)/aes.o $(SCC)/aes.cpp

$(B)/aesni.o: $(SCC)/aesni.cpp $(SCC)/aesni.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -c -o $(B)/aesni.o $(SCC)/aesni.cpp

$(B)/sha1.o: $(SCC)/sha1.cpp $(SCC)/sha1.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/sha1.o $(SCC)/sha1.cpp

$(B)/sha256.o: $(SCC)/sha256.cpp $(SCC)/sha256.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/sha256.o $(SCC)/sha256.cpp

$(B)/hmacsha256.o: $(SCC)/hmacsha256.cpp $(SCC)/hmacsha256.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/hmacsha256.o $(SCC)/hmacsha256.cpp

$(B)/encapsulate.o: $(SCC)/encapsulate.cpp $(SCC)/encapsulate.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/encapsulate.o $(SCC)/encapsulate.cpp

$(B)/fastArith.o: $(SBM)/fastArith.cpp
	$(CC) $(CFLAGS1) -I$(SC) -I$(SBM) -c -o $(B)/fastArith.o $(SBM)/fastArith.cpp

$(B)/mpBasicArith.o: $(SBM)/mpBasicArith.cpp
	$(CC) $(CFLAGS1) -I$(SC) -I$(SBM) -c -o $(B)/mpBasicArith.o $(SBM)/mpBasicArith.cpp

$(B)/mpModArith.o: $(SBM)/mpModArith.cpp
	$(CC) $(CFLAGS) -I$(SC) -I$(SBM) -c -o $(B)/mpModArith.o $(SBM)/mpModArith.cpp

$(B)/mpNumTheory.o: $(SBM)/mpNumTheory.cpp
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/mpNumTheory.o $(SBM)/mpNumTheory.cpp

$(B)/keys.o: $(SCC)/keys.cpp $(SCC)/keys.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/keys.o $(SCC)/keys.cpp

$(B)/jlmcrypto.o: $(SCC)/jlmcrypto.cpp $(SCC)/jlmcrypto.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -I$(SBM) -c -o $(B)/jlmcrypto.o $(SCC)/jlmcrypto.cpp

$(B)/modesandpadding.o: $(SCD)/modesandpadding.cpp $(SCD)/modesandpadding.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(SCC) -I$(SBM) -c -o $(B)/modesandpadding.o $(SCD)/modesandpadding.cpp

$(B)/fileHash.o: $(SCC)/fileHash.cpp $(SCC)/fileHash.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCC) -c -o $(B)/fileHash.o $(SCC)/fileHash.cpp

$(B)/cryptoHelper.o: $(SCD)/cryptoHelper.cpp $(SCD)/cryptoHelper.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(SCC) -I$(SBM) -c -o $(B)/cryptoHelper.o $(SCD)/cryptoHelper.cpp

$(B)/tinyxml.o : $(SC)/tinyxml.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxml.o $(SC)/tinyxml.cpp

$(B)/tinyxmlparser.o : $(SC)/tinyxmlparser.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxmlparser.o $(SC)/tinyxmlparser.cpp

$(B)/tinyxmlerror.o : $(SC)/tinyxmlerror.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxmlerror.o $(SC)/tinyxmlerror.cpp

$(B)/tinystr.o : $(SC)/tinystr.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinystr.o $(SC)/tinystr.cpp

$(E)/canonical.exe: $(cobjs)
	@echo "canonical"
	$(LINK) -o $(E)/canonical.exe $(cobjs)

$(B)/canonical.o : $(S)/canonical.cpp
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/canonical.o $(S)/canonical.cpp

