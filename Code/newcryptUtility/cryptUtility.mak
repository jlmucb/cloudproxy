E=          ~/jlmcrypt
B=          ~/jlmcrypt/newcryptUtilityobjects
S=          ../newcryptUtility
SC=         ../commonCode
SCD=	    ../newjlmcrypto
SBM=	    ../jlmbignum
TPM=	    ../TPMDirect
CLM=	    ../newclaims
TAO=	    ../tao

DEBUG_CFLAGS     := -Wall -Wno-format -g -DDEBUG
RELEASE_CFLAGS   := -Wall -Wno-unknown-pragmas -Wno-format -O3
LDFLAGSXML      := ${RELEASE_LDFLAGS}
CFLAGS=	    -D TEST  -D NOAESNI $(DEBUG_CFLAGS) -D TEST -D QUOTE2_DEFINED
CFLAGS1=    -D TEST -D NOAESNI -Wall -Wno-unknown-pragmas -Wno-format -O1

CC=         g++
LINK=       g++

dobjs=      $(B)/cryptUtility.o $(B)/logging.o $(B)/jlmcrypto.o $(B)/aes.o \
	    $(B)/sha256.o $(B)/modesandpadding.o $(B)/hmacsha256.o $(B)/encapsulate.o \
	    $(B)/keys.o $(B)/sha1.o $(B)/hashprep.o $(B)/jlmUtility.o \
	    $(B)/cert.o $(B)/quote.o \
	    $(B)/cryptoHelper.o $(B)/fastArith.o $(B)/mpBasicArith.o $(B)/mpModArith.o \
	    $(B)/mpNumTheory.o  $(B)/fileHash.o $(B)/tinystr.o $(B)/tinyxmlerror.o \
	    $(B)/tinyxml.o $(B)/tinyxmlparser.o 

all: $(E)/newcryptUtility.exe

$(E)/newcryptUtility.exe: $(dobjs)
	@echo "newcryptUtility"
	$(LINK) -o $(E)/newcryptUtility.exe $(dobjs) -lpthread

$(B)/logging.o: $(SC)/logging.cpp $(SC)/logging.h 
	$(CC) $(CFLAGS) -I$(SC) -I$(SBM) -c -o $(B)/logging.o $(SC)/logging.cpp

$(B)/jlmUtility.o: $(SC)/jlmUtility.cpp $(SC)/jlmUtility.h 
	$(CC) $(CFLAGS) -I$(SC) -I$(SBM) -I$(SCD) -c -o $(B)/jlmUtility.o $(SC)/jlmUtility.cpp

$(B)/cryptUtility.o: $(S)/cryptUtility.cpp $(S)/cryptUtility.h $(SCD)/jlmcrypto.h $(SCD)/keys.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(SCD) -I$(CLM) -I$(SBM) -I $(TPM) -c -o $(B)/cryptUtility.o $(S)/cryptUtility.cpp

$(B)/hashprep.o: $(TPM)/hashprep.cpp $(TPM)/hashprep.h
	$(CC) $(CFLAGS) -D TEST -I$(SC) -I$(SCD) -I$(TPM) -c -o $(B)/hashprep.o $(TPM)/hashprep.cpp

$(B)/aes.o: $(SCD)/aes.cpp $(SCD)/aes.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -c -o $(B)/aes.o $(SCD)/aes.cpp

$(B)/aesni.o: $(SCD)/aesni.cpp $(SCD)/aesni.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -c -o $(B)/aesni.o $(SCD)/aesni.cpp

$(B)/sha1.o: $(SCD)/sha1.cpp $(SCD)/sha1.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(SBM) -c -o $(B)/sha1.o $(SCD)/sha1.cpp

$(B)/sha256.o: $(SCD)/sha256.cpp $(SCD)/sha256.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(SBM) -c -o $(B)/sha256.o $(SCD)/sha256.cpp

$(B)/hmacsha256.o: $(SCD)/hmacsha256.cpp $(SCD)/hmacsha256.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(SBM) -c -o $(B)/hmacsha256.o $(SCD)/hmacsha256.cpp

$(B)/encapsulate.o: $(SCD)/encapsulate.cpp $(SCD)/encapsulate.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(SBM) -c -o $(B)/encapsulate.o $(SCD)/encapsulate.cpp

$(B)/fastArith.o: $(SBM)/fastArith.cpp
	$(CC) $(CFLAGS1) -I$(SC) -I$(SBM) -c -o $(B)/fastArith.o $(SBM)/fastArith.cpp

$(B)/mpBasicArith.o: $(SBM)/mpBasicArith.cpp
	$(CC) $(CFLAGS1) -I$(SC) -I$(SBM) -c -o $(B)/mpBasicArith.o $(SBM)/mpBasicArith.cpp

$(B)/mpModArith.o: $(SBM)/mpModArith.cpp
	$(CC) $(CFLAGS) -I$(SC) -I$(SBM) -c -o $(B)/mpModArith.o $(SBM)/mpModArith.cpp

$(B)/mpNumTheory.o: $(SBM)/mpNumTheory.cpp
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(SBM) -c -o $(B)/mpNumTheory.o $(SBM)/mpNumTheory.cpp

$(B)/keys.o: $(SCD)/keys.cpp $(SCD)/keys.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(SBM) -c -o $(B)/keys.o $(SCD)/keys.cpp

$(B)/jlmcrypto.o: $(SCD)/jlmcrypto.cpp $(SCD)/jlmcrypto.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(SBM) -c -o $(B)/jlmcrypto.o $(SCD)/jlmcrypto.cpp

$(B)/modesandpadding.o: $(SCD)/modesandpadding.cpp $(SCD)/modesandpadding.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(SBM) -c -o $(B)/modesandpadding.o $(SCD)/modesandpadding.cpp

$(B)/fileHash.o: $(SCD)/fileHash.cpp $(SCD)/fileHash.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -c -o $(B)/fileHash.o $(SCD)/fileHash.cpp

$(B)/cryptoHelper.o: $(SCD)/cryptoHelper.cpp $(SCD)/cryptoHelper.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(SBM) -c -o $(B)/cryptoHelper.o $(SCD)/cryptoHelper.cpp

$(B)/tinyxml.o : $(SC)/tinyxml.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxml.o $(SC)/tinyxml.cpp

$(B)/tinyxmlparser.o : $(SC)/tinyxmlparser.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxmlparser.o $(SC)/tinyxmlparser.cpp

$(B)/tinyxmlerror.o : $(SC)/tinyxmlerror.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinyxmlerror.o $(SC)/tinyxmlerror.cpp

$(B)/tinystr.o : $(SC)/tinystr.cpp $(SC)/tinyxml.h $(SC)/tinystr.h
	$(CC) $(CFLAGS) $(RELEASECFLAGS) -I$(SC) -c -o $(B)/tinystr.o $(SC)/tinystr.cpp

$(B)/cert.o: $(CLM)/cert.cpp $(CLM)/cert.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(SBM) -c -o $(B)/cert.o $(CLM)/cert.cpp

$(B)/quote.o: $(CLM)/quote.cpp $(CLM)/quote.h
	$(CC) $(CFLAGS) -I$(SC) -I$(SCD) -I$(TAO) -I$(TPM) -I$(SBM) -c -o $(B)/quote.o $(CLM)/quote.cpp

