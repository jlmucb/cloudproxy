CC=g++
AR=ar
ARFLAGS=rcu
LDFLAGS=-lpthread -lm
INCLUDES=-IcommonCode -Ijlmbignum -Ijlmcrypto
DEBUG_CFLAGS=-g -DDEBUG
RELEASE_CFLAGS=-O3 -Wno-unknown-pragmas
CFLAGS=-c $(INCLUDES) -Wall -Werror -Wno-format -DLINUX -DTEST -D__FLUSHIO__ $(DEBUG_CFLAGS)
OBJS=obj
TEST=test
LIB=lib
OBJROOT=/home/tmroeder/jlmcrypt

BIGNUM_SOURCE=jlmbignum/mpBasicArith.cpp \
		jlmbignum/mpModArith.cpp \
		jlmbignum/mpNumTheory.cpp \
		jlmbignum/mpRand.cpp
BIGNUM_OBJ=$(BIGNUM_SOURCE:%.cpp=obj/%.o)

COMMON_SOURCE=commonCode/jlmUtility.cpp \
		commonCode/logging.cpp \
		commonCode/tinystr.cpp \
		commonCode/tinyxml.cpp \
		commonCode/tinyxmlerror.cpp \
		commonCode/tinyxmlparser.cpp
COMMON_OBJ=$(COMMON_SOURCE:%.cpp=obj/%.o)

CRYPTO_SOURCE=jlmcrypto/encryptedblockIO.cpp \
		jlmcrypto/fileHash.cpp \
		jlmcrypto/hmacsha256.cpp \
		jlmcrypto/jlmcrypto.cpp \
		jlmcrypto/keys.cpp \
		jlmcrypto/modesandpadding.cpp \
		jlmcrypto/rsaHelper.cpp \
		jlmcrypto/sha1.cpp \
		jlmcrypto/sha256.cpp \
		jlmcrypto/aes.cpp \
		jlmcrypto/aesni.cpp
CRYPTO_OBJ=$(CRYPTO_SOURCE:%.cpp=obj/%.o)

TESTS=tests/encryptedBlockIOTest
LIBS=$(LIB)/jlmbignum.a $(LIB)/commonCode.a $(LIB)/jlmcrypto.a 
LIB_SOURCES=$(COMMON_SOURCE) $(CRYPTO_SOURCE)

.PHONY: keyNegoServer tcService fileServer fileClient cryptUtility cryptotest aesspeed rsaspeedtest clean libs tests

all: keyNegoServer tcService fileServer fileClient cryptUtility cryptotest aesspeed rsaspeedtest

libs: $(LIB_SOURCES) $(LIBS)

tests: $(TESTS)

$(LIB)/jlmbignum.a: $(BIGNUM_OBJ)
	$(AR) $(ARFLAGS) $@ $(BIGNUM_OBJ)

$(LIB)/commonCode.a: $(COMMON_OBJ)
	$(AR) $(ARFLAGS) $@ $(COMMON_OBJ)

$(LIB)/jlmcrypto.a: $(CRYPTO_OBJ)
	$(AR) $(ARFLAGS) $@ $(CRYPTO_OBJ)

obj/%.o: %.cpp
	$(CC) $(CFLAGS) $< -o $@

tests/encryptedBlockIOTest: obj/Test/encryptedBlockIOTest.o $(LIB)/jlmcrypto.a $(LIB)/jlmbignum.a $(LIB)/commonCode.a
	$(CC) $^ -o $@ $(LDFLAGS)

tcService:
	$(MAKE) -C tcService -f tcService.mak

fileServer:
	$(MAKE) -C fileProxy -f fileServer.mak

fileClient:
	$(MAKE) -C fileProxy -f fileClient.mak

keyNegoServer:
	$(MAKE) -C keyNegoServer -f keyNegoServer.mak

cryptUtility:
	$(MAKE) -C cryptUtility -f cryptUtility.mak

cryptotest:
	$(MAKE) -C Test -f cryptotest.mak

aesspeed:
	$(MAKE) -C Test -f aesspeed.mak

rsaspeedtest:
	$(MAKE) -C Test -f rsaspeedtest.mak

clean:
	rm -f $(TESTS)
	rm -f $(CRYPTO_OBJ) $(COMMON_OBJ) $(BIGNUM_OBJ)
	rm -f $(LIBS)
	rm -f $(OBJROOT)/*objects/*
	rm -f $(OBJROOT)/*.o
	rm -f $(OBJROOT)/keyNegoServer.exe
	rm -f $(OBJROOT)/tcService.exe
	rm -f $(OBJROOT)/fileServer.exe
	rm -f $(OBJROOT)/fileClient.exe
	rm -f $(OBJROOT)/rsaspeedtest.exe
	rm -f $(OBJROOT)/cryptUtility.exe
	rm -f $(OBJROOT)/aesspeedtest.exe
