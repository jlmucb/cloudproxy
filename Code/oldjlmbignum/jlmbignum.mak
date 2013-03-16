B=          ~/jlmcrypt
S=          ../jmbignum
##MSSDK=      "/cygdrive/c/Program Files/Microsoft SDKs/Windows/v7.1/lib"
CFLAGS=	    
RFLAGS=	    -D "UNIXRANDBITS"

CC=         g++
LINK=       g++

dobjs=      $(B)/mpBasicArith.o $(B)/mpModArith.o $(B)/mpNumTheory.o \
            $(B)/mpRand.o $(B)/mpTest.o 

all: $(B)/mpTest.exe
$(B)/mpTest.exe: $(dobjs)
	@echo "mpTest"
	$(LINK) -o $(B)/mpTest.exe $(dobjs)

$(B)/mpBasicArith.o: mpBasicArith.cpp
	$(CC) $(CFLAGS) -c -o $(B)/mpBasicArith.o $(S)/mpBasicArith.cpp
$(B)/mpModArith.o: mpModArith.cpp
	$(CC) $(CFLAGS) -c -o $(B)/mpModArith.o $(S)/mpModArith.cpp
$(B)/mpNumTheory.o: mpNumTheory.cpp
	$(CC) $(CFLAGS) -c -o $(B)/mpNumTheory.o $(S)/mpNumTheory.cpp
$(B)/mpRand.o: mpRand.cpp
	$(CC) $(RFLAGS) $(CFLAGS) -c -o $(B)/mpRand.o $(S)/mpRand.cpp
$(B)/mpTest.o: mpTest.cpp
	$(CC) $(CFLAGS) -c -o $(B)/mpTest.o $(S)/mpTest.cpp
