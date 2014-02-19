
ifndef CPProgramDirectory
E=              /home/jlm/jlmcrypt
else
E=              $(CPProgramDirectory)
endif
ifndef CryptoSourceDirectory
S=              /home/jlm/fpDev/fileProxy/src/cpcrypto
else
S=              $(CryptoSourceDirectory)
endif
ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

# compile cloudproxy crypto library
mainsrc=        $(S)
B=              $(E)/sha256speedtestobjects
INCLUDES=       -I$(S) -I$(S)/bignum -I$(S)/symmetric -I$(S)/ecc \
                -I$(S)/support -I$(s)/Test 
DEBUG_CFLAGS     := -Wall -Wno-format -g -DDEBUG
CFLAGS   := -Wall -Wno-unknown-pragmas -Wno-format -O3 -D NOAESNI -D FAST -D TEST
CFLAGS1   := -Wall -Wno-unknown-pragmas -Wno-format  -O3 -D NOAESNI -D FAST -D TEST
LDFLAGSXML      := ${RELEASE_LDFLAGS}

CC=         g++
LINK=       g++


dobjs=      $(B)/sha256speedtest.o

all: $(E)/sha256speedtest.exe

$(E)/sha256speedtest.exe: $(dobjs) $(E)/cpcryptolib.a
	@echo "sha256speedtest"
	$(LINK) -o $(E)/sha256speedtest.exe $(dobjs) $(E)/cpcryptolib.a

$(B)/sha256speedtest.o: sha256speedtest.cc 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(B)/sha256speedtest.o sha256speedtest.cc

