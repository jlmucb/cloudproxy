ifndef CPProgramDirectory
E=/home/jlm/jlmcrypt
else
E=	$(CPProgramDirectory)
endif

B=          $(E)/testKvmLaunchobjects
S=          .

DEBUG_CFLAGS     := -Wall -Werror -Wno-format -g -DDEBUG
RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3
O1RELEASE_CFLAGS   := -Wall -Werror -Wno-unknown-pragmas -Wno-format -O1
CFLAGS=     -D LINUX -D TEST -D TIXML_USE_STL $(RELEASE_CFLAGS)
LDFLAGS          := $(RELEASE_LDFLAGS)

CC=         g++
LINK=       g++

dobjs=      $(B)/testKvmLaunch.o 

all: $(E)/testKvmLaunch.exe

$(E)/testKvmLaunch.exe: $(dobjs)
	@echo "testKvmLaunch"
	$(LINK) -o $(E)/testKvmLaunch.exe $(dobjs) $(LDFLAGS)
$(B)/testKvmLaunch.o: $(S)/testKvmLaunch.cpp
	$(CC) $(CFLAGS) -D LINUXTCSERVICE -c -o $(B)/testKvmLaunch.o $(S)/testKvmLaunch.cpp

