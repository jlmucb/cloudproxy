#

#
# Make libchromium.a
#

#ifndef GOOGLE_INCLUDE
GOOGLE_INCLUDE=/usr/local/include/google
#endif
#ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
#endif

CS= $(SRC_DIR)/src/github.com/jlmucb/cloudproxy/src/third_party/chromium/base
O= $(OBJ_DIR)/tao_clib
INCLUDE= -I$(S) -I/usr/local/include -I$(GOOGLE_INCLUDE)

LIBDEST=/Domains
INCLUDEDEST= $(S)/include

CFLAGS=$(INCLUDE) -DOS_POSIX -O3 -g -Wall -std=c++11 -Wno-strict-aliasing -Wno-deprecated # -DGFLAGS_NS=google
CFLAGS1=$(INCLUDE) -DOS_POSIX -O1 -g -Wall -std=c++11

CC=g++
LINK=g++
PROTO=protoc
AR=ar
export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread -lcrypto -lssl -lchromium -lglog -lmodp

dobj_clib=$(O)/.o 


all:	$(LIBDEST)/libchromium.a

clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing libchromium.a"
	rm $(LIBDEST)/libchromium.a

$(LIBDEST)/libchromium.o: $(dobj_clib)
	@echo "linking libchromium.a"
	$(AR) -o $(EXE_DIR)/libchromium.a $(dobj_alib) 

$(O)/xxx.o: $(CS)/xxx.cc
	@echo "compiling xxx.cc"
	$(CC) $(CFLAGS) -c -o $(O)/xxx.o $(CS)/xxx.cc

