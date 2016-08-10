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

LIBDEST=/Domains
INCLUDEDEST= $(LIBDEST)/include
CS= $(SRC_DIR)/src/third_party/chromium/src/base
INCLUDE= -I$(CS) -I/usr/local/include -I$(GOOGLE_INCLUDE) -I$(INCLUDEDEST) -I$(INCLUDEDEST)/chromium

CFLAGS=$(INCLUDE) -DOS_POSIX -O3 -g -Wall -std=c++11 -Wno-strict-aliasing -Wno-deprecated # -DGFLAGS_NS=google
CFLAGS1=$(INCLUDE) -DOS_POSIX -O1 -g -Wall -std=c++11

CC=g++
LINK=g++
PROTO=protoc
AR=ar
export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread -lcrypto -lssl -lchromium -lglog -lmodp

dobj_clib= $(O)/file_path_constants.o $(O)/file_util_posix.o $(O)/file_path.o $(O)/file_util.o 


all:	$(LIBDEST)/libchromium.a

clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing libchromium.a"
	rm $(LIBDEST)/libchromium.a

$(LIBDEST)/libchromium.a: $(dobj_clib)
	@echo "linking libchromium.a"
	$(AR) -r $(LIBDEST)/libchromium.a $(dobj_clib) 

$(O)/file_path_constants.o: $(CS)/file_path_constants.cc
	@echo "compiling file_path_constants.cc"
	echo "$(CC) $(CFLAGS) -c -o $(O)/file_path_constants.o $(CS)/file_path_constants.cc"
	$(CC) $(CFLAGS) -c -o $(O)/file_path_constants.o $(CS)/file_path_constants.cc

$(O)/file_util_posix.o: $(CS)/file_util_posix.cc
	@echo "compiling file_util_posix.cc"
	$(CC) $(CFLAGS) -c -o $(O)/file_util_posix.o $(CS)/file_util_posix.cc

$(O)/file_path.o: $(CS)/file_path.cc
	@echo "compiling file_path.cc"
	$(CC) $(CFLAGS) -c -o $(O)/file_path.o $(CS)/file_path.cc

$(O)/file_util.o: $(CS)/file_util.cc
	@echo "compiling file_util.cc"
	$(CC) $(CFLAGS) -c -o $(O)/file_util.o $(CS)/file_util.cc

