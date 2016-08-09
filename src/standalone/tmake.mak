#

#
# Make libtao.a
#

#ifndef GOOGLE_INCLUDE
GOOGLE_INCLUDE=/usr/local/include/google
#endif
#ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
#endif

INCLUDE= -I$(S) -I/usr/local/include -I$(GOOGLE_INCLUDE) -I$(SL) -I/usr/local/ssl/include
TS= $(SRC_DIR)/src/github.com/jlmucb/cloudproxy/src/tao

LIBDEST=/Domains
INCLUDEDEST= $(S)/include

CFLAGS=$(INCLUDE) -DOS_POSIX -O3 -g -Wall -std=c++11 -Wno-strict-aliasing -Wno-deprecated # -DGFLAGS_NS=google
CFLAGS1=$(INCLUDE) -DOS_POSIX -O1 -g -Wall -std=c++11

CC=g++
LINK=g++
PROTO=protoc
AR=ar
export LD_LIBRARY_PATH=/usr/local/lib

dobj_tlib=$(O)/.o 


all:$(LIBDEST)/libtao.o	

clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing libtao.a"
	rm $(LIBDEST)/libtao.a

$(LIBDEST)/libtao.o: $(dobj_tlib)
	@echo "linking tao library"
	$(AR) -o $(LIBDEST)/libtao.a  $(dobj_tlib) 

$(O)/xxx.o: $(TS)/xxx.cc
	@echo "compiling xxx.cc"
	$(CC) $(CFLAGS) -c -o $(O)/xxx.o $(TS)/xxx.cc
