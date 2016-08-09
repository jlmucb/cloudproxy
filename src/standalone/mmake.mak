#

#
# Make the libmodp.a
#

#ifndef GOOGLE_INCLUDE
GOOGLE_INCLUDE=/usr/local/include/google
#endif
#ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
#endif

MS= $(S)/third_party/modp
INCLUDE= -I$(S) -I/usr/local/include -I$(GOOGLE_INCLUDE)

CFLAGS=$(INCLUDE) -DOS_POSIX -O3 -g -Wall -std=c++11 -Wno-strict-aliasing -Wno-deprecated # -DGFLAGS_NS=google
CFLAGS1=$(INCLUDE) -DOS_POSIX -O1 -g -Wall -std=c++11

CC=g++
LINK=g++
PROTO=protoc
AR=ar
export LD_LIBRARY_PATH=/usr/local/lib
LDFLAGS= -lprotobuf -lgtest -lgflags -lpthread -lglog -l$(LIBDEST)/libmodp.a -l$(LIBDEST)/libchromium.a

dobj_mlib=$(O)/.o 


all:	$(LIBDEST)/libmodp.o

clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing libmodp"
	rm $(LIBDEST)/libmodp.a

$(LIBDEST)/libmodp.o: $(dobj_mlib)
	@echo "linking libmodp.a"
	$(AR) -o $(LIBDEST)/libmodp.exe $(dobj_mlib) 

$(O)/xxx.o: $(MS)/xxx.cc
	@echo "compiling xxx.cc"
	$(CC) $(CFLAGS) -c -o $(O)/xxx.o $(MS)/xxx.cc

