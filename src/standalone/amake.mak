#

#
# Make libauth.a
#

#ifndef GOOGLE_INCLUDE
GOOGLE_INCLUDE=/usr/local/include/google
#endif
#ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
#endif

AS= $(S)
INCLUDE= -I$(S) -I/usr/local/include -I$(GOOGLE_INCLUDE)

CFLAGS=$(INCLUDE) -DOS_POSIX -O3 -g -Wall -std=c++11 -Wno-strict-aliasing -Wno-deprecated # -DGFLAGS_NS=google
CFLAGS1=$(INCLUDE) -DOS_POSIX -O1 -g -Wall -std=c++11

CC=g++
LINK=g++
PROTO=protoc
AR=ar
export LD_LIBRARY_PATH=/usr/local/lib

dobj_alib=$(O)/.o 

all: $(LIBDEST)/libauth.a

clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing libauth.a"
	rm $(LIBDEST)/libauth.a

$(LIBDEST)/libauth.o: $(dobj_tlib)
	@echo "linking libauth.a"
	$(AR) -o $(LIBDEST)/libauth.a $(dobj_alib) 

$(O)/xxx.o: $(AS)/xxx.cc
	@echo "compiling xxx.cc"
	$(CC) $(CFLAGS) -c -o $(O)/xxx.o $(AS)/xxx.cc
