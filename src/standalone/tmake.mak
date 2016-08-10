#

# Make libtao.a

#ifndef GOOGLE_INCLUDE
GOOGLE_INCLUDE=/usr/local/include/google
#endif
#ifndef LOCAL_LIB
LOCAL_LIB=/usr/local/lib
#endif

TS= $(SRC_DIR)/src/tao
LIBDEST=/Domains
INCLUDEDEST= $(LIBDEST)/include
LD_LIBRARY_PATH=/usr/local/lib
INCLUDE= -I$(SRC_DIR)/src -I$(TS) -I/usr/local/include -I$(GOOGLE_INCLUDE) -I$(INCLUDEDEST) -I/usr/local/ssl/include

CFLAGS=$(INCLUDE) -DOS_POSIX -O3 -g -Wall -std=c++11 -Wno-strict-aliasing -Wno-deprecated # -DGFLAGS_NS=google
CFLAGS1=$(INCLUDE) -DOS_POSIX -O1 -g -Wall -std=c++11

CC=g++
LINK=g++
PROTO=protoc
AR=ar

dobj_tlib=$(O)/message_channel.o $(O)/tao_rpc.o $(O)/fd_message_channel.o \
$(O)/util.o $(O)/tao_rpc.pb.o $(O)/tao_rpc.pb.o

all: $(LIBDEST)/libtao.a

clean:
	@echo "removing object files"
	rm $(O)/*.o
	@echo "removing libtao.a"
	rm $(LIBDEST)/libtao.a

$(LIBDEST)/libtao.a: $(dobj_tlib)
	@echo "linking tao library"
	$(AR) -r $(LIBDEST)/libtao.a  $(dobj_tlib) 

$(O)/message_channel.o: $(TS)/message_channel.cc
	@echo "compiling message_channel.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/message_channel.o $(TS)/message_channel.cc

$(O)/tao_rpc.pb.o: $(TS)/tao_rpc.pb.cc
	@echo "proto"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/tao_rpc.pb.o $(TS)/tao_rpc.pb.cc

$(TS)/tao_rpc.pb.cc: $(TS)/tao_rpc.proto
	@echo "proto"
	$(PROTOC) --cpp_out=$(TS) $(TS)/tao_rpc.proto

$(O)/tao_rpc.o: $(TS)/tao_rpc.cc
	@echo "compiling tao_rpc.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/tao_rpc.o $(TS)/tao_rpc.cc

$(O)/fd_message_channel.o: $(TS)/fd_message_channel.cc
	@echo "compiling fd_message_channel.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/fd_message_channel.o $(TS)/fd_message_channel.cc

$(O)/util.o: $(TS)/util.cc
	@echo "compiling util.cc"
	$(CC) $(CFLAGS) $(INCLUDE) -c -o $(O)/util.o $(TS)/util.cc

