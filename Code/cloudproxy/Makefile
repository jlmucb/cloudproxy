CPPFLAGS=-Wall -Werror -std=c++0x
LDFLAGS=-lgflags -lglog -lkeyczar -lcrypto -lprotobuf

all: test

cloudproxy.pb.cc: cloudproxy.proto
	protoc -I. --cpp_out=. cloudproxy.proto

test: cloudproxy.pb.o main.o 
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f *.o cloudproxy.pb.* test