CPPFLAGS=-Wall -Werror -std=c++0x
LDFLAGS=-lgflags -lglog -lkeyczar -lcrypto -lprotobuf
PROTOC=protoc

all: test

cloudproxy.pb.cc: cloudproxy.proto
	protoc -I. --cpp_out=. cloudproxy.proto

test: cloudproxy.pb.o main.o 
	$(CC) -o $@ $^ $(LDFLAGS)

sign_acls: sign_acls.o cloudproxy.pb.o
	$(CC) -o $@ $^ $(LDFLAGS)

verify_acls: verify_acls.o cloudproxy.pb.o
	$(CC) -o $@ $^ $(LDFLAGS)

acls: acls.ascii cloudproxy.proto
	$(PROTOC) -I./ --encode=cloudproxy.ACL ./cloudproxy.proto <$< >$@

acls_sig: acls sign_acls
	./sign_acls --acl_file acls --acl_sig_file acls_sig

clean:
	rm -f *.o cloudproxy.pb.* test sign_acls acls acls_sig verify_acls
