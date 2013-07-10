CPPFLAGS=-Wall -Werror -std=c++0x -MMD
LDFLAGS=
LIBS=-lgflags -lglog -lkeyczar -lcrypto -lprotobuf
PROTOC=protoc
AR=ar
ARFLAG=rcu

SRCS=cloud_auth.cc \
    cloud_server.cc \
    cloud_user_manager.cc \
    cloudproxy.pb.cc

OBJS=$(SRCS:.cc=.o)

all: test sign_acls verify_acls acls acls_sig sign_pub_key verify_pub_key cloudserver

cloudproxy.pb.cc: cloudproxy.proto
	protoc -I. --cc_out=. cloudproxy.proto

test: cloudproxy.pb.o main.o 
	$(CC) -o $@ $^ $(LDFLAGS)

sign_acls: sign_acls.o cloudproxy.pb.o
	$(CC) -o $@ $^ $(LDFLAGS)

verify_acls: verify_acls.o cloudproxy.pb.o
	$(CC) -o $@ $^ $(LDFLAGS)

sign_pub_key: sign_pub_key.o cloudproxy.pb.o
	$(CC) -o $@ $^ $(LDFLAGS)

verify_pub_key: verify_pub_key.o cloudproxy.pb.o
	$(CC) -o $@ $^ $(LDFLAGS)

acls: acls.ascii cloudproxy.proto
	$(PROTOC) -I./ --encode=cloudproxy.ACL ./cloudproxy.proto <$< >$@

acls_sig: acls sign_acls
	./sign_acls --acl_file acls --acl_sig_file acls_sig

cloudproxy.lib: $(OBJS)
	$(AR) $(ARFLAGS) $@ $^

clean:
	rm -f *.o cloudproxy.pb.* test sign_acls acls acls_sig verify_acls sign_pub_key verify_pub_key

-include $(OBJS:.o=.d)
