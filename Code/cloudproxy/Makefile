CPPFLAGS=-Wall -Werror -std=c++0x -MMD
LDFLAGS=
LIBS=-lgflags -lglog -lkeyczar -lcrypto -lprotobuf -lssl
PROTOC=protoc
AR=ar
ARFLAG=rcu
RANLIB=ranlib

SRCS=cloud_auth.cc \
    cloud_server.cc \
    cloud_client.cc \
    cloud_user_manager.cc \
    cloudproxy.pb.cc \
    util.cc

OBJS=$(SRCS:.cc=.o)

default: client server acls_sig

all: default test sign_acls verify_acls sign_pub_key verify_pub_key

cloudproxy.pb.cc cloudproxy.pb.h: cloudproxy.proto
	protoc -I. --cpp_out=. cloudproxy.proto

test: cloudproxy.pb.h main.o cloudproxy.lib
	$(CC) -o test main.o cloudproxy.lib $(LIBS)

sign_acls: cloudproxy.pb.h sign_acls.o cloudproxy.lib
	$(CC) -o $@ sign_acls.o cloudproxy.lib $(LIBS)

verify_acls: cloudproxy.pb.h verify_acls.o cloudproxy.lib
	$(CC) -o $@ verify_acls.o cloudproxy.lib $(LIBS)

sign_pub_key: cloudproxy.pb.h sign_pub_key.o cloudproxy.lib
	$(CC) -o $@ sign_pub_key.o cloudproxy.lib $(LIBS)

verify_pub_key: cloudproxy.pb.h verify_pub_key.o cloudproxy.lib
	$(CC) -o $@ verify_pub_key.o cloudproxy.lib $(LIBS)

acls: acls.ascii cloudproxy.proto
	$(PROTOC) -I./ --encode=cloudproxy.ACL ./cloudproxy.proto <$< >$@

acls_sig: acls sign_acls
	./sign_acls --acl_file acls --acl_sig_file acls_sig

cloudproxy.lib: $(OBJS)
	$(AR) $(ARFLAGS) $@ $^
	$(RANLIB) $@

client: cloudproxy.pb.h client.o cloudproxy.lib
	$(CC) -o $@ client.o cloudproxy.lib $(LIBS)

server: cloudproxy.pb.h server.o cloudproxy.lib
	$(CC) -o $@ server.o cloudproxy.lib $(LIBS)

clean:
	rm -f *.o cloudproxy.pb.* test sign_acls acls acls_sig verify_acls
	rm -f sign_pub_key verify_pub_key cloudproxy.lib server client


distclean: clean
	rm -f *.d

-include $(OBJS:.o=.d)
