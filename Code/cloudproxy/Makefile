CPPFLAGS=-Wall -Werror -std=c++0x -MMD
LDFLAGS=
LIBS=-lgflags -lglog -lkeyczar -lcrypto -lprotobuf
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

all: cloudproxy.lib

cloudproxy.pb.cc cloudproxy.pb.h: cloudproxy.proto
	protoc -I. --cpp_out=. cloudproxy.proto

test: cloudproxy.pb.o main.o 
	$(CC) -o $@ $^ $(LIBS)

sign_acls: cloudproxy.pb.o sign_acls.o 
	$(CC) -o $@ $^ $(LIBS)

verify_acls: cloudproxy.pb.o verify_acls.o  
	$(CC) -o $@ $^ $(LIBS)

sign_pub_key: cloudproxy.pb.o sign_pub_key.o 
	$(CC) -o $@ $^ $(LIBS)

verify_pub_key: cloudproxy.pb.o verify_pub_key.o 
	$(CC) -o $@ $^ $(LIBS)

acls: acls.ascii cloudproxy.proto
	$(PROTOC) -I./ --encode=cloudproxy.ACL ./cloudproxy.proto <$< >$@

acls_sig: acls sign_acls
	./sign_acls --acl_file acls --acl_sig_file acls_sig

cloudproxy.lib: $(OBJS)
	$(AR) $(ARFLAGS) $@ $^
	$(RANLIB) $@

clean:
	rm -f *.o cloudproxy.pb.* test sign_acls acls acls_sig verify_acls
	rm -f sign_pub_key verify_pub_key cloudproxy.lib

-include $(OBJS:.o=.d)
