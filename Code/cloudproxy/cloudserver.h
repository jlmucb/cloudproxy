#ifndef CLOUDSERVER_H_
#define CLOUDSERVER_H_

#include "cloudproxy.pb.h"
#include "cloudauth.h"
#include "util.h"
#include <openssl/ssl.h>
#include <keyczar/openssl/util.h>

#include <string>
#include <set>

using std::string;
using std::set;

namespace cloudproxy {

// A server that handles requests from a CloudClient (and a base class for all
// such servers). This class handles requests from a CloudClient and checks its
// ACL database to see if the operations is authorized by CloudProxy policy.
class CloudServer {
  public:
    // Creates a CloudServer with a given key store, location of its (encrypted
    // and integrity-protected) ACL database, and the port on which to listen.
    CloudServer(const string &tls_key_location, 
		const string &public_policy_key,
		const string &acl_location,
                ushort port);

    virtual ~CloudServer();

    // start listening to the port and handle connections as they arrive
    bool Listen();

  protected:
    // Handles specific requests for resources. In this superclass
    // implementation, it just deals with names in a std::set. Subclasses
    // override these methods to implement their functionality
    virtual bool HandleCreate(const Action &action);
    virtual bool HandleDestroy(const Action &action);
    virtual bool HandleWrite(const Action &action);
    virtual bool HandleRead(const Action &action);


  private:

    // handles an incoming message from a client
    bool HandleMessage(const ClientMessage &message);
    bool HandleAuth(const Action &action);

    // a context object that stores all the TLS parameters for the connection
    ScopedSSLCtx context_;

    // the main BIO set up for this connection
    keyczar::openssl::ScopedBIO bio_;

    // an accept BIO that listens on the TLS connection
    keyczar::openssl::ScopedBIO abio_;

    // an object that manages an ACL for requests from the client
    CloudAuth auth_;

    // a simple object management tool: a set of object names
    set<string> objects_;
};
}

#endif // CLOUDSERVER_H_
