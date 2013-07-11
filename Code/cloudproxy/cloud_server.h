#ifndef CLOUDPROXY_CLOUD_SERVER_H_
#define CLOUDPROXY_CLOUD_SERVER_H_

#include "cloudproxy.pb.h"
#include "cloud_auth.h"
#include "cloud_user_manager.h"
#include "util.h"
#include <openssl/ssl.h>
#include <keyczar/openssl/util.h>
#include <keyczar/base/scoped_ptr.h>
#include <keyczar/crypto_factory.h>
#include <keyczar/keyczar.h>
#include <pthread.h>

#include <map>
#include <mutex>
#include <thread>
#include <string>
#include <set>

using std::map;
using std::mutex;
using std::thread;
using std::set;
using std::string;

namespace cloudproxy {

// A server that handles requests from a CloudClient (and a base class for all
// such servers). This class handles requests from a CloudClient and checks its
// ACL database to see if the operations is authorized by CloudProxy policy.
class CloudServer {
  public:
    static const int NonceSize = 16;

    // Creates a CloudServer with a given key store, location of its signed ACL
    // database, and the port on which to listen. It also needs the location of
    // the public policy key in two ways: one as a PEM file for use in TLS, and
    // one as public RSA keyczar directory
    CloudServer(const string &tls_cert,
		const string &tls_key,
		const string &tls_password,
		const string &public_policy_keyczar,
		const string &public_policy_pem,
		const string &acl_location,
		const string &server_key_location,
		const string &host,
		ushort port);

    virtual ~CloudServer() { }

    // start listening to the port and handle connections as they arrive
    bool Listen();

  protected:
    // a single guard for all synchronized data access
    // TODO(tmroeder): in C++14, make this a shared_mutex and support readers
    // and writers semantics
    mutex m_;

    // Handles specific requests for resources. In this superclass
    // implementation, it just deals with names in a std::set. Subclasses
    // override these methods to implement their functionality
    virtual bool HandleCreate(const Action &action, BIO *bio, string *reason,
		    bool *reply);
    virtual bool HandleDestroy(const Action &action, BIO *bio, string *reason,
		    bool *reply);
    virtual bool HandleWrite(const Action &action, BIO *bio, string *reason,
		    bool *reply);
    virtual bool HandleRead(const Action &action, BIO *bio, string *reason,
		    bool *reply);

  private:

    // handles an incoming message from a client
    bool ListenAndHandle(BIO *bio, string *reason, bool *reply);
    void HandleConnection(BIO *bio);
    bool HandleMessage(const ClientMessage& message, BIO *bio, string *reason,
		    bool *reply, bool *close);
    bool HandleAuth(const Auth &auth, BIO *bio, string *reason,
		    bool *reply);
    bool HandleResponse(const Response &response, BIO *bio, string *reason,
		    bool *reply);

    // the encryption/decryption key for this server
    scoped_ptr<keyczar::Keyczar> crypter_;

    // the public policy key, used to check signatures
    scoped_ptr<keyczar::Keyczar> public_policy_key_;

    // random number generator for generating challenges
    scoped_ptr<keyczar::RandImpl> rand_;

    // a context object that stores all the TLS parameters for the connection
    ScopedSSLCtx context_;

    // the main BIO set up for this connection
    keyczar::openssl::ScopedBIO bio_;

    // an accept BIO that listens on the TLS connection
    keyczar::openssl::ScopedBIO abio_;

    // an object that manages an ACL for requests from the client
    scoped_ptr<CloudAuth> auth_;

    // an object that manages users known to the server
    scoped_ptr<CloudUserManager> users_;

    // a simple object management tool: a set of object names
    set<string> objects_;

    // a map of outstanding challenge nonces and the subject they apply to.
    // TODO(tmroeder): these challenges should be timed out or should be stored
    // in a cache instead of a map
    map<string, set<string> > challenges_;

    DISALLOW_COPY_AND_ASSIGN(CloudServer);
};
}

#endif // CLOUDPROXY_CLOUD_SERVER_H_
