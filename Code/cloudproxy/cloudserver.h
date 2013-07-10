#ifndef CLOUDSERVER_H_
#define CLOUDSERVER_H_

#include "cloudproxy.pb.h"
#include "cloudauth.h"
#include "cloud_user_manager.h"
#include "util.h"
#include <openssl/ssl.h>
#include <keyczar/openssl/util.h>
#include <keyczar/crypto_factory.h>

#include <string>
#include <set>

using std::set;
using std::string;

namespace cloudproxy {

// A server that handles requests from a CloudClient (and a base class for all
// such servers). This class handles requests from a CloudClient and checks its
// ACL database to see if the operations is authorized by CloudProxy policy.
class CloudServer {
  public:
    // Creates a CloudServer with a given key store, location of its signed ACL
    // database, and the port on which to listen. It also needs the location of
    // the public policy key in two ways: one as a PEM file for use in TLS, and
    // one as public RSA keyczar directory
    CloudServer(const string &tls_cert,
		const string &tls_key,
		const string &public_policy_keyczar,
		const string &public_policy_pem,
		const string &acl_location,
                ushort port);

    virtual ~CloudServer();

    // start listening to the port and handle connections as they arrive
    bool Listen();

  protected:
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

    bool ReceiveData(BIO *bio, void *buffer, size_t buffer_len);
    bool ReceiveData(BIO *bio, string *data);
    bool SendData(BIO *bio, void *buffer, size_t buffer_len);
    bool SendData(BIO *bio, const string &data);

  private:

    // handles an incoming message from a client
    bool HandleConnection(keyczar::openssl::ScopedBIO &sbio);
    bool HandleMessage(const ClientMessage& message, BIO *bio, string *reason,
		    bool *reply);
    bool HandleAuth(const Auth &auth, BIO *bio, string *reason,
		    bool *reply);
    bool HandleResponse(const Response &response, BIO *bio, string *reason,
		    bool *reply);

    // the encryption/decryption key for this server
    unique_ptr<keyczar::Keyczar> crypter_;

    // the public policy key, used to check signatures
    unique_ptr<keyczar::Keyczar> public_policy_key_;

    // random number generator for generating challenges
    unique_ptr<keyczar::RandImpl> rand_;

    // a context object that stores all the TLS parameters for the connection
    ScopedSSLCtx context_;

    // the main BIO set up for this connection
    keyczar::openssl::ScopedBIO bio_;

    // an accept BIO that listens on the TLS connection
    keyczar::openssl::ScopedBIO abio_;

    // an object that manages an ACL for requests from the client
    unique_ptr<CloudAuth> auth_;

    // an object that manages users known to the server
    unique_ptr<CloudUserManager> users_;

    // a simple object management tool: a set of object names
    set<string> objects_;

    // a map of outstanding challenge nonces and the subject they apply to.
    // TODO(tmroeder): these challenges should be timed out or should be stored
    // in a cache instead of a map
    map<string, string> challenges_;

    unique_ptr<CloudUserManager> users_;
};
}

#endif // CLOUDSERVER_H_
