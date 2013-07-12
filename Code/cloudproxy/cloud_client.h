#ifndef CLOUDPROXY_CLOUD_CLIENT_H_
#define CLOUDPROXY_CLOUD_CLIENT_H_

#include <openssl/ssl.h>
#include <keyczar/keyczar.h>

#include "util.h"
#include "cloud_user_manager.h"

#include <set>
#include <string>

using std::set;
using std::string;

namespace cloudproxy {

// A client that can establish a secure connection with a CloudServer and manage
// simple operations between the client and the server. See cloudproxy.proto for
// the details of the messages exchanged between CloudClient and CloudServer, as
// well as the (related) format of ACLs stored on the server. These ACLs are
// used by CloudServer to check if actions requested by the CloudClient are
// authorized by CloudProxy policy.
//
// Sample usage: see client.cc
class CloudClient {
  public:
    // Creates a CloudClient with a directory (key_location) it searches to find
    // keyczar directories, the location of certificates and keys for TLS, as
    // well as with the addr:port of a CloudServer. 
    CloudClient(const string &tls_cert,
        const string &tls_key,
	const string &tls_password,
        const string &public_policy_keyczar, 
        const string &public_policy_pem,
        const string &server_addr,
		ushort server_port);

    virtual ~CloudClient() { }

    // Connects to the specified server using the keys
    bool Connect();

    bool AddUser(const string &user, const string &key_path,
      const string &password);
    // Authenticates the subject to a connected CloudServer. There must be a
    // directory under key_location that has a name matching the parameter.
    bool Authenticate(const string &subject, const string &binding_file);

    // Sends a CREATE request to the attached CloudServer
    virtual bool Create(const string &owner, const string &object_name);

    // Sends a DESTROY request to the attached CloudServer
    virtual bool Destroy(const string &owner, const string &object_name);

    // Send a READ request to a CloudServer
    virtual bool Read(const string &requestor, const string &object_name);

    // Sends a WRITE request to a CloudServer
    virtual bool Write(const string &requestor, const string &object_name);

    // Closes the connection to the server
    bool Close(bool error);

  protected:
    bool SendAction(const string &subject, const string &object, Op op);
    bool HandleReply();

    // The BIO used to communicate over the TLS channel
    keyczar::openssl::ScopedBIO bio_;

  private:
    bool HandleChallenge(const Challenge& chall);

    // the public policy key for this connection
    scoped_ptr<keyczar::Keyczar> public_policy_key_;

    // A TLS connection to the server
    ScopedSSLCtx context_;

    // Principals that have been authenticated on this connection, and the keys
    // for each user
    scoped_ptr<CloudUserManager> users_;

    DISALLOW_COPY_AND_ASSIGN(CloudClient);
};
}

#endif // CLOUDPROXY_CLOUD_CLIENT_H_
