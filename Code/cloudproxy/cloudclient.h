#ifndef CLOUDCLIENT_H_
#define CLOUDCLIENT_H_

#include <openssl/ssl.h>

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
// Sample usage:
// 
// CloudClient cc("/var/keys", 12345);
// CHECK(cc.Authenticate("tmroeder")) << "Could not get /var/keys/tmroeder";
// CHECK(cc.Create("tmroeder", "test")) << "Could not create a test object";
// CHECK(cc.Destroy("tmroeder", "test")) << "Could not destroy the test obj";
class CloudClient {
  public:
    // Creates a CloudClient with a directory (key_location) it searches to find
    // keyczar directories, the location of certificates and keys for TLS, as
    // well as with the addr:port of a CloudServer. 
    CloudClient(const string &user_key_location, const string &tls_key_location,
                const string &server_addr, ushort server_port);

    virtual ~CloudClient();

    // Connects to the specified server using the keys
    bool Connect();

    // Authenticates the subject to a connected CloudServer. There must be a
    // directory under key_location that has a name matching the parameter.
    bool Authenticate(const string &subject);

    // Sends a CREATE request to the attached CloudServer
    virtual bool Create(const string &owner, const string &object_name);

    // Sends a DESTROY request to the attached CloudServer
    virtual bool Destroy(const string &owner, const string &object_name);

    // Send a READ request to a CloudServer
    virtual bool Read(const string &requestor, const string &object_name);

    // Sends a WRITE request to a CloudServer
    virtual bool Write(const string &requestor, const string &object_name);

  private:
    // A TLS connection to the server
    SSL_CTX *ctx_;

    // The BIO used to communicate over the TLS channel
    BIO *bio_;

    // The location of all keyczar key directories for this client
    string key_location_;
    
    // Principals that have been authenticated on this connection
    set<string> principals_;

    // disallow copy construction and assignment
    CloudClient(const CloudClient&);
    CloudClient& operator=(const CloudClient&);
};
}

#endif // CLOUDCLIENT_H_
