#ifndef CLOUDPROXY_FILE_CLIENT_H_
#define CLOUDPROXY_FILE_CLIENT_H_

#include "cloud_client.h"

namespace cloudproxy {
class FileClient : public CloudClient {
  public:

    FileClient(const string &file_path,
        const string &tls_cert,
        const string &tls_key,
	    const string &tls_password,
        const string &public_policy_keyczar, 
        const string &public_policy_pem,
        const string &server_addr,
		ushort server_port);

    virtual ~FileClient() { }

    // Sends a CREATE request to the attached CloudServer
    virtual bool Create(const string &owner, const string &object_name);

    // Sends a DESTROY request to the attached CloudServer
    virtual bool Destroy(const string &owner, const string &object_name);

    // Send a READ request to a CloudServer
    virtual bool Read(const string &requestor, const string &object_name);

    // Sends a WRITE request to a CloudServer
    virtual bool Write(const string &requestor, const string &object_name);

  private:

    // the base path for files that are read from and written to the server
    string file_path_;
};
}

#endif // CLOUDPROXY_FILE_CLIENT_H_
