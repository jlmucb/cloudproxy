#include "file_server.h"

namespace cloudproxy {

FileServer::FileServer(const string &file_path,
	       const string &tls_cert,
	       const string &tls_key,
		const string &tls_password,
		const string &public_policy_keyczar,
		const string &public_policy_pem,
		const string &acl_location,
		const string &server_key_location,
		const string &host,
		ushort port)
  : CloudServer(tls_cert,
      tls_key,
      tls_password,
      public_policy_keyczar,
      public_policy_pem,
      acl_location,
      server_key_location,
      host,
      port),
    file_path_(file_path) {

}
bool FileServer::HandleCreate(const Action &action, BIO *bio, string *reason,
		    bool *reply, CloudServerThreadData &cstd) {
  bool rv = CloudServer::HandleCreate(action, bio, reason, reply, cstd);
  if (rv) {
    // touch the file to create it
    LOG(INFO) << "TODO: create the file";
  }

  return rv;
}

bool FileServer::HandleDestroy(const Action &action, BIO *bio, string *reason,
		    bool *reply, CloudServerThreadData &cstd) {
  bool rv = CloudServer::HandleDestroy(action, bio, reason, reply, cstd);
  if (rv) {
    // delete the file
    LOG(INFO) << "TODO: delete the file";
  }

  return rv;
}

bool FileServer::HandleWrite(const Action &action, BIO *bio, string *reason,
		    bool *reply, CloudServerThreadData &cstd) {
  bool rv = CloudServer::HandleWrite(action, bio, reason, reply, cstd);
  if (rv) {
    // send a reply ourselves and receive the file to write
    LOG(INFO) << "TODO: send a reply and receive the file";
  }

  return rv;
}

bool FileServer::HandleRead(const Action &action, BIO *bio, string *reason,
		    bool *reply, CloudServerThreadData &cstd) {
  bool rv = CloudServer::HandleRead(action, bio, reason, reply, cstd);
  if (rv) {
    // look up the file and send a reply if we can find it, then immediately
    // start sending the bits of the file
    LOG(INFO) << "TODO: handle the read operation";
  }

  return rv;
}

} // namespace cloudproxy
