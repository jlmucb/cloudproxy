#include "file_client.h"

namespace cloudproxy {

FileClient::FileClient(const string &file_path,
        const string &tls_cert,
        const string &tls_key,
	    const string &tls_password,
        const string &public_policy_keyczar, 
        const string &public_policy_pem,
        const string &server_addr,
		ushort server_port)
  : CloudClient(tls_cert,
      tls_key,
      tls_password,
      public_policy_keyczar,
      public_policy_pem,
      server_addr,
      server_port),
    file_path_(file_path) {
  LOG(INFO) << "Constructing the file client";
  // TODO(tmroeder): check that this path exists
}

bool FileClient::Create(const string &owner, const string &object_name) {
  // defer to the CloudClient implementation to get this created
  return CloudClient::Create(owner, object_name);
}

bool FileClient::Destroy(const string &owner, const string &object_name) {
  // defer to the CloudClient implementation to get this destroyed
  return CloudClient::Destroy(owner, object_name);
}

bool FileClient::Read(const string &requestor, const string &object_name) {
  // make the call to get permission for the operation, and it that succeeds,
  // start to receive the bits
  CHECK(CloudClient::Read(requestor, object_name)) << "Could not get permission to"
    " read the object";

  LOG(INFO) << "TODO: accept the bits from the network and write them to disk";
  return true;
}

bool FileClient::Write(const string &requestor, const string &object_name) {
  // make the call to get permission for the operation, and if that succeeds,
  // then start to write the bits to the network
  CHECK(CloudClient::Write(requestor, object_name)) << "Could not get"
    " permission to write to the file";
  
  // TODO(tmroeder): add a StreamBytes and ReceiveByteStream methods that take
  // callbacks for each chunk of bytes that are received

  LOG(INFO) << "TODO: read the bits from the disk and write them to the"
    " network";
  return true;
}

} // namespace cloudproxy
