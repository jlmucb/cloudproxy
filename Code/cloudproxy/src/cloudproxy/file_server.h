#ifndef CLOUDPROXY_FILE_SERVER_H_
#define CLOUDPROXY_FILE_SERVER_H_

#include "cloud_server.h"

namespace cloudproxy {

class FileServer : public CloudServer {
 public:
  FileServer(const string &file_path, const string &meta_path,
             const string &tls_cert, const string &tls_key,
             const string &tls_password, const string &public_policy_keyczar,
             const string &public_policy_pem, const string &acl_location,
             const string &server_key_location, const string &host,
             ushort port);

  virtual ~FileServer() {}

 protected:
  virtual bool HandleCreate(const Action &action, BIO *bio, string *reason,
                            bool *reply, CloudServerThreadData &cstd);
  virtual bool HandleDestroy(const Action &action, BIO *bio, string *reason,
                             bool *reply, CloudServerThreadData &cstd);
  virtual bool HandleWrite(const Action &action, BIO *bio, string *reason,
                           bool *reply, CloudServerThreadData &cstd);
  virtual bool HandleRead(const Action &action, BIO *bio, string *reason,
                          bool *reply, CloudServerThreadData &cstd);

 private:
  // a key for deriving keys for encryption
  scoped_ptr<keyczar::Keyczar> main_key_;

  keyczar::base::ScopedSafeString enc_key_;
  keyczar::base::ScopedSafeString hmac_key_;

  // the path to which we write incoming files
  string file_path_;

  // the path to which we write file metadata
  string meta_path_;
};

}  // namespace cloudproxy

#endif  // CLOUDPROXY_FILE_SERVER_H_
