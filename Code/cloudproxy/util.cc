#include "util.h"

#include <fstream>
#include <sstream>

#include <arpa/inet.h>

#include <keyczar/base/json_reader.h>
#include <keyczar/keyset_metadata.h>
#include <keyczar/keyset.h>
#include <keyczar/keyczar.h>
#include <keyczar/rsa_impl.h>
#include <keyczar/rsa_public_key.h>

#include "cloudproxy.pb.h"

using std::ifstream;
using std::stringstream;

namespace cloudproxy {

// this callback will change once we get the password from the Tao/TPM
int PasswordCallback(char *buf, int size, int rwflag, void *password)
{
 strncpy(buf, (char *)(password), size);
 buf[size - 1] = '\0';
 return(strlen(buf));
}

bool SetUpSSLCTX(SSL_CTX *ctx, const string &public_policy_key,
		const string &cert, const string &key, const string &password) {
  CHECK(ctx) << "null ctx";

  // set up the TLS connection with the list of acceptable ciphers
  CHECK(SSL_CTX_set_cipher_list(ctx, "AES128-SHA256")) <<
    "Could not set up a cipher list on the TLS context";

  // turn off compression (?) 
  CHECK(SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION)) <<
    "Could not turn off compression on the TLS connection";

  CHECK(SSL_CTX_load_verify_locations(ctx, public_policy_key.c_str(), NULL)) <<
    "Could not load the public policy key for verification";

  LOG(INFO) << "Loading the cert location " << cert;
  CHECK(SSL_CTX_use_certificate_file(ctx, cert.c_str(), SSL_FILETYPE_PEM)) <<
    "Could not load the certificate for this connection";

  // set up the password callback and the password itself
  SSL_CTX_set_default_passwd_cb(ctx, PasswordCallback);
  SSL_CTX_set_default_passwd_cb_userdata(ctx,
    const_cast<char*>(password.c_str()));

  CHECK(SSL_CTX_use_PrivateKey_file(ctx, key.c_str(), SSL_FILETYPE_PEM)) <<
    "Could not load the private key for this connection";

  return true;
}

bool ExtractACL(const string &signed_acls_file, keyczar::Keyczar *key,
		 string *acl) {

  CHECK(key) << "null key";
  CHECK(acl) << "null acl";

  // load the signature
  ifstream sig(signed_acls_file.c_str());
  stringstream sig_buf;
  sig_buf << sig.rdbuf();

  cloudproxy::SignedACL sacl;
  sacl.ParseFromString(sig_buf.str());

  if (!VerifySignature(sacl.serialized_acls(), sacl.signature(), key)) {
    return false;
  }

  acl->assign(sacl.serialized_acls());
  return true;
}

bool VerifySignature(const string &data, const string &signature,
		keyczar::Keyczar *key) {
  if (!key->Verify(data, signature)) {
    LOG(ERROR) << "Verify failed";
    return false;
  }

  return true;
}

bool CreateRSAPublicKeyset(const string &key, const string &metadata,
		keyczar::Keyset *keyset) {
  CHECK(keyset) << "null keyset";

  // create KeyMetadata from the metadata string
  scoped_ptr<Value> meta_value(keyczar::base::JSONReader::Read(metadata,
			  false));
  keyset->set_metadata(keyczar::KeysetMetadata::CreateFromValue(meta_value.get()));

  // create an RSA public Key from the key JSON string
  scoped_ptr<Value> key_value(keyczar::base::JSONReader::Read(key, false));
  // Note: it is always key version 1, since this is the first key we are adding.
  // TODO(tmroeder): Or do I need to read this information from the metadata? Look in the file.
  if (!keyset->AddKey(keyczar::RSAPublicKey::CreateFromValue(*key_value), 1)) {
    LOG(ERROR) << "Could not add an RSA Public Key";
    return false;
  }

  return true;
}

bool ReceiveData(BIO *bio, void *buffer, size_t buffer_len) {
  CHECK(bio) << "null bio";
  CHECK(buffer) << "null buffer";

  // get the data, retrying until we get it.
  // Note: this assumes that BIO_read doesn't get partial data from the SSL
  // connection but instead blocks until it has enough data.
  int x = 0;
  while ((x = BIO_read(bio, buffer, buffer_len)) != buffer_len) {
    if (x == 0) return false;
    if ((x < 0) && !BIO_should_retry(bio)) return false;
  }

  return true;
}

bool ReceiveData(BIO *bio, string *data) {
  CHECK(bio) << "null bio";
  CHECK(data) << "null data";

  uint32_t net_len;
  if (!ReceiveData(bio, &net_len, sizeof(net_len))) {
    LOG(ERROR) << "Could not get the length of the data";
    return false;
  }

  // convert from network byte order to get the length
  uint32_t len = ntohl(net_len);
  scoped_array<char> temp_data(new char[len]);

  if (!ReceiveData(bio, temp_data.get(), len)) {
    LOG(ERROR) << "Could not get the data";
    return false;
  }

  data->assign(temp_data.get(), len);

  return true;
}

bool SendData(BIO *bio, const void *buffer,
    size_t buffer_len) {
  int x = 0;
  while((x = BIO_write(bio, buffer, buffer_len)) != buffer_len) {
    if (x == 0) return false;
    if ((x < 0) && !BIO_should_retry(bio)) return false;
  }

  return true;
}


bool SendData(BIO *bio, const string &data) {
  size_t s = data.length();
  uint32_t net_len = htonl(s);

  // send the length to the client first
  if (!SendData(bio, &net_len, sizeof(net_len))) {
    LOG(ERROR) << "Could not send the len";
    return false;
  }

  if (!SendData(bio, data.data(), data.length())) {
    LOG(ERROR) << "Could not send the data";
    return false;
  }

  return true;
}

bool SignData(const string &data, string *signature,
		keyczar::Keyczar *key) {
  if (!key->Sign(data, signature)) {
    LOG(ERROR) << "Could not sign the data";
    return false;
  }

  return true;
}

} // namespace cloudproxy
