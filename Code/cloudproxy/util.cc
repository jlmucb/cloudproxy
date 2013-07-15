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

#define READ_BUFFER_LEN 16384

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

bool CopyRSAPublicKeyset(keyczar::Keyczar *public_key,
               keyczar::Keyset *keyset) {
  CHECK(public_key) << "null public_key";
  CHECK(keyset) << "null keyset";
  LOG(INFO) << "Getting the public_key keyset";
  const keyczar::Keyset *public_keyset = public_key->keyset();
  CHECK(public_keyset) << "null public keyset";
  LOG(INFO) << "Getting the key value";
  const keyczar::Key *k1 = public_keyset->GetKey(1);
  CHECK(k1) << "Null key 1";
  scoped_ptr<Value> key_value(k1->GetValue());
  LOG(INFO) << "Getting the metadata";
  scoped_ptr<Value> meta_value(public_keyset->metadata()->GetValue(true));
  LOG(INFO) << "Setting metadata for the keyset";

  keyset->set_metadata(keyczar::KeysetMetadata::CreateFromValue(meta_value.get()));

  LOG(INFO) << "Adding the key";
  // TODO(tmroeder): read the number of the primary key from the public_key
  // metadata
  if (!keyset->AddKey(keyczar::RSAPublicKey::CreateFromValue(*key_value), 1)) {
    LOG(ERROR) << "Could not add an RSA Public Key";
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

// TODO(tmroeder): change this function to take a function pointer parameter to actually write the data:
// size_t write_data(const void *buffer, int len, FILE *f)
bool ReceiveStreamData(BIO *bio, const string &path) {
  // open the file
  CHECK(bio) << "null bio";
  FILE *f = fopen(path.c_str(), "w");

  //ScopedFile f(fopen(path.c_str(), "w"));
  if (nullptr == f) {
    LOG(ERROR) << "Could not open the file " << path << " for writing";
    return false;
  }

  // first receive the length
  uint32_t net_len = 0;
  if (!ReceiveData(bio, &net_len, sizeof(net_len))) {
    LOG(ERROR) << "Could not get the length of the data";
    return false;
  }

  // convert from network byte order to get the length
  uint32_t expected_len = ntohl(net_len);
  LOG(INFO) << "Got expected length " << expected_len;

  uint32_t total_len = 0;
  int len = READ_BUFFER_LEN;
  int out_len = 0;
  size_t bytes_written = 0;
  scoped_array<unsigned char> buf(new unsigned char[len]);
  while((total_len < expected_len) && (out_len = BIO_read(bio, buf.get(), len)) != 0) {
    if (out_len < 0) {
      if (!BIO_should_retry(bio)) {
	LOG(ERROR) << "Write failed after " << total_len << " bytes were written";
	return false;
      }
    } else {
      // TODO(tmroeder): write to a temp file first so we only need to lock on
      // the final rename step
      bytes_written = fwrite(buf.get(), 1, out_len, f);
      // this cast is safe, since out_len is guaranteed to be non-negative
      if (bytes_written != static_cast<size_t>(out_len)) {
	LOG(ERROR) << "Could not write the received bytes to disk after " << total_len << " bytes were written";
	return false;
      }

      total_len += bytes_written;
    }
  }

  fclose(f);

  return true;
}

// TODO(tmroeder): change this function to take a function pointer argument as for ReceiveStreamData
// size_t read_data(FILE *f, void *buffer, int *len)
bool SendStreamData(const string &path, size_t size, BIO *bio) {
  CHECK(bio) << "null bio";

  // open the file
  CHECK(bio) << "null bio";
  FILE *f = fopen(path.c_str(), "r");
  //ScopedFile f(fopen(path.c_str(), "r"));
  if (nullptr == f) {
    LOG(ERROR) << "Could not open the file " << path << " for reading";
    return false;
  }

  // send the length of the file first
  uint32_t net_len = htonl(size);

  // send the length to the client 
  if (!SendData(bio, &net_len, sizeof(net_len))) {
    LOG(ERROR) << "Could not send the len";
    return false;
  }

  // stream the file bytes from disk to the network
  size_t total_bytes = 0;
  size_t len = READ_BUFFER_LEN;
  size_t bytes_read = 0;
  scoped_array<unsigned char> buf(new unsigned char[len]);
  while((total_bytes < size) &&
        (bytes_read = fread(buf.get(), 1, len, f)) != 0) {
    int x = 0;
    while((x = BIO_write(bio, buf.get(), bytes_read)) < 0) {
      if (!BIO_should_retry(bio)) {
        LOG(ERROR) << "Network write operation failed";
        return false;
      }
    }

    if (x == 0) {
      LOG(ERROR) << "Could not write the bytes to the network after " <<
        " total_bytes were written";
    }

    // this cast is safe, since x is guaranteed to be non-negative
    total_bytes += static_cast<size_t>(x);
  }

  if (total_bytes != size) {
    LOG(ERROR) << "Did not send all bytes to the server";
    return false;
  }

  fclose(f);
  return true;
}

} // namespace cloudproxy
