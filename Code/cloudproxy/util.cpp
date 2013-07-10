#include "util.h"

#include <fstream>
#include <sstream>

#include <keyczar/base/json_reader.h>
#include <keyczar/keyset_metadata.h>
#include <keyczar/keyset.h>
#include <keyczar/keyczar.h>

using std::ifstream;
using stringstream;

namespace cloudproxy {
bool SetUpSSLCTX(SSL_CTX *ctx, const string &public_policy_key,
		const string &cert, const string &key) {
  // set up the TLS connection with the list of acceptable ciphers
  CHECK(SSL_CTX_set_cipher_list(ctx, "AES128-SHA256")) <<
    "Could not set up a cipher list on the TLS context";

  // turn off compression (?) 
  CHECK(SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION)) <<
    "Could not turn off compression on the TLS connection";

  CHECK(SSL_CTX_load_verify_locations(ctx, public_policy_key)) <<
    "Could not load the public policy key for verification";

  CHECK(SSL_CTX_use_certificate_file(ctx, cert, SSL_FILETYPE_PEM)) <<
    "Could not load the certificate for this connection";

  CHECK(SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM)) <<
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

  if (!VerifySignature(sacl.serialized_acls(), sacl.signature())) {
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
  shared_ptr<Value> meta_value(keyczar::base::JSONReader::Read(metadata,
			  false));
  if (!keyset->set_metadata(keyczar::KeysetMetadata::CreateFromValue(meta_value.get()))) {
    LOG(ERROR) << "Could not add the metadata for this key";
    return false;
  }

  // create an RSA public Key from the key JSON string
  shared_ptr<Value> key_value(keyczar::base::JSONReader::Read(key, false));
  // Note: it is always key version 1, since this is the first key we are adding.
  // TODO(tmroeder): Or do I need to read this information from the metadata? Look in the file.
  if (!keyset->AddKey(keyczar::RSAPublicKey::CreateFromValue(key_value.get())), 1) {
    LOG(ERROR) << "Could not add an RSA Public Key";
    return false;
  }

  // make sure this key is the primary key
  if (!keyset->PromoteKey(1)) {
    LOG(ERROR) << "Could not promote the key to primary";
    return false;
  }
  
  return true;
}
