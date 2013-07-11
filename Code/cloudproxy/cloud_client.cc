#include "cloud_client.h"

#include <glog/logging.h>

#include "cloudproxy.pb.h"

#include <sstream>
#include <fstream>

using std::ifstream;
using std::stringstream;

namespace cloudproxy {

CloudClient::CloudClient(const string &tls_cert,
		const string &tls_key,
		const string &public_policy_keyczar,
		const string &public_policy_pem,
		const string &server_addr,
		ushort server_port)
	: public_policy_key_(keyczar::Verifier::Read(public_policy_keyczar.c_str())),
	context_(SSL_CTX_new(TLSv1_2_client_method())),
	bio_(nullptr),
	users_() {
  // set up the TLS connection with the cert and keys and trust DB
  CHECK(SetUpSSLCTX(context_.get(), public_policy_pem, tls_cert, tls_key)) 
    << "Could not set up the client TLS connection";

  bio_.reset(BIO_new_ssl_connect(context_.get()));
  SSL *ssl = nullptr;

  BIO_get_ssl(bio_.get(), &ssl);
  CHECK(ssl) << "Could not get the SSL pointer for the TLS bio"; SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

  stringstream ss;
  ss << server_port;
  string host_and_port = server_addr + string(":") + ss.str();

  BIO_set_conn_hostname(bio_.get(), const_cast<char*>(host_and_port.c_str()));
}

bool CloudClient::Connect() {
  int r = BIO_do_connect(bio_.get());
  if (r <= 0) {
    LOG(ERROR) << "Could not connect to the server";
    return false;
  }

  return true;
}

bool CloudClient::AddUser(const string &user, const string &key_path,
    const string &password) {
  if (users_->HasKey(user)) {
    LOG(ERROR) << "User " << user << " already has a key";
    return false;
  }

  return users_->AddKey(user, key_path, password);
}

bool CloudClient::Authenticate(const string &subject,
		const string &binding_file) {
  // check to see if we have already authenticated this subject
  if (users_->IsAuthenticated(subject)) {
    LOG(INFO) << "User " << subject << " is already authenticated";
    return true;
  }

  // check to see if we have the key for this user. If not, then we can't
  // authenticate
  CHECK(users_->HasKey(subject)) << "No key loaded for user " << subject;

  shared_ptr<keyczar::Keyczar> signer;
  CHECK(users_->GetKey(subject, &signer)) << "Could not get the key for user "
    << subject;

  // send to the server an AUTH request
  Auth a;
  a.set_subject(subject);

  string serialized_auth;
  CHECK(a.SerializeToString(&serialized_auth)) << "Could not serialize the"
      " Auth message";

  CHECK(SendData(bio_.get(), serialized_auth)) << "Could not request auth";

  // now listen for the connection
  string serialized_chall;
  CHECK(ReceiveData(bio_.get(), &serialized_chall)) << "Could not get a"
    " challenge from the server";

  Challenge c;
  CHECK(c.ParseFromString(serialized_chall)) << "Could not deserialize the"
    " challenge from the server";

  CHECK_STREQ(c.subject().c_str(), subject.c_str()) << "Challenge for the wrong subject";

  string sig;
  CHECK(SignData(serialized_chall, &sig, signer.get())) << "Could not sign the"
      " challenge";

  Response r;
  r.set_serialized_chall(serialized_chall);
  r.set_signature(sig);

  SignedSpeaksFor *ssf = r.mutable_binding();

  // now create a SignedSpeaksFor annotation from the corresponding signed file
  // for this user
  ifstream ssf_file(binding_file.c_str());
  ssf->ParseFromIstream(&ssf_file);

  string serialized_response;
  CHECK(r.SerializeToString(&serialized_response)) << "Could not serialize"
    " the Response to the Challenge";

  CHECK(SendData(bio_.get(), serialized_response)) << "Could not send"
    " Response";

  return HandleReply();
}

bool CloudClient::SendAction(const string &owner, const string &object_name,
		Op op) {
  Action a;
  a.set_subject(owner);
  a.set_verb(op);
  a.set_object(object_name);

  string s;
  CHECK(a.SerializeToString(&s)) << "Could not serialize Action";
  CHECK(SendData(bio_.get(), s)) << "Could not send the Action to CloudServer";
  return HandleReply();
}

bool CloudClient::Create(const string &owner, const string &object_name) {
  return SendAction(owner, object_name, CREATE);
}

bool CloudClient::Destroy(const string &requestor, const string &object_name) {
  return SendAction(requestor, object_name, DESTROY);
}

bool CloudClient::Read(const string &requestor, const string &object_name) {
  return SendAction(requestor, object_name, READ);
}

bool CloudClient::Write(const string &requestor, const string &object_name) {
  return SendAction(requestor, object_name, WRITE);
}

bool CloudClient::HandleReply() {
  string s;
  if (!ReceiveData(bio_.get(), &s)) {
    LOG(ERROR) << "Could not receive a reply from the server";
    return false;
  }

  Result r;
  if (!r.ParseFromString(s)) {
    LOG(ERROR) << "Could not parse the response from the server";
    return false;
  }

  if (!r.success()) {
    if (r.has_reason()) {
      LOG(ERROR) << "Error: " << r.reason();
    } else {
      LOG(ERROR) << "The operation failed for an unknown reason";
    }
    return false;
  }
  
  LOG(INFO) << "The operation was successful";
  return true;
}

} // namespace cloudproxy
