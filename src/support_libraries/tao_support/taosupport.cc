//  Copyright (c) 2014, Google Inc.  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
#include <string>
#include <vector>
#include <stdlib.h>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "tao/fd_message_channel.h"
#include "tao/tao_rpc.h"
#include "tao/util.h"

#include "agile_crypto_support.h"
#include "ssl_helpers.h"
#include "taosupport.h"

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>

#include "keys.pb.h"
#include "domain_policy.pb.h"
#include "auth.h"

using std::string;
using std::unique_ptr;

using tao::Base64WDecode;
using tao::Base64WEncode;
using tao::FDMessageChannel;
using tao::InitializeApp;
using tao::MarshalSpeaksfor;
using tao::Tao;
using tao::TaoRPC;

#include <google/protobuf/io/coded_stream.h>
#include <google/protobuf/io/zero_copy_stream_impl_lite.h>
#include <google/protobuf/stubs/common.h>
using google::protobuf::io::CodedInputStream;
using google::protobuf::io::CodedOutputStream;
using google::protobuf::io::StringOutputStream;
using google::protobuf::io::ArrayInputStream;
using tao::MarshalSpeaksfor;

#define BUFSIZE 8192

void SerializeTermToString(tao::Term* term, string* name) {
  if (dynamic_cast<tao::Prin*> (term)) {
    tao::Prin* prin = dynamic_cast<tao::Prin*>(term);
    *name += prin->type_ + "("; 
    SerializeTermToString(prin->keyhash_.get(), name);
    *name += ")";
    tao::SubPrin* w = prin->ext_.get();
    for (std::vector<std::unique_ptr<tao::PrinExt>>::iterator
           it = w->elts_.begin(); it != w->elts_.end(); ++it) {
      *name += ".";
      tao::PrinExt* prinExt = (*it).get();
      *name += prinExt->name_ + "(";
      SerializeTermToString(prinExt->args_[0].get(), name);
      *name += ")";
    }
  } else if (dynamic_cast<tao::Bytes*> (term)) {
    tao::Bytes* bytes = dynamic_cast<tao::Bytes*> (term);
    string* hex = ByteToHexLeftToRight((int)bytes->elt_.size(), (byte*)bytes->elt_.data());
    *name += *hex;
    delete hex;
  }
}

TaoChannel::~TaoChannel() {
}

void TaoProgramData::ClearProgramData() {
  initialized_ = false;
  marshalled_tao_name_.clear();
  tao_name_.clear();
  policy_cert_.clear();

  tao_ = nullptr;

  // Clear keys
  memset((byte*)verifying_key_, 0, sizeof(*verifying_key_));
  memset((byte*)program_signing_key_, 0, sizeof(*program_signing_key_));
  memset((byte*)crypting_key_, 0, sizeof(*crypting_key_));

  if (policy_certificate_ != nullptr) {
    X509_free(policy_certificate_);
  }
  policy_certificate_ = nullptr;
}

TaoProgramData::TaoProgramData() {
  initialized_ = false;
  tao_ = nullptr;
  cipher_suite_.clear();
  tao_name_.clear();
  policy_cert_.clear();
  policy_certificate_ = nullptr;
  program_signing_key_ = nullptr;
  verifying_key_ = nullptr;
  crypting_key_ = nullptr;
  program_cert_.clear();
  program_certificate_ = nullptr;
}

TaoProgramData::~TaoProgramData() {
  ClearProgramData();
}

void TaoProgramData::SetPolicyCertificate(X509* c) {
  policy_certificate_ = c;
}

bool TaoProgramData::GetTaoName(string* name) {
  if (!initialized_)
    return false;
  *name = tao_name_;
  return true;
}

bool TaoProgramData::GetPolicyCert(string* cert) {
  if (!initialized_)
    return false;
  *cert = policy_cert_;
  return true;
}

X509* TaoProgramData::GetPolicyCertificate() {
  if (!initialized_)
    return nullptr;
  return policy_certificate_;
}

bool TaoProgramData::GetCipherSuite(string* keyType) {
  if (!initialized_)
    return false;
  *keyType = cipher_suite_;
  return true;
}

void TaoProgramData::SetProgramCertificate(X509* certificate) {
  program_certificate_ = certificate;
}

EVP_PKEY* TaoProgramData::GetProgramKey() {
  return program_signing_key_->sk_;
}

bool TaoProgramData::GetProgramKeyType(string* key_type) {
  if (!SignerAlgorithmNameFromCipherSuite(cipher_suite_, key_type)) {
    return false;
  }
  return true;
}

bool TaoProgramData::GetProgramCert(string* cert) {
  *cert = program_cert_;
  return true;
}

X509* TaoProgramData::GetProgramCertificate() {
  return program_certificate_;
}

std::list<string>* TaoProgramData::GetProgramCertChain() {
  if (!initialized_)
    return nullptr;
  return &program_cert_chain_;
}

void TaoProgramData::Print() {
  if (!initialized_) {
    printf("Program object is NOT initialized\n");
    return;
  }
  printf("Program object is initialized\n");
  printf("Cipher suite: %s\n", cipher_suite_.c_str());
  printf("Tao name: %s\n", marshalled_tao_name_.c_str());
  printf("Policy cert: ");
  PrintBytes(policy_cert_.size(), (byte*)policy_cert_.data());printf("\n");
  printf("Program key: "); printf("TODO"); printf("\n");
  printf("Program cert: ");PrintBytes(program_cert_.size(), (byte*)program_cert_.data());printf("\n");
  printf("Program path: %s\n", program_path_.c_str());
}

void TaoChannel::Print() {
  printf("Peer name: %s\n", peer_name_.c_str());
}

bool TaoProgramData::Attest(string& to_attest, string* attested) {
  return tao_->Attest(to_attest, attested);
}

bool TaoProgramData::SealMaterial(string& data, string* sealed) {
  return tao_->Seal(data, Tao::SealPolicyDefault, sealed);
}

bool TaoProgramData::UnsealMaterial(string& sealed, string* unsealed) {
  string policy;
  return tao_->Unseal(sealed, unsealed, &policy);
}

bool TaoProgramData::InitCounter(string& label, int64_t& c) {
printf("Calling tao_->TaoProgramData::InitCounter(%llx)\n", c);
  return tao_->InitCounter(label, c);
}

bool TaoProgramData::GetCounter(string& label, int64_t* c) {
  return tao_->GetCounter(label, c);
}

bool TaoProgramData::RollbackProtectedSeal(string& label, string& data, string* sealed) {
  return tao_->RollbackProtectedSeal(label, data, Tao::SealPolicyDefault, sealed);
}

bool TaoProgramData::RollbackProtectedUnseal(string& sealed, string* data, string* policy) {
  return tao_->RollbackProtectedUnseal(sealed, data, policy);
}

bool TaoProgramData::InitTao(string& cipher_suite, FDMessageChannel* msg, Tao* tao,
       string& policy_key_path, string& host_key_path, string& program_path, string& network,
       string& address, string& port, bool useSimpleService) {

  cipher_suite_ = cipher_suite;
  msg_ = msg;
  tao_ = tao;
  program_path_ = program_path;
  network_ = network;
  address_ = address;
  port_ = port;
  useSimpleService_ = useSimpleService;
  host_cert_file_name_ = host_key_path + "/cert";
  policy_cert_file_name_ = policy_key_path + "/cert";

  // Read policy cert from config.
  if (!ReadFile(policy_cert_file_name_, &policy_cert_)) {
    printf("Can't read policy cert.\n");
    return false;
  }

  // Translate policy cert.
  policy_verifying_key_ = VerifierFromCertificate(policy_cert_);
  
  byte* pc = (byte*)policy_cert_.data();
  policy_certificate_ = d2i_X509(nullptr, (const byte**)&pc, policy_cert_.size());
  if (policy_certificate_ == nullptr) {
    printf("Can't DER parse policy cert.\n");
    return false;
  }

  // Read host cert
  if (!ReadFile(host_cert_file_name_, &host_cert_)) {
    printf("Can't read host cert %s.\n", host_cert_file_name_.c_str());
    return false;
  }

  // Read host cert chain

  // Extend principal name, with hash of policy public key.
  string policy_principal_bytes;
  if (!UniversalKeyName(policy_verifying_key_, &policy_principal_bytes)) {
    return false;
  }

  std::vector<std::unique_ptr<tao::PrinExt>> v;

  std::vector<std::unique_ptr<tao::Term>> w;
  w.push_back(tao::make_unique<tao::Bytes>(policy_principal_bytes.data()));
  v.push_back(tao::make_unique<tao::PrinExt> ("PolicyKey", std::move(w)));
  tao::SubPrin p(std::move(v));
  string subprin;
  {
    StringOutputStream raw_output_stream(&subprin);
    CodedOutputStream output_stream(&raw_output_stream);
    p.Marshal(&output_stream);
  }

  // Extend Tao name with policy key.
  if (!tao_->ExtendTaoName(subprin)) {
    printf("Can't extend name.\n");
    return false;
  }

  // Retrieve extended name.
  if (!tao->GetTaoName(&marshalled_tao_name_)) {
    printf("Can't get tao name.\n");
    return false;
  }

  tao::Prin unmarshalled_tao_name;
  {
    ArrayInputStream raw_input_stream(marshalled_tao_name_.data(),
                                      marshalled_tao_name_.size());
    CodedInputStream input_stream(&raw_input_stream);
    if (!unmarshalled_tao_name.Unmarshal(&input_stream)) {
        printf("Can't unmarshal tao name\n");
    }
  }
  SerializeTermToString((tao::Term*)&unmarshalled_tao_name, &tao_name_);

  if (!GetProgramData()) {
    printf("Can't init program keys.\n");
    return false;
  }
  initialized_ = true;
  return true;
}

bool TaoProgramData::RequestDomainServiceCert(string& request_string) {

  // Set up a fake SSL channel, key does't matter
  if (policy_certificate_ == nullptr) {
    printf("Policy cert is null.\n");
    return false;
  }

  X509_REQ* req = X509_REQ_new();;
  X509* cert = X509_new();
  string common_name("Fred");
  string issuer("Self");
  string keyUsage("critical,digitalSignature,keyEncipherment,keyAgreement,keyCertSign");
  string extendedKeyUsage("serverAuth,clientAuth");

  tao::CryptoKey sck;
  string key_type;
  if (!SignerAlgorithmNameFromCipherSuite(cipher_suite_, &key_type)) {
    printf("RequestDomainServiceCert: Can't get signer alg name.\n");
    return false;
  }
  if (!GenerateCryptoKey(key_type, &sck)) {
    printf("RequestDomainServiceCert: Can't get signer key.\n");
    return false;
  }
  Signer* s = CryptoKeyToSigner(sck);
  if (s == nullptr) {
    printf("RequestDomainServiceCert: Can't translate key.\n");
    return false;
  }

  if (!GenerateX509CertificateRequest(s->sk_, common_name, false, req)) {
    printf("RequestDomainServiceCert: Can't generate x509 request\n");
    return false;
  }

  if (!SignX509Certificate(s->sk_, true, true, issuer, 
                           keyUsage, extendedKeyUsage, 86400,
                           s->sk_, req, false, cert)) {
    printf("RequestDomainServiceCert: Can't sign x509 request\n");
    return false;
  }

  // Open request channel.
  SslChannel domainChannel;
  if (!domainChannel.InitClientSslChannel(network_, address_, port_,
        cert, cert, key_type, s->sk_,
        SSL_NO_SERVER_VERIFY_NO_CLIENT_VERIFY)) {
    printf("RequestDomainServiceCert: Can't init ssl channel to domain server.\n");
    return false;
  }

  // Send request to Domain service and get response.
  int bytes_written = SslMessageWrite(domainChannel.GetSslChannel(),
                          (int)request_string.size(),
                          (byte*)request_string.data());
  if (bytes_written <= 0) {
    printf("RequestDomainServiceCert: Domain channel write failure.\n");
    return false;
  }
  byte read_buf[BUFSIZE];
  string response_buf;
  int bytes_read = 0;
  while ((bytes_read = SslMessageRead(domainChannel.GetSslChannel(), BUFSIZE, read_buf))
           == 0);
  if (bytes_read <= 0) {
    printf("RequestDomainServiceCert: Domain channel read failure (%d).\n", bytes_read);
    return false;
  }

  // Get response and populate this with cert and cert chain.
  response_buf.assign((const char*)read_buf, bytes_read);
  domain_policy::DomainCertResponse response;
  if (!response.ParseFromString(response_buf)) {
    printf("Domain channel parse failure.\n");
    return false;
  }
  program_cert_.assign((const char*)response.signed_cert().data(),
                       response.signed_cert().size());
  for (int j = 0; j < response.cert_chain_size(); j++) {
      program_cert_chain_.push_back(string(response.cert_chain(j)));
  }

  return true;
}

bool TaoProgramData::SaveProgramData(tao_support::SavedProgramData& pd, string* out) {
  // Serialize and Seal
  string serialized;
  if (!pd.SerializeToString(&serialized)) {
    return false;
  }
  if (!SealMaterial(serialized, out)) {
    return false;
  }
  return true;
}

bool TaoProgramData::RecoverProgramData(string in, tao_support::SavedProgramData* pd) {
  // Unseal and deserialize
  string unsealed;
  if (!UnsealMaterial(in, &unsealed)) {
    return false;
  }
  if (!pd->ParseFromString(unsealed)) {
    return false;
  }
  return true;
}

bool TaoProgramData::InitProgramKeys(tao_support::SavedProgramData* pd) {
  string crypter_alg_name;
  if (!CrypterAlgorithmNameFromCipherSuite(cipher_suite_, &crypter_alg_name)) {
    printf("InitializeProgramKeys: can't get CrypterAlgorithmNameFromCipherSuite.\n");
    return false;
  }
  string signer_alg_name;
  if (!SignerAlgorithmNameFromCipherSuite(cipher_suite_, &signer_alg_name)) {
    printf("InitializeProgramKeys: Can't get SignerAlgorithmNameFromCipherSuite.\n");
    return false;
  }
  tao::CryptoKey eck;
  if (!GenerateCryptoKey(crypter_alg_name, &eck)) {
    printf("InitializeProgramKeys: Can't generate crypter key.\n");
    return false;
  }
  tao::CryptoKey sck;
  if (!GenerateCryptoKey(signer_alg_name, &sck)) {
    printf("InitializeProgramKeys: Can't generate signer key.\n");
    return false;
  }

  crypting_key_ = CryptoKeyToCrypter(eck);
  if (crypting_key_ == nullptr) {
    printf("InitializeProgramKeys: couldn't convert crypter crypto key to crypter.\n");
    return false;
  }
  program_signing_key_ = CryptoKeyToSigner(sck);
  if (program_signing_key_ == nullptr) {
    printf("InitializeProgramKeys: couldn't convert signer crypto key to crypter.\n");
    return false;
  }
  verifying_key_ = VerifierFromSigner(program_signing_key_);
  if (verifying_key_ == nullptr) {
    printf("InitializeProgramKeys: .\n");
    return false;
  }

  string key_bytes;
  if (!UniversalKeyName(verifying_key_, &key_bytes)) {
    printf("InitializeProgramKeys: couldn't get KeyPrincipalBytes.\n");
    return false;
  }

  // Construct a delegation statement.
  string msf;
  if (!MarshalSpeaksfor(key_bytes, marshalled_tao_name_, &msf)) {
    printf("InitializeProgramKeys: couldn't MarshalSpeaksfor.\n");
    return false;
  }
  
  // Get an attestation using delegation and program key;
  string attestation_string;
  if (!Attest(msf, &attestation_string)) {
    printf("InitializeProgramKeys: couldn't Attest.\n");
    return false;
  }

  // Der serialize key
  byte der_subj_key[8196];
  byte* ptr = der_subj_key;
  int der_subj_key_size = i2d_PUBKEY(GetProgramKey(), &ptr);
  if (der_subj_key_size <= 0) {
    printf("Can't i2d ECC public key\n");
    return false;
  }

  // Make cert request.
  domain_policy::DomainCertRequest request;
  request.set_attestation(attestation_string);
  request.set_key_type(signer_alg_name);
  request.set_subject_public_key(der_subj_key, der_subj_key_size);

  string request_string;
  if (!request.SerializeToString(&request_string)) {
    printf("InitializeProgramKey: couldn't serialize request.\n");
    return false;
  }

  // Get Program Cert.
  if (!RequestDomainServiceCert(request_string)) {
    printf("InitializeProgramKeys: couldn't RequestDomainServiceCert.\n");
    return false;
  }

  string crypting_key_blob;
  string signing_key_blob;

  if (!eck.SerializeToString(&crypting_key_blob)) {
    printf("InitializeProgramKeys: can't serialize crypting key.\n");
    return false;
  }
  if (!sck.SerializeToString(&signing_key_blob)) {
    printf("InitializeProgramKeys: can't serialize crypting key.\n");
    return false;
  }

  pd->set_crypto_suite(cipher_suite_);
  pd->set_file_path(program_path_);
  pd->set_policy_cert(policy_cert_);
  pd->set_program_name(tao_name_);
  pd->set_signing_key_blob(signing_key_blob);
  pd->set_crypting_key_blob(crypting_key_blob);
  pd->set_delegation(attestation_string);
/*
  for (int i = 0; i < pd->signer_cert_chain_.size(); i++) {
    string der_cert = pd->signer_cert_chain_(i);
    program_cert_chain_.push_back(der_cert);
  }
 */

  return true;
}

bool TaoProgramData::GetProgramData() {

  string protected_keys_file_name(program_path_);
  protected_keys_file_name += "/protectedProgramKeys";
  string cert_file_name;
  cert_file_name = protected_keys_file_name + "_cert";

  string encrypted_saved_program_data;
  tao_support::SavedProgramData program_data;

  // By now we should have config paths, addresses and tao set.

  if (!ReadFile(protected_keys_file_name, &encrypted_saved_program_data)) {
    // need to init keys
    if (!InitProgramKeys(&program_data)) {
      printf("GetProgramData: can't InitProgramKeys\n");
      return false;
    }
    if (!SaveProgramData(program_data, &encrypted_saved_program_data)) {
      printf("GetProgramData: can't SaveProgramData\n");
      return false;
    }
    if (!WriteFile(protected_keys_file_name, encrypted_saved_program_data)) {
      printf("GetProgramData: can't write savedProgramData\n");
      return false;
    }
    // Save cert too.
    if (!WriteFile(cert_file_name, program_cert_)) {
      printf("GetProgramData: can't write program cert\n");
      return false;
    }
  } else {
    // decrypt program keys
    if (!RecoverProgramData(encrypted_saved_program_data, &program_data)) {
      printf("GetProgramData: can't RecoverProgramData\n");
      return false;
    }
  }

  // Fill corresponding TaoProgramData values
  if (!program_data.has_file_path()) {
      printf("GetProgramData: no program path\n");
      return false;
  }
  if (!program_data.has_policy_cert()) {
      printf("GetProgramData: no policy certt\n");
      return false;
  }
  if (!program_data.has_program_name()) {
      return false;
  }
  if (!program_data.has_signing_key_blob()) {
      printf("GetProgramData: no signing key blob\n");
      return false;
  }
  if (!program_data.has_crypting_key_blob()) {
      printf("GetProgramData: no crypting key blob\n");
      return false;
  }
  if (program_data.has_crypto_suite()) {
      printf("GetProgramData: no crypto suite\n");
      return false;
  }

  tao::CryptoKey sck;
  tao::CryptoKey cck;
  if (!sck.ParseFromString(program_data.signing_key_blob())) {
      printf("GetProgramData: can't decode signing key blob\n");
      return false;
  }
  program_signing_key_ = CryptoKeyToSigner(sck);
  if (program_signing_key_ == nullptr) {
  }
  if (!cck.ParseFromString(program_data.crypting_key_blob())) {
      printf("GetProgramData: can't decode crypting key blob\n");
      return false;
  }
  crypting_key_ = CryptoKeyToCrypter(cck);
  if (crypting_key_ == nullptr) {
  }
  verifying_key_ = VerifierFromSigner(program_signing_key_);
  if (verifying_key_ == nullptr) {
      printf("GetProgramData: can't get VerifierFromSigner\n");
      return false;
  }

  if (program_data.has_delegation()) {
      printf("GetProgramData: no delegation\n");
  }

  // repeated bytes signer_cert_chain

  return true;
}

TaoChannel::TaoChannel() {
  peerCertificate_ = nullptr;
}

bool TaoChannel::OpenTaoChannel(TaoProgramData& client_program_data,
                    string& serverAddress, string& port) {

  string key_type;
  if (!client_program_data.GetProgramKeyType(&key_type)) {
      printf("OpenTaoChannel: No private key type.\n");
      return false;
  }

  // Open TLS channel with Program cert.
  string network("tcp");
  if (!peer_channel_.InitClientSslChannel(network, serverAddress, port,
                    client_program_data.GetPolicyCertificate(),
                    client_program_data.GetProgramCertificate(),
                    key_type,
                    client_program_data.GetProgramKey(),
                    SSL_SERVER_VERIFY_CLIENT_VERIFY)) {
    printf("OpenTaoChannel: Can't Init Ssl channel.\n");
    return false;
  }

  // Get peer name from organizational unit.
  peerCertificate_ = peer_channel_.GetPeerCert();
  if (peerCertificate_ != nullptr) {
    X509_NAME* name = X509_get_subject_name(peerCertificate_);
    int nid = OBJ_txt2nid("OU");
    char buf[BUFSIZE];
    if (X509_NAME_get_text_by_NID(name, nid, buf, BUFSIZE) == 1) {
      peer_name_ = buf ;
    }
  }

  return true;
}

void TaoChannel::CloseTaoChannel() {
  peer_channel_.Close();
}

bool TaoChannel::SendRequest(int size, byte* out) {
  int k = SslMessageWrite(peer_channel_.GetSslChannel(), size, out);
  return k > 0;
}

bool TaoChannel::GetRequest(int* size, byte* in) {
  int k = SslMessageRead(peer_channel_.GetSslChannel(), *size, in);
  if (k <= 0) {
    printf("Can't read request channel.\n");
    return false;
  }
  *size = k;
  return true;
}
