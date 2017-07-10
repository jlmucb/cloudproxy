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

#include "helpers.h"
#include "taosupport.h"

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>

#include "keys.pb.h"
#include "ca.pb.h"
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

  // TODO: erase key first.
  // Clear private key.
  if (program_key_ != nullptr) {
    EVP_PKEY_free(program_key_);
  }
  program_key_ = nullptr;

  if (size_program_sym_key_ > 0 && program_sym_key_ != nullptr) {
    memset(program_sym_key_, 0, size_program_sym_key_);
    free(program_sym_key_);
  }

  if (policyCertificate_ != nullptr) {
    X509_free(policyCertificate_);
  }
  policyCertificate_ = nullptr;
  if (programCertificate_ != nullptr) {
    X509_free(programCertificate_);
  }
  programCertificate_ = nullptr;
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
  policyCertificate_ = c;
}

void TaoProgramData::SetProgramCertificate(X509* c) {
  programCertificate_ = c;
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
  return policyCertificate_;
}

bool TaoProgramData::GetCipherSuite(string* keyType) {
  if (!initialized_)
    return false;
  *keyType = cipher_suite_;
  return true;
}

bool TaoProgramData::GetProgramCert(string* cert) {
  *cert = program_cert_;
  return true;
}

X509* TaoProgramData::GetProgramCertificate() {
  return programCertificate_;
}

std::list<string>* TaoProgramData::GetCertChain() {
  if (!initialized_)
    return nullptr;
  return &certs_in_chain_;
}

void TaoProgramData::Print() {
  if (!initialized_) {
    printf("Program object is NOT initialized\n");
    return;
  }
  printf("Program object is NOT initialized\n");
  printf("Tao name: %s\n", marshalled_tao_name_.c_str());
  printf("Policy cert: ");
  PrintBytes(policy_cert_.size(), (byte*)policy_cert_.data());printf("\n");
  printf("Program key: "); printf("TODO"); printf("\n");
  printf("Sym key: ");PrintBytes(size_program_sym_key_, program_sym_key_);printf("\n");
  printf("Program cert: ");PrintBytes(program_cert_.size(), (byte*)program_cert_.data());printf("\n");
  printf("Program path: %s\n", program_file_path_.c_str());
}

void TaoChannel::Print() {
  printf("Peer name: %s\n", peer_name_.c_str());
}

bool TaoProgramData::Attest(string& to_attest, string* attested) {
  return tao_->Attest(to_attest, attested);
}

bool TaoProgramData::Seal(string& data, string* sealed) {
  return tao_->Seal(data, Tao::SealPolicyDefault, sealed);
}

bool TaoProgramData::Unseal(string& sealed, string* unsealed) {
  string policy;
  return tao_->Unseal(sealed, unsealed, &policy);
}

bool TaoProgramData::InitCounter(string& label, int64_t& c) {
printf("Calling tao_->TaoProgramData::InitCounter(%llx)\n", tao_);
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
       string& cfg, string& path, string& network, string& address, string& port,
       bool useSimpleService) {

  // Set tao and msg for later calls.
  msg_ = msg;
  tao_ = tao;
  cipher_suite_ = cipher_suite;
  path_ = path;
  network_ = network;
  address_ = address;
  port_ = port;
  useSimpleService_ = useSimpleService;

  // Read policy cert.
  string policy_cert_file = path + "/policy_keys/cert";
  if (!ReadFile(policy_cert_file, &policy_cert_)) {
    printf("Can't read policy cert.\n");
    return false;
  }

  // Parse policy cert.
  byte* pc = (byte*)policy_cert_.data();
  X509* parsed_policy_cert = d2i_X509(nullptr, (const byte**)&pc,
          policy_cert_.size());
  if (parsed_policy_cert == nullptr) {
    printf("Can't DER parse policy cert.\n");
    return false;
  }

  EVP_PKEY* evp_policy_key = X509_get_pubkey(parsed_policy_cert);
  if (evp_policy_key == nullptr) {
    printf("Can't get policy public key from cert.\n");
    return false;
  }

  // Policy verifier.
  //  policy_verifying_key_
  int key_type = EVP_PKEY_id(evp_policy_key);
  if (EVP_PKEY_EC == key_type) {
  } else if (EVP_PKEY_RSA == key_type) {
  } else {
    printf("Unsupported key type.\n");
    return false;
  }

/*
  optional string file_path = 1;
        optional bytes policy_cert = 2;
        optional string program_name = 3;
        optional bytes signing_key_blob = 4;
        optional bytes crypting_key_blob = 5;
        repeated bytes signer_cert_chain = 6;
        optional string crypto_suite = 7;
        optional bytes delegation = 8;
 */

  // Extend principal name, with hash of policy public key.
  string policy_hash_str;
  if(!GetKeyBytes(evp_policy_key, &policy_hash_str)) {
    printf("Can't get key bytes.\n");
    return false;
  }

  std::vector<std::unique_ptr<tao::PrinExt>> v;

  std::vector<std::unique_ptr<tao::Term>> w;
  w.push_back(tao::make_unique<tao::Bytes>(policy_hash_str.data()));
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

bool TaoProgramData::RequestDomainServiceCert(string& network, string& address,
                              string& port, string& attestation_string,
                              string& endorsement_cert,
                              string* program_cert,
                              std::list<string>* certChain) {

  if (policyCertificate_ == nullptr) {
    printf("Policy cert is null.\n");
    return false;
  }

  X509_REQ* req = X509_REQ_new();;
  X509* cert = X509_new();
  string key_type("ECC");
  string common_name("Fred");
  string issuer("Self");
  string keyUsage("critical,digitalSignature,keyEncipherment,keyAgreement,keyCertSign");
  string extendedKeyUsage("serverAuth,clientAuth");

  EVP_PKEY* self = GenerateKey(key_type, 256);
  if (self == nullptr) {
    printf("Can't Generate temporary channel key.\n");
    return false;
  }
  if (!GenerateX509CertificateRequest(key_type, common_name, self,
         false, req)) {
    printf("Can't generate x509 request\n");
    return false;
  }

  if (!SignX509Certificate(self, true, true, issuer, 
                           keyUsage, extendedKeyUsage, 86400,
                           self, req, false, cert)) {
    printf("Can't sign x509 request\n");
    return false;
  }

  SslChannel domainChannel;

  if (!domainChannel.InitClientSslChannel(network, address, port,
        cert, cert, key_type, self,
        SSL_NO_SERVER_VERIFY_NO_CLIENT_VERIFY)) {
    printf("Can't init ssl channel to domain server.\n");
    return false;
  }

  // Format request and send it to Domain service and get response.
  int bytes_written = SslMessageWrite(domainChannel.GetSslChannel(),
                          (int)attestation_string.size(),
                          (byte*)attestation_string.data());
  if (bytes_written <= 0) {
    printf("Domain channel write failure.\n");
    return false;
  }
  byte read_buf[BUFSIZE];
  string response_buf;
  int bytes_read = 0;
  while ((bytes_read = SslMessageRead(domainChannel.GetSslChannel(), BUFSIZE, read_buf))
           == 0);
  if (bytes_read <= 0) {
    printf("Domain channel read failure (%d).\n", bytes_read);
    return false;
  }

  response_buf.assign((const char*)read_buf, bytes_read);
  domain_policy::DomainCertResponse response;
  if (!response.ParseFromString(response_buf)) {
    printf("Domain channel parse failure.\n");
    return false;
  }
  // Fill in program cert.
  program_cert->assign((const char*)response.signed_cert().data(),
                       response.signed_cert().size());

  // Cert chain
  for (int j = 0; j < response.cert_chain_size(); j++) {
      certChain->push_back(string(response.cert_chain(j)));
  }
  return true;
}

bool TaoProgramData::SaveProgramData(tao_support::SavedProgramData& pd, string* out) {
  // Serialize and Seal
  return false;
}

bool TaoProgramData::RecoverProgramData(string in, tao_support::SavedProgramData* pd) {
  // Unseal and deserialize
  return false;
}

bool TaoProgramData::InitProgramData(tao_support::SavedProgramData* pd) {
	return false;
}

bool TaoProgramData::GetProgramData() {

  string protected_keys_file_name(path_);
  protected_keys_file_name += "protectedProgramKeys";
  string cert_file_name;
  cert_file_name = protected_keys_file_name | "_cert";

  string encrypted_saved_program_data;
  tao_support::SavedProgramData program_data;

  // By now we should have config paths, addresses and tao set.

  if (!ReadFile(protected_keys_file_name, &encrypted_saved_program_data)) {
    // need to init keys
    if (!InitProgramData(&program_data)) {
    }
    if (!SaveProgramData(program_data, &encrypted_saved_program_data)) {
    }
    if (!WriteFile(protected_keys_file_name, encrypted_saved_program_data)) {
    }
  } else {
    // decrypt program keys
    if (!RecoverProgramData(encrypted_saved_program_data, &saved_program_data)) {
    }
  }

  // Fill corresponding TaoProgramData values
  if (program_data.file_path() != nullptr) {
  }
  if (program_data.policy_cert() != nullptr) {
  }
  if (program_data.program_name() != nullptr) {
  }
  if (program_data.signing_key_blob() != nullptr) {
    // Unmarshal cryptokey first
  }
  if (program_data.crypting_key_blob () != nullptr) {
    // Unmarshal cryptokey first
  }
  if (program_data.crypto_suite() != nullptr) {
  }
  if (program_data.delegation() != nullptr) {
  }
 // repeated bytes signer_cert_chain
  return true;
}

TaoChannel::TaoChannel() {
  peerCertificate_ = nullptr;
}

bool TaoChannel::OpenTaoChannel(TaoProgramData& client_program_data,
                    string& serverAddress, string& port) {

  // Parse policy cert and program cert.
  string policy_cert;
  if (!client_program_data.GetPolicyCert(&policy_cert) ||
       policy_cert.size() == 0 ) {
    printf("No policy cert.\n");
    return false;
  }
  X509* policyCertificate = nullptr;
  byte* pc = (byte*)policy_cert.data();
  policyCertificate = d2i_X509(nullptr,
      (const byte**)&pc, policy_cert.size());
  if (policyCertificate == nullptr) {
    printf("Can't parse policy certificate.\n");
    return false;
  }
  client_program_data.SetPolicyCertificate(policyCertificate);

  string program_cert;
  if (!client_program_data.GetProgramCert(&program_cert) ||
       program_cert.size() == 0 ) {
    printf("No program certificate.\n");
    return false;
  }

  pc = (byte*)program_cert.data();
  X509* programCertificate= d2i_X509(nullptr, (const byte**)&pc,
        program_cert.size());
  if (programCertificate == nullptr) {
    printf("Can't translate program certificate.\n");
    return false;
  }
  client_program_data.SetProgramCertificate(programCertificate);
  if (client_program_data.GetProgramKey() == nullptr) {
      printf("No program private key.\n");
      return false;
  }

  string key_type;
  if (!client_program_data.GetProgramKeyType(&key_type)) {
      printf("No private key type.\n");
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
    printf("Can't Init Ssl channel.\n");
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
