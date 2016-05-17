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
#include <stdlib.h>

#include <gflags/gflags.h>
#include <glog/logging.h>

#include "tao/fd_message_channel.h"
#include "tao/tao_rpc.h"
#include "tao/util.h"

#include "helpers.h"
#include "taosupport.h"
#include <taosupport.pb.h>

#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>

#include "ca.pb.h"
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

#define BUFSIZE 4096

void PrintBytes(int n, byte* in) {
  for (int i = 0; i < n; i++) printf("%02x", in[i]);
}

TaoChannel::TaoChannel() {
  peerCertificate_ = nullptr;
}

TaoChannel::~TaoChannel() {
}

bool TaoChannel::OpenTaoChannel(TaoProgramData& client_program_data,
                    string& serverAddress, string& port) {

  // Parse policy cert and program cert.
  if (client_program_data.policy_cert_.size() ==0 ) {
    return false;
  }
  if (client_program_data.policyCertificate_ == nullptr) {
    byte* pc = (byte*)client_program_data.policy_cert_.data();
    client_program_data.policyCertificate_ = d2i_X509(nullptr, (const byte**)&pc,
          client_program_data.policy_cert_.size());
    if (client_program_data.policyCertificate_ == nullptr) {
      return false;
    }
  }
  if (client_program_data.program_cert_.size() ==0 ) {
    return false;
  }
  if (client_program_data.programCertificate_ == nullptr) {
    byte* pc = (byte*)client_program_data.program_cert_.data();
    client_program_data.policyCertificate_ = d2i_X509(nullptr, (const byte**)&pc,
          client_program_data.program_cert_.size());
    if (client_program_data.programCertificate_ == nullptr) {
      return false;
    }
  }

  // Open TLS channel with Program cert.
  string network("tcp");
  if (!peer_channel_.InitSslChannel(network, serverAddress, port,
                    client_program_data.policyCertificate_,
                    client_program_data.programCertificate_,
                    client_program_data.program_key_, true)) {
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

bool TaoChannel::SendRequest(taosupport::SimpleMessage& out) {
  string msg_buf;

  if (!out.SerializeToString(&msg_buf)) {
    return false;
  }
  int k = peer_channel_.Write(msg_buf.size(), (byte*)msg_buf.data());
  return k > 0;
}

bool TaoChannel::GetRequest(taosupport::SimpleMessage* in) {
  byte buf[BUFSIZE];

  int k = peer_channel_.Read(BUFSIZE, buf);
  if (k <= 0) {
    return false;
  }
  string in_msg;
  in_msg.assign((const char*) buf, k);
  if (!in->ParseFromString(in_msg)) {
    return false;
  }
  return true;
}

TaoProgramData::TaoProgramData() {
  initialized_ = false;
  tao_ = nullptr;
  program_key_ = nullptr;
  size_program_sym_key_ = 0;
  program_sym_key_ = nullptr;
  policy_key_ = nullptr;
  programCertificate_ = nullptr;
  policyCertificate_ = nullptr;
}

TaoProgramData::~TaoProgramData() {
  ClearProgramData();
}

void TaoProgramData::ClearProgramData() {
  initialized_ = false;
  tao_name_.clear();
  policy_cert_.clear();

  tao_ = nullptr;

  // TODO: erase key first.
  // Clear private key.
  if (program_key_ != nullptr) {
    RSA_free(program_key_);
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

bool TaoProgramData::ExtendName(string& subprin) {
  return tao_->ExtendTaoName(subprin);
}

bool TaoProgramData::InitTao(FDMessageChannel* msg, Tao* tao, string& cfg, string& path,
                              string& network, string& address, string& port) {

  // Set tao and msg for later calls.
  msg_ = msg;
  tao_ = tao;

  // Read policy cert.
  string policy_cert_file = path + "policyCert";
  string cert;
  if (ReadFile(policy_cert_file, &cert)) {
    return false;
  }

  // Parse policy cert.
  byte* pc = (byte*)policy_cert_.data();
  X509* parsed_policy_cert = d2i_X509(nullptr, (const byte**)&pc, policy_cert_.size());
  if (parsed_policy_cert == nullptr) {
    return false;
  }
  EVP_PKEY* evp_policy_key = X509_get_pubkey(parsed_policy_cert);
  policy_key_ = EVP_PKEY_get1_RSA(evp_policy_key);
  if (policy_key_ == nullptr) {
    return false;
  }
  int cert_OK = X509_verify(parsed_policy_cert, X509_get_pubkey(parsed_policy_cert));
  if (cert_OK <= 0) {
    return false;
  }

  // Extend principal name, hash of policy cert identifies policy extension.
  // TODO: Extend name with hash of policy cert.
  std::vector<std::unique_ptr<tao::PrinExt>> v;
  v.push_back(tao::make_unique<tao::PrinExt>("Validated", std::vector<std::unique_ptr<tao::Term>>()));

  tao::Prin p("key", tao::make_unique<tao::Bytes>("These are not key bytes"),
         tao::make_unique<tao::SubPrin>(std::move(v)));
  string subprin;
  {
    StringOutputStream raw_output_stream(&subprin);
    CodedOutputStream output_stream(&raw_output_stream);
    p.Marshal(&output_stream);
  }
  if (!ExtendName(subprin)) {
    return false;
  }

  // Retrieve extended name.
  if (!tao->GetTaoName(&tao_name_)) {
    return false;
  }

  // Get (or initialize) my symmetric keys.
  if (!InitializeSymmetricKeys(path, 32)) {
    return false;
  }

  // Get (or initialize) my program key.
  if (!InitializeProgramKey(path, 2048, network, address, port)) {
    return false;
  }
  return true;
}

void TaoProgramData::Print() {
  if (!initialized_) {
    printf("Program object is NOT initialized\n");
    return;
  }
  printf("Program object is NOT initialized\n");
  printf("Tao name: %s\n", tao_name_.c_str());
  printf("Policy cert: ");PrintBytes(policy_cert_.size(), (byte*)policy_cert_.data());printf("\n");
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

bool TaoProgramData::Seal(string& to_seal, string* sealed) {
  // string encodedBytes; if (!Base64WEncode(to_seal, &encodedBytes)) { }
  return tao_->Seal(to_seal, Tao::SealPolicyDefault, sealed);
}

bool TaoProgramData::Unseal(string& sealed, string* unsealed) {
  string policy;
  return tao_->Unseal(sealed, unsealed, &policy);
}

bool TaoProgramData::RequestDomainServiceCert(string& network, string& address,
                              string& port, string& attestation_string,
                              string& endorsement_cert,
                              string* program_cert) {

  if (policyCertificate_ == nullptr) {
    return false;
  }

  // Construct temporary channel key.
  RSA* tmpChannelKey = RSA_generate_key(2048, 0x010001ULL, nullptr, nullptr);
  if (tmpChannelKey == nullptr) {
    return false;
  }

  // Self signed cert.
  X509* tmpChannelCert = nullptr;
  X509_REQ* req = X509_REQ_new();;
  X509* cert = X509_new();
  string key_type("RSA");
  string common_name("Fred");
  string issuer("Self");
  string purpose("signing");

  string* modulus = nullptr; // FIX BN_to_bin(BIGNUM& n);
  string* exponent = nullptr; // FIX BN_to_bin(BIGNUM& n);
  EVP_PKEY* self = new EVP_PKEY();
  EVP_PKEY_assign_RSA(self, tmpChannelKey);
  if (!GenerateX509CertificateRequest(key_type, common_name, *exponent,
      *modulus, false, req)) {
    printf("Can't generate x509 request\n");
    return false;
  }
  if (!SignX509Certificate(tmpChannelKey, true, true,
                         issuer, purpose, 86400,
                         self, req, false, cert)) {
    printf("Can't sign x509 request\n");
    return false;
  }

  SslChannel domainChannel;

  if (!domainChannel.InitSslChannel(network, address, port,
        policyCertificate_, tmpChannelCert, tmpChannelKey, false)) {
    return false;
  }


  // Format request and send it to Domain service and get response.
  tao::CARequest request;
  tao::CAResponse response;
  tao::Attestation attestation;
  attestation.ParseFromString(attestation_string);
  request.set_type(tao::CAType::ATTESTATION);
  request.set_allocated_attestation(&attestation);
  string request_buf;
  request.SerializeToString(&request_buf);
  int bytes_written = domainChannel.Write(request_buf.size(), (byte*)request_buf.data());
  if (bytes_written <= 0) {
    return false;
  }
  byte read_buf[BUFSIZE];
  string response_buf;
  int bytes_read = domainChannel.Read(BUFSIZE, read_buf);
  if (bytes_read <= 0) {
    return false;
  }
  if (!response.ParseFromString(response_buf)) {
    return false;
  }
  if (response.type() != tao::CAType::ATTESTATION) {
    return false;
  }

  // Fill in program cert.
  program_cert_ = response.attestation().serialized_statement();
  return true;
}

bool TaoProgramData::InitializeSymmetricKeys(string& path, int keysize) {
  string sealed;
  string unsealed;
  string file_name = path + "sealedsymmetricKey";

  // Read key file.
  if (ReadFile(file_name, &sealed)) {
    if (!Unseal(sealed, &unsealed)) {
      printf("Can't open InitializeSymmetricKeys\n");
      return false;
    }
    size_program_sym_key_ = unsealed.size();
    program_sym_key_ = (byte*)malloc(size_program_sym_key_);
    memcpy(program_sym_key_, (byte*)unsealed.data(), size_program_sym_key_ );
    memset((byte*)unsealed.data(), 0, size_program_sym_key_);
    return true;
  }

  // Create keys, should really be a call to GetRandom.
  program_sym_key_ = (byte*)malloc(keysize);
  if (program_sym_key_ != nullptr) {
    return false;
  }
  size_program_sym_key_ = keysize;
  if (keysize != RAND_bytes(program_sym_key_, keysize)) {
    return false;
  }

  // Seal the key and save it.
  unsealed.assign((const char*)program_sym_key_, size_program_sym_key_);
  string policy = Tao::SealPolicyDefault;
  if (!tao_->Seal(unsealed, policy, &sealed)) {
    unsealed.clear();
    return false;
  }
  if (!WriteFile(file_name, sealed)) {
    return false;
  }
  unsealed.clear();
  return true;
}

bool TaoProgramData::InitializeProgramKey(string& path, int keysize,
        string& network, string& address, string& port) {

  string sealed_key_file_name = path + "sealedsigningKey";
  string signer_cert_file_name = path + "signerCert";
  string policy_cert_file_name = path + "policyCert";
  string sealed_key;
  string unsealed_key;
  string program_cert;


  // Read and parse policy cert.
  if (!ReadFile(policy_cert_file_name, &policy_cert_)) {
    return false;
  }
  byte* pc = (byte*)policy_cert_.data();
  policyCertificate_ = d2i_X509(nullptr, (const byte**)&pc,
        policy_cert_.size());
  if (policyCertificate_ == nullptr) {
    return false;
  }

  if (ReadFile(sealed_key_file_name, &sealed_key) &&
      ReadFile(signer_cert_file_name, &program_cert)) {
    if (!Unseal(sealed_key, &unsealed_key)) {
      printf("Can't open InitializeProgramKey\n");
      return false;
    }
    // Deserialize the key.
    program_key_ = DeserializeRsaPrivateKey(unsealed_key);
    return true;
  }

  // Generate the key;
  RSA* rsa_key = RSA_generate_key(2048, 0x010001ULL, nullptr, nullptr);
  if (rsa_key == nullptr) {
    return false;
  }
  program_key_ = rsa_key;

  // Get the program cert from the domain service.
  // First we need the endorsement cert.
  string endorsement_cert_file_name = path + "endorsementCert";
  string endorse_cert;
  if (ReadFile(endorsement_cert_file_name, &endorse_cert)) {
    return false;
  }

  // Construct a delegation statement.
  // TODO: make serialized key.
  string serialized_key;
  string msf;
  if (!MarshalSpeaksfor(serialized_key, tao_name_, &msf)) {
    return false;
  }

  // Get an attestation using delegation and program key;
  string attestation_string;
  if (!Attest(msf, &attestation_string)) {
    return false;
  }

  // Get Program Cert.
  if (!RequestDomainServiceCert(network, address, port, attestation_string, endorse_cert,
          &program_cert_)) {
    return false;
  }

  // Save the program cert.
  if (WriteFile(signer_cert_file_name, program_cert)) {
    return false;
  }

  // Serialize and save the RSAKey.
  string out_buf;
  if (!SerializeRsaPrivateKey(rsa_key, &out_buf)) {
    return false;
  }
  if (WriteFile(sealed_key_file_name, out_buf)) {
    return false;
  }
  return true;
}

