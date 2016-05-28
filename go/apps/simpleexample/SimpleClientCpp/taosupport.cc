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

TaoChannel::TaoChannel() {
  peerCertificate_ = nullptr;
}

TaoChannel::~TaoChannel() {
}

bool TaoChannel::OpenTaoChannel(TaoProgramData& client_program_data,
                    string& serverAddress, string& port) {

  // Parse policy cert and program cert.
  if (client_program_data.policy_cert_.size() == 0 ) {
    printf("No policy cert.\n");
    return false;
  }
  if (client_program_data.policyCertificate_ == nullptr) {
    byte* pc = (byte*)client_program_data.policy_cert_.data();
    client_program_data.policyCertificate_ = d2i_X509(nullptr, (const byte**)&pc,
          client_program_data.policy_cert_.size());
    if (client_program_data.policyCertificate_ == nullptr) {
      printf("No policy certificate.\n");
      return false;
    }
  }
  if (client_program_data.program_cert_.size() == 0 ) {
    printf("No program certificate.\n");
    return false;
  }
  if (client_program_data.programCertificate_ == nullptr) {
    byte* pc = (byte*)client_program_data.program_cert_.data();
    client_program_data.policyCertificate_ = d2i_X509(nullptr, (const byte**)&pc,
          client_program_data.program_cert_.size());
    if (client_program_data.programCertificate_ == nullptr) {
      printf("Can't translate program certificate.\n");
      return false;
    }
  }

  // Open TLS channel with Program cert.
  string network("tcp");
  if (!peer_channel_.InitClientSslChannel(network, serverAddress, port,
                    client_program_data.policyCertificate_,
                    client_program_data.programCertificate_,
                    client_program_data.program_key_type_,
                    client_program_data.program_key_, true)) {
    printf("Can't Init SSl channel.\n");
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

bool TaoChannel::SendRequest(taosupport::SimpleMessage& out) {
  string msg_buf;

  if (!out.SerializeToString(&msg_buf)) {
    printf("Can't serialize request.\n");
    return false;
  }
  int k = peer_channel_.Write(msg_buf.size(), (byte*)msg_buf.data());
  return k > 0;
}

bool TaoChannel::GetRequest(taosupport::SimpleMessage* in) {
  byte buf[BUFSIZE];

  int k = peer_channel_.Read(BUFSIZE, buf);
  if (k <= 0) {
    printf("Can't read request channel.\n");
    return false;
  }
  string in_msg;
  in_msg.assign((const char*) buf, k);
  if (!in->ParseFromString(in_msg)) {
    printf("Can't parse response from channel.\n");
    return false;
  }
  return true;
}

TaoProgramData::TaoProgramData() {
  initialized_ = false;
  tao_ = nullptr;
  program_key_type_.clear();
  program_key_ = nullptr;
  size_program_sym_key_ = 0;
  program_sym_key_ = nullptr;
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

bool TaoProgramData::InitTao(FDMessageChannel* msg, Tao* tao, string& cfg,
       string& path, string& network, string& address, string& port) {

  // Set tao and msg for later calls.
  msg_ = msg;
  tao_ = tao;

  // Read policy cert.
  string policy_cert_file = path + "/policy_keys/cert";
  if (!ReadFile(policy_cert_file, &policy_cert_)) {
    printf("Can't read policy cert.\n");
    return false;
  }
  PrintBytes((int)policy_cert_.size(), (byte*)policy_cert_.data()); printf("\n");

  // Parse policy cert.
  byte* pc = (byte*)policy_cert_.data();
  X509* parsed_policy_cert = d2i_X509(nullptr, (const byte**)&pc,
          policy_cert_.size());
  if (parsed_policy_cert == nullptr) {
    printf("Can't DER parse policy cert.\n");
    return false;
  }

  string keyType;
  int key_size;
  EVP_PKEY* evp_policy_key = X509_get_pubkey(parsed_policy_cert);
  if (evp_policy_key == nullptr) {
    printf("Can't get policy public key from cert.\n");
    return false;
  }
  int key_type = EVP_PKEY_id(evp_policy_key);
  if (EVP_PKEY_EC == key_type) {
    keyType = "ECC";
    key_size = 256;
  } else if (EVP_PKEY_RSA == key_type) {
    keyType = "RSA";
    key_size = 2048;
  } else {
    printf("Unsupported key type.\n");
    return false;
  }


  // Extend principal name, hash of policy cert identifies policy extension.

  // Hash of policy cert.
  byte policy_hash[32];
  SHA256_CTX sha256;
  SHA256_Init(&sha256);
  SHA256_Update(&sha256, (byte*)policy_cert_.data(), policy_cert_.size());
  SHA256_Final(policy_hash, &sha256);
  string* hexPolicyHash = ByteToHexLeftToRight(32, policy_hash);

  std::vector<std::unique_ptr<tao::PrinExt>> v;

  // Should it be "PolicyCertHash" rather than "key"?
  std::vector<std::unique_ptr<tao::Term>> w;
  w.push_back(tao::make_unique<tao::Bytes>(hexPolicyHash->c_str()));
  v.push_back(tao::make_unique<tao::PrinExt> ("key", std::move(w)));
  tao::SubPrin p(std::move(v));
  string subprin;
  {
    StringOutputStream raw_output_stream(&subprin);
    CodedOutputStream output_stream(&raw_output_stream);
    p.Marshal(&output_stream);
  }

#if 0
// for debug
string debugFileName("/Domains/extendtest");
if (!WriteFile(debugFileName, subprin)) {
    printf("Can't write %s.\n", debugFileName.c_str());
}
#endif
  if (!tao_->ExtendTaoName(subprin)) {
    printf("Can't extend name.\n");
    return false;
  }

  // Retrieve extended name.
  if (!tao->GetTaoName(&tao_name_)) {
    printf("Can't get tao name.\n");
    return false;
  }

  // Get (or initialize) my symmetric keys.
  if (!InitializeSymmetricKeys(path, 32)) {
    printf("Can't init symmetric keys.\n");
    return false;
  }

  // Get (or initialize) my program key.
  if (!InitializeProgramKey(path, keyType, key_size, network, address, port)) {
    printf("Can't init program keys.\n");
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
    printf("Policy cert is null.\n");
    return false;
  }

  X509_REQ* req = X509_REQ_new();;
  X509* cert = X509_new();
  string key_type("ECC");
  string common_name("Fred");
  string issuer("Self");
  string purpose("signing");

  EVP_PKEY* self = GenerateKey(key_type, 256);
  if (self == nullptr) {
    printf("Can't Generate temporary channel key.\n");
    return false;
  }
  if (!GenerateX509CertificateRequest(key_type, common_name, 
          self, false, req)) {
    printf("Can't generate x509 request\n");
    return false;
  }

  if (!SignX509Certificate(self, true, true, issuer, purpose, 86400,
                           self, req, false, cert)) {
    printf("Can't sign x509 request\n");
    return false;
  }

  SslChannel domainChannel;
  string keyType("RSA");

  if (!domainChannel.InitClientSslChannel(network, address, port,
        policyCertificate_, cert, keyType, self, false)) {
    printf("Can't init ssl channel to domain server.\n");
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
    printf("Domain channel write failure.\n");
    return false;
  }
  byte read_buf[BUFSIZE];
  string response_buf;
  int bytes_read = domainChannel.Read(BUFSIZE, read_buf);
  if (bytes_read <= 0) {
    printf("Domain channel read failure.\n");
    return false;
  }
  if (!response.ParseFromString(response_buf)) {
    printf("Domain channel parse failure.\n");
    return false;
  }
  if (response.type() != tao::CAType::ATTESTATION) {
    printf("Not attestation type.\n");
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

#if 1
printf("symmetric keys are in %s\n", file_name.c_str());
#endif
  // Read key file.
  if (ReadFile(file_name, &sealed)) {
    if (!Unseal(sealed, &unsealed)) {
      printf("Can't open InitializeSymmetricKeys %s\n", file_name.c_str());
      return false;
    }
    size_program_sym_key_ = unsealed.size();
    program_sym_key_ = (byte*)malloc(size_program_sym_key_);
    memcpy(program_sym_key_, (byte*)unsealed.data(), size_program_sym_key_ );
    memset((byte*)unsealed.data(), 0, size_program_sym_key_);
    return true;
  }

  // Create keys, should really be a call to GetRandom.
  // TODO: free this
  program_sym_key_ = (byte*)malloc(keysize);
  if (program_sym_key_ == nullptr) {
    printf("InitializeSymmetricKeys: Can't malloc symmetric key.\n");
    return false;
  }
  size_program_sym_key_ = keysize;
  if (keysize != RAND_bytes(program_sym_key_, keysize)) {
    printf("InitializeSymmetricKeys: Can't generate symmetric key.\n");
    return false;
  }

  // Seal the key and save it.
  unsealed.assign((const char*)program_sym_key_, size_program_sym_key_);
  string policy = Tao::SealPolicyDefault;
  if (!tao_->Seal(unsealed, policy, &sealed)) {
    unsealed.clear();
    printf("InitializeSymmetricKeys: Can't seal sym keys\n");
    return false;
  }
  if (!WriteFile(file_name, sealed)) {
    printf("InitializeSymmetricKeys: write sealed sym keys.\n");
    return false;
  }
  unsealed.clear();
  return true;
}

bool TaoProgramData::InitializeProgramKey(string& path, string& key_type,
        int key_size, string& network, string& address, string& port) {
  string sealed_key_file_name = path + "/sealedsigningKey";
  string signer_cert_file_name = path + "/signerCert";
  string policy_cert_file_name = path + "/policyCert";
  string sealed_key;
  string unsealed_key;
  string program_cert;

#if 1
printf("Policy cert is in %s\n", policy_cert_file_name.c_str());
printf("Program cert is in %s\n", signer_cert_file_name.c_str());
printf("Program key is in %s\n", sealed_key_file_name.c_str());
#endif
  // Read and parse policy cert.
  if (!ReadFile(policy_cert_file_name, &policy_cert_)) {
    printf("InitializeProgramKey: Can't read policy cert.\n");
    return false;
  }
  byte* pc = (byte*)policy_cert_.data();
  policyCertificate_ = d2i_X509(nullptr, (const byte**)&pc,
        policy_cert_.size());
  if (policyCertificate_ == nullptr) {
    printf("InitializeProgramKey: policy certificate is null.\n");
    return false;
  }

  if (ReadFile(sealed_key_file_name, &sealed_key) &&
      ReadFile(signer_cert_file_name, &program_cert)) {
    if (!Unseal(sealed_key, &unsealed_key)) {
      printf("InitializeProgramKey: Can't open InitializeProgramKey\n");
      return false;
    }
    // Deserialize the key.
    if (!DeserializePrivateKey(unsealed_key, &program_key_type_, &program_key_)) {
      printf("InitializeProgramKey: Can't DeserializePrivateKey\n");
      return false;
    }
    return true;
  }

  // Generate the key and specify key bytes.
  EVP_PKEY* program_key_ = GenerateKey(key_type, key_size);
  if (program_key_ == nullptr) {
    printf("InitializeProgramKey: couldn't generate program key.\n");
    return false;
  }
  string* key_bytes = GetKeyBytes(program_key_);
  if (key_bytes == nullptr) {
    printf("InitializeProgramKey: couldn't get key bytes.\n");
    return false;
  }

  // Get the program cert from the domain service.
  // First, we need the endorsement cert.
  string endorsement_cert_file_name = path + "endorsementCert";
  string endorse_cert;
  if (!ReadFile(endorsement_cert_file_name, &endorse_cert)) {
    printf("InitializeProgramKey: couldn't read endorsement cert.\n");
    return false;
  } 
  // Construct a delegation statement.
  string serialized_key;

  std::vector<std::unique_ptr<tao::PrinExt>> v;
  v.push_back(tao::make_unique<tao::PrinExt>("Validated", std::vector<std::unique_ptr<tao::Term>>()));

  // Should this be "ProgramKeyHash" rather than "key"?
  tao::Prin p("key", tao::make_unique<tao::Bytes>(key_bytes->c_str()),
         tao::make_unique<tao::SubPrin>(std::move(v)));
  {
    StringOutputStream raw_output_stream(&serialized_key);
    CodedOutputStream output_stream(&raw_output_stream);
    p.Marshal(&output_stream);
  }
  string msf;
  if (!MarshalSpeaksfor(serialized_key, tao_name_, &msf)) {
    printf("InitializeProgramKey: couldn't MarshalSpeaksfor.\n");
    return false;
  }

  // Get an attestation using delegation and program key;
  string attestation_string;
  if (!Attest(msf, &attestation_string)) {
    printf("InitializeProgramKey: couldn't Attest.\n");
    return false;
  }

  // Get Program Cert.
  if (!RequestDomainServiceCert(network, address, port, attestation_string,
          endorse_cert, &program_cert_)) {
    printf("InitializeProgramKey: couldn't RequestDomainServiceCert.\n");
    return false;
  }

  // Save the program cert.
  if (!WriteFile(signer_cert_file_name, program_cert)) {
    printf("InitializeProgramKey: couldn't writed signed program cert.\n");
    return false;
  }

  // Serialize Key.
  string out_buf;
  if (!SerializePrivateKey(program_key_type_, program_key_, &out_buf)) {
    printf("InitializeProgramKey: couldn't serialize private key.\n");
    return false;
  }

  // Seal the key and save it.
  string sealed_out;
  string policy = Tao::SealPolicyDefault;
  if (!tao_->Seal(out_buf, policy, &sealed_out)) {
    out_buf.clear();
    printf("InitializeProgramKeys: Can't seal program key\n");
    return false;
  }
  if (!WriteFile(sealed_key_file_name, sealed_out)) {
    printf("InitializeProgramKey: couldn't write sealed private key.\n");
    return false;
  }
  return true;
}

