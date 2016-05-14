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
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/rand.h>

using std::string;
using std::unique_ptr;

using tao::Base64WDecode;
using tao::Base64WEncode;
using tao::FDMessageChannel;
using tao::InitializeApp;
using tao::MarshalSpeaksfor;
using tao::Tao;
using tao::TaoRPC;

void PrintBytes(int n, byte* in) {
  for (int i = 0; i < n; i++) printf("%02x", in[i]);
}

TaoChannel::TaoChannel() {
  fd_ = 0;
}

TaoChannel::~TaoChannel() {
  fd_ = 0;
}

bool TaoChannel::OpenTaoChannel(TaoProgramData& client_program_data,
                    string& serverAddress) {

  // Parse policy cert and make it root of chain.

  // Open TLS channel with Program cert.

  // Get peer name from organizational unit.

  return false;
}

void TaoChannel::CloseTaoChannel() {
  if (fd_ > 0)
    close(fd_);
  fd_ = 0;
}

bool TaoChannel::SendRequest(taosupport::SimpleMessage& out) {
  return false;
}

bool TaoChannel::GetRequest(taosupport::SimpleMessage* in) {
  return false;
}

TaoProgramData::TaoProgramData() {
  initialized_ = false;
  tao_ = nullptr;
  size_policy_cert_ = 0;
  policy_cert_ = nullptr;
  program_key_ = nullptr;
  size_program_sym_key_ = 0;
  program_sym_key_ = nullptr;
  size_program_cert_ = 0;
  program_cert_ = 0;
  policy_key_ = nullptr;
  size_endorsement_cert_ = 0;
  endorsement_cert_ = nullptr;
}

TaoProgramData::~TaoProgramData() {
  ClearProgramData();
}

void TaoProgramData::ClearProgramData() {
  initialized_ = false;
  tao_name_.clear();
  if (policy_cert_ != nullptr) {
    free(policy_cert_);
  }
  tao_ = nullptr;
  size_policy_cert_ = 0;
  policy_cert_ = nullptr;

  // Clear private key.
  if (program_key_ != nullptr) {
    RSA_free(program_key_);
  }
  program_key_ = nullptr;

  if (size_program_sym_key_ > 0 && program_sym_key_ != nullptr) {
    memset(program_sym_key_, 0, size_program_sym_key_);
    free(program_sym_key_);
  }
}

bool TaoProgramData::ExtendName(string& subprin) {
  return false;
}

// if (unsealed->compare(bytes) != 0) { }

bool TaoProgramData::InitTao(FDMessageChannel* msg, Tao* tao, string& cfg, string& path,
			      string& network, string& address) {

  // Set tao and msg for later calls.
  msg_ = msg;
  tao_ = tao;

  // Load domain
  string policy_cert_file = path + "policyCert";

  // Get policy cert.
  string cert;
  if (ReadFile(policy_cert_file, &cert)) {
    return false;
  }
  size_policy_cert_ = cert.size();
  policy_cert_ = (byte*) malloc(size_policy_cert_);
  memcpy(policy_cert_, cert.data(), size_policy_cert_);

  // Parse policy cert.
  X509* parsed_policy_cert = d2i_X509(nullptr, (const byte**)&policy_cert_,
                         size_policy_cert_);
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
  string subprin;
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
  if (!InitializeProgramKey(path, 2048, network, address)) {
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
  printf("Policy cert: ");PrintBytes(size_policy_cert_, policy_cert_);printf("\n");
  printf("Program key: "); printf("TODO"); printf("\n");
  printf("Sym key: ");PrintBytes(size_program_sym_key_, program_sym_key_);printf("\n");
  printf("Program cert: ");PrintBytes(size_program_cert_, program_cert_);printf("\n");
  printf("Program path: %s\n", program_file_path_.c_str());
}

void TaoChannel::Print() {
  printf("fd: %d\n", fd_);
  printf("Server name: %s\n", server_name_.c_str());
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
			      string& attestation,
                              int size_endorse_cert, byte* endorse_cert,
			      string* program_cert) {
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
	string& network, string& address) {

  string sealed_key_file_name = path + "sealedsigningKey";
  string signer_cert_file_name = path + "signerCert";
  string sealed_key;
  string unsealed_key;
  string program_cert;

  if (ReadFile(sealed_key_file_name, &sealed_key) &&
      ReadFile(signer_cert_file_name, &program_cert)) {
    if (!Unseal(sealed_key, &unsealed_key)) {
      printf("Can't open InitializeProgramKey\n");
      return false;
    }
    // Deserialize the key.
    program_key_ = DeserializeRsaPrivateKey(unsealed_key);

    // Fill the policy cert.
    size_program_cert_ = program_cert.size();
    program_cert_ = (byte*) malloc(size_program_cert_);;
    memcpy(program_cert_, program_cert.data(), size_program_cert_);
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
  size_endorsement_cert_= endorse_cert.size();
  endorsement_cert_ = (byte*) malloc(size_endorsement_cert_);;
  memcpy(endorsement_cert_, endorse_cert.data(), size_endorsement_cert_);

  // Construct a delegation statement.
  string msf;
  // if (!MarshalSpeaksfor(fakeKey, taoName, &msf)) {
  //  return false;
  // }

  // Get an attestation using delegation and program key;
  string attestation;

  // Get Program Cert.
  if (!RequestDomainServiceCert(network, address, attestation, size_endorsement_cert_,
	  endorsement_cert_, &program_cert)) {
    return false;
  }
  size_program_cert_= endorse_cert.size();
  program_cert_ = (byte*) malloc(size_program_cert_);
  memcpy(program_cert_, program_cert.data(), size_program_cert_);

  // Save the program cert.
  if (WriteFile(signer_cert_file_name, program_cert)) {
    return false;
  }

  // Serialize the RSAKey.
  string out_buf;
  if (!SerializeRsaPrivateKey(rsa_key, &out_buf)) {
    return false;
  }

  // Save the sealed key.
  if (WriteFile(sealed_key_file_name, out_buf)) {
    return false;
  }
  return true;
}

