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

#ifndef __TAOSUPPORT_H__
#define __TAOSUPPORT_H__

#include "tao/fd_message_channel.h"
#include "tao/tao_rpc.h"
#include "tao/util.h"

#include "attestation.pb.h"

#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <string>
#include <list>

#ifndef byte
typedef unsigned char byte;
#endif

class TaoProgramData {
private:

  // Has InitTao initialized me successfully?
  bool  initialized_;

  // cipher suite
  string cipher_suite_;

  // Program path
  string program_path_;

  // Policy cert file name (including path).
  string policy_cert_file_name_;

  // network
  string network_;

  // Address of Authority.
  string address_;
  string port_;

  // What kind of Authority Service?
  bool useSimpleService_;

  // Channel to communicate with host.
  tao::FDMessageChannel* msg_;

  // Tao object interface
  tao::Tao* tao_;

  // Endorsement for AIK for TPM
  string endorsement_cert_;

  // Marshalled tao name (a Prin).
  string marshalled_tao_name_;

  // Printable tao name
  string tao_name_;

  string policy_cert_;
  X509* policy_certificate_;
  Verifier* policy_verifying_key_;

  // keys
  Signer* program_signing_key_;
  Verifier* verifying_key_;
  Crypter* crypting_key_;

  // Der encoded and parsed X509 program certificate.
  string program_cert_;
  X509* program_certificate_;

  // Cert chain for Program Certificate.
  std::list<string> certs_in_chain_;

  bool SealMaterial(string& to_seal, string* sealed);
  bool UnsealMaterial(string& sealed, string* unsealed);
  bool Attest(string& to_attest, string* attested);

  bool SaveProgramData(string* out);
  bool RecoverProgramData(string& in);

  bool InitProgramKeys(tao_support::SavedProgramData* pd);
  bool GetProgramData();

public:
  TaoProgramData();
  ~TaoProgramData();

  void ClearProgramData();
  bool InitTao(tao::FDMessageChannel* msg, tao::Tao* tao, string&, string&,
               string& network, string& address, string& port, string& cipher_suite,
               bool useSimpleService);

  // Accessors
  bool ExtendName(string& subprin);
  bool GetTaoName(string* name);

  void Print();

  bool GetPolicyCert(string* cert);
  X509* GetPolicyCertificate();
  X509* GetProgramCertificate();
  bool GetProgramCert(string* cert);
  void SetProgramCertificate(X509* c);
  std::list<string>* GetCertChain();

  bool InitCounter(string& label, int64_t& c);
  bool GetCounter(string& label, int64_t* c);
  bool RollbackProtectedSeal(string& label, string& data, string* sealed);
  bool RollbackProtectedUnseal(string& sealed, string* data, string* policy);

private:
  // This should be private.
  bool RequestDomainServiceCert(string& network, string& address, string& port,
          string& attestation_string, string& endorsement_cert,
          string* program_cert, std::list<string>* certsinChain);
};

class TaoChannel {
public:
  SslChannel peer_channel_;
  X509* peerCertificate_;
  string peer_name_;

  TaoChannel();
  ~TaoChannel();
  bool OpenTaoChannel(TaoProgramData& client_program_data,
                      string& serverAddress, string& port);
  void CloseTaoChannel();
  bool SendRequest(int size, byte* out);
  bool GetRequest(int* size, byte* in);
  void Print();
};

bool GetKeyBytes(EVP_PKEY* pKey, string* bytes_out);

bool Protect(string& crypter_suite, int sizeKey, byte* key, int sizeIn, byte* in,
             int* sizeOut, byte* out);
bool Unprotect(string& crypter_suite, int sizeKey, byte* key, int sizeIn, byte* in,
             int* sizeOut, byte* out);
#endif


