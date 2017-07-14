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

#include "agile_crypto_support.h"

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
  string address_;
  string port_;

  // What kind of Authority Service?
  bool useSimpleService_;

  // Channel to communicate with host.
  tao::FDMessageChannel* msg_;

  // Tao object interface
  tao::Tao* tao_;

  // Marshalled tao name (a Prin).
  string marshalled_tao_name_;

  // Printable tao name
  string tao_name_;

  string policy_cert_;
  X509* policy_certificate_;
  Verifier* policy_verifying_key_;

  // host certificate.
  string host_cert_file_name_;
  string host_cert_;
  std::list<string> host_cert_chain_;

  // keys
  Signer* program_signing_key_;
  Verifier* verifying_key_;
  Crypter* crypting_key_;

  // Der encoded and parsed X509 program certificate.
  string program_cert_;
  X509* program_certificate_;
  std::list<string> program_cert_chain_;

  bool SealMaterial(string& to_seal, string* sealed);
  bool UnsealMaterial(string& sealed, string* unsealed);
  bool Attest(string& to_attest, string* attested);

  bool SaveProgramData(tao_support::SavedProgramData& pd, string* out);
  bool RecoverProgramData(string in, tao_support::SavedProgramData* pd);

  bool InitProgramKeys(tao_support::SavedProgramData* pd);
  bool GetProgramData();

public:
  TaoProgramData();
  ~TaoProgramData();

  void ClearProgramData();
  bool InitTao(string& cipher_suite, tao::FDMessageChannel* msg, tao::Tao* tao,
       string& policy_key_path, string& host_key_path, string& program_path,
       string& network, string& address, string& port, bool useSimpleService);

  // Accessors
  bool ExtendName(string& subprin);
  bool GetTaoName(string* name);

  void Print();

  bool GetCipherSuite(string* keyType);

  bool GetPolicyCert(string* cert);
  bool GetProgramCert(string* cert);

  void SetPolicyCertificate(X509* c);
  X509* GetPolicyCertificate();
  void SetProgramCertificate(X509* c);
  X509* GetProgramCertificate();
  std::list<string>* GetProgramCertChain();

  bool InitCounter(string& label, int64_t& c);
  bool GetCounter(string& label, int64_t* c);
  bool RollbackProtectedSeal(string& label, string& data, string* sealed);
  bool RollbackProtectedUnseal(string& sealed, string* data, string* policy);

private:
  // This should be private.
  bool RequestDomainServiceCert(string& attestation_string, string& host_cert,
          std::list<string> host_certs_chain, string* program_cert,
          std::list<string>* program_certs_chain);
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
#endif
