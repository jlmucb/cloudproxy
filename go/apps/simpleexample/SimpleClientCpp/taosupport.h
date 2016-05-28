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
#include <taosupport.pb.h>

#ifndef __TAOSUPPORT_H__
#define __TAOSUPPORT_H__

#include "tao/fd_message_channel.h"
#include "tao/tao_rpc.h"
#include "tao/util.h"

#include "attestation.pb.h"

#include <taosupport.pb.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#ifndef byte
typedef unsigned char byte;
#endif

class TaoProgramData {
public:
  bool  initialized_;
  tao::FDMessageChannel* msg_;
  tao::Tao* tao_;

  int endorsement_cert_;

  string tao_name_;

  string policy_cert_;
  X509* policyCertificate_;

  // Tao data.
  string program_key_type_;
  EVP_PKEY* program_key_;

  string program_cert_;
  X509* programCertificate_;

  int size_program_sym_key_;
  byte* program_sym_key_;
  string program_file_path_;

  TaoProgramData();
  ~TaoProgramData();
  void ClearProgramData();
  bool InitTao(tao::FDMessageChannel* msg, tao::Tao* tao, string&, string&,
               string& network, string& address, string& port);
  void Print();

  bool InitializeProgramKey(string& path, string& key_type, int key_size,
                            string& network, string& address, string& port);
  bool InitializeSymmetricKeys(string& path, int keysize);
  bool ExtendName(string& subprin);

  bool Seal(string& to_seal, string* sealed);
  bool Unseal(string& sealed, string* unsealed);
  bool Attest(string& to_attest, string* attested);
  bool RequestDomainServiceCert(string& network, string& address, string& port,
          string& attestation_string, string& endorsement_cert,
          string* program_cert);
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
  bool SendRequest(taosupport::SimpleMessage& out);
  bool GetRequest(taosupport::SimpleMessage* in);
  void Print();
};
#endif


