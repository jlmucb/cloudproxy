//  File: attestation_verifier.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An implementation of attestation verification
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
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
// limitations under the License.

#include "tao/attestation_verifier.h"
#include "tao/attestation.pb.h"

using keyczar::Keyczar;
using keyczar::Keyset;
using keyczar::Verifier;

typedef unsigned char BYTE;

namespace tao {
AttestationVerifier::AttestationVerifier(const string &aik_cert_file,
                                         const string &public_policy_key_file,
                                         TaoAuth *auth_manager)
    : aik_rsa_(nullptr), policy_key_(nullptr), auth_manager_(auth_manager) {}

bool AttestationVerifier::Init() {
  // TODO(tmroeder): initialize the keys
  return false;
}

bool AttestationVerifier::VerifyAttestation(const string &attestation,
                                            string *data) const {
  Attestation a;
  if (!a.ParseFromString(attestation)) {
    LOG(ERROR) << "Could not deserialize an Attestation";
    return false;
  }

  // Choose the verifier to use based on the type of the attestation.
  bool verified = false;
  switch (a.type()) {
    case ROOT:
      verified = CheckRootSignature(a);
      break;
    case INTERMEDIATE:
      verified = CheckIntermediateSignature(a);
      break;
    case TPM_1_2_QUOTE:
      verified = CheckTPM12Quote(a);
      break;
    case LEGACY:
      LOG(ERROR) << "Legacy attestations are not currently supported";
      return false;
    case UNKNOWN:
    default:
      LOG(ERROR) << "Unknown attestation type";
      return false;
  }

  if (!verified) {
    LOG(ERROR) << "Could not verify the signature";
    return false;
  }

  // Check that this attestation is authorized.
  // TODO(tmroeder): make sure this is using the right hash algorithm, too
  // TODO(tmroeder): Note that this will need to use the quote when the hash
  // algorithm is "TPM1.2 Quote"
  if (!auth_manager_->IsAuthorized(a)) {
    LOG(ERROR) << "The attested program was not authorized";
    return false;
  }

  Statement s;
  if (!s.ParseFromString(a.serialized_statement())) {
    LOG(ERROR) << "Could not parse the statement";
    return false;
  }

  data->assign(s.data().data(), s.data().size());

  VLOG(1) << "The attestation passed verification";

  return true;
}

bool AttestationVerifier::CheckRootSignature(const Attestation &a) const {
  if (a.type() != ROOT) {
    LOG(ERROR) << "This is not a ROOT attestation, but it claims to be "
                  "signed with the public key";
    return false;
  }

  VLOG(2) << "About to verify the signature against the policy key";
  VLOG(2) << "a.serialized_statement().size = "
          << (int)a.serialized_statement().size();
  VLOG(2) << "a.signature().size = " << (int)a.signature().size();

  // Verify against the policy key.
  if (!policy_key_->Verify(a.serialized_statement(), a.signature())) {
    LOG(ERROR) << "Verification failed with the policy key";
    return false;
  }

  return true;
}

bool AttestationVerifier::CheckIntermediateSignature(
    const Attestation &a) const {
  if (a.type() != INTERMEDIATE) {
    LOG(ERROR)
        << "Expected this Attestation to be INTERMEDIATE, but it was not";
    return false;
  }

  // Recurse on the attestation to get the key information from the cert.
  string key_data;
  if (!VerifyAttestation(a.cert(), &key_data)) {
    LOG(ERROR) << "Could not verify the public_key attestation";
    return false;
  }

  KeyczarPublicKey kpk;
  if (!kpk.ParseFromString(key_data)) {
    LOG(ERROR) << "Could not deserialize the public key for this attestation";
    return false;
  }

  // Get a Keyset corresponding to this public key
  Keyset *k = nullptr;
  if (!DeserializePublicKey(kpk, &k)) {
    LOG(ERROR) << "Could not deserialize the public key";
    return false;
  }

  scoped_ptr<Verifier> v(new Verifier(k));
  v->set_encoding(Keyczar::NO_ENCODING);
  if (!v->Verify(a.serialized_statement(), a.signature())) {
    LOG(ERROR) << "The statement in an attestation did not have a valid "
                  "signature from its public key";
    return false;
  }

  return true;
}

bool AttestationVerifier::CheckTPM12Quote(const Attestation &a) const {
  if (a.type() != TPM_1_2_QUOTE) {
    LOG(ERROR) << "This method can only verify TPM_1_2_QUOTE attestations";
    return false;
  }

  // Hash the statement with SHA1 for the external data part of the quote.
  BYTE statement_hash[20];
  SHA1(reinterpret_cast<const BYTE *>(a.serialized_statement().data()),
       a.serialized_statement().size(), statement_hash);

  // The quote can be verified in a qinfo, which has a header of 8 bytes, and
  // two hashes.  The first hash is the hash of the external data, and the
  // second is the hash of the quote itself (pcr_buf above with length in
  // index). This can be hashed and verified directly by OpenSSL.

  BYTE qinfo[8 + 2 * 20];
  qinfo[0] = 1;
  qinfo[1] = 1;
  qinfo[2] = 0;
  qinfo[3] = 0;
  qinfo[4] = 'Q';
  qinfo[5] = 'U';
  qinfo[6] = 'O';
  qinfo[7] = 'T';

  // The quote in a TPM_1_2_QUOTE is the quote data itself.
  if (!a.has_quote()) {
    LOG(ERROR) << "A TPM_1_2_QUOTE must have a quote value";
    return false;
  }

  SHA1(reinterpret_cast<const BYTE *>(a.quote().data()), a.quote().size(),
       qinfo + 8);
  memcpy(qinfo + 8 + 20, statement_hash, sizeof(statement_hash));

  BYTE quote_hash[20];
  SHA1(qinfo, sizeof(qinfo), quote_hash);
  if (RSA_verify(NID_sha1, quote_hash, sizeof(quote_hash),
                 reinterpret_cast<const BYTE *>(a.signature().data()),
                 a.signature().size(), aik_rsa_.get()) !=
      1) {
    LOG(ERROR) << "The RSA signature did not pass verification";
    return false;
  }

  return true;
}
}  // namespace tao
