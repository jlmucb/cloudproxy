//  File: whitelist_auth.cc
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: An implementation of the whitelist manager that handles
//  whitelist files signed with the policy public key.
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

#include "tao/whitelist_auth.h"

#include <arpa/inet.h>

#include <fstream>

#include <keyczar/base/base64w.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "tao/hosted_programs.pb.h"
#include "tao/attestation.pb.h"
#include "tao/keyczar_public_key.pb.h"
#include "tao/util.h"

using keyczar::Keyczar;
using keyczar::Keyset;
using keyczar::Verifier;

using std::ifstream;

typedef unsigned char BYTE;
typedef unsigned int UINT32;
typedef unsigned short UINT16;

namespace tao {
bool WhitelistAuth::Init() {
  // Load the public policy key
  policy_key_.reset(keyczar::Verifier::Read(policy_public_key_.c_str()));
  policy_key_->set_encoding(keyczar::Keyczar::NO_ENCODING);

  // load the whitelist file and check its signature
  ifstream whitelist(whitelist_path_);

  SignedWhitelist sw;
  sw.ParseFromIstream(&whitelist);
  if (!policy_key_->Verify(sw.serialized_whitelist(), sw.signature())) {
    LOG(ERROR) << "The signature did not verify on the signed whitelist";
    return false;
  }

  Whitelist w;
  const string &serialized_w = sw.serialized_whitelist();

  if (!w.ParseFromString(serialized_w)) {
    LOG(ERROR) << "Could not parse the serialized whitelist";
    return false;
  }

  for (int i = 0; i < w.programs_size(); i++) {
    const HostedProgram &hp = w.programs(i);
    if (whitelist_.find(hp.name()) != whitelist_.end()) {
      LOG(ERROR) << "Can't add " << hp.name() << " to the whitelist twice";
      return false;
    }

    whitelist_[hp.name()] = hp.hash();
    hash_whitelist_.insert(hp.hash());
  }

  return true;
}

bool WhitelistAuth::IsAuthorized(const string &program_hash) const {
  bool authorized = (hash_whitelist_.find(program_hash) != hash_whitelist_.end());
  if (!authorized) {
    LOG(ERROR) << "Could not find the hash " << program_hash
               << " on the whitelist";
  }

  return authorized;
}

bool WhitelistAuth::IsAuthorized(const string &program_name,
                                 const string &program_hash) const {
  auto it = whitelist_.find(program_name);
  if (it == whitelist_.end()) {
    LOG(ERROR) << "The program " << program_name << " with hash "
               << program_hash << " was not found on the whitelist";
    return false;
  }

  return (it->second.compare(program_hash) == 0);
}

bool WhitelistAuth::CheckAuthorization(const Attestation &attestation) const {
  Statement s;
  if (!s.ParseFromString(attestation.serialized_statement())) {
    LOG(ERROR) << "Could not parse the statement from an attestation";
    return false;
  }

  // check the time to make sure it hasn't expired
  time_t cur_time;
  time(&cur_time);
  if (cur_time > s.expiration()) {
    LOG(ERROR) << "This attestation has expired";
    return false;
  }

  if (s.hash_alg().compare("SHA256") == 0) {
    // This is a normal program-like hash, so check the whitelist directly
    return IsAuthorized(s.hash());
  }

  if (attestation.has_quote()) {
    // Extract the PCRs as a single string and look for them in the whitelist.
    string quote(attestation.quote().data(), attestation.quote().size());
    size_t quote_len = quote.size();
    if (quote_len < sizeof(UINT16)) {
      LOG(ERROR) << "The quote was not long enough to contain a mask length";
      return false;
    }

    const char *quote_bytes = quote.c_str();
    UINT32 index = 0;
    UINT16 mask_len = ntohs(*(UINT16 *)(quote_bytes + index));
    index += sizeof(UINT16);

    // skip the mask bytes
    if ((quote_len < index) || (quote_len - index < mask_len)) {
      LOG(ERROR) << "The quote was not long enough to contain the mask";
      return false;
    }

    index += mask_len;

    if ((quote_len < index) || (quote_len - index < sizeof(UINT32))) {
      LOG(ERROR) << "The quote was not long enough to contain the pcr length";
      return false;
    }

    UINT32 pcr_len = ntohl(*(UINT32 *)(quote_bytes + index));
    index += sizeof(UINT32);

    if ((quote_len < index) || (quote_len - index < pcr_len)) {
      LOG(ERROR) << "The quote was not long enough to contain the PCRs";
      return false;
    }

    string pcrs(quote_bytes + index, pcr_len);

    // The whitelist uses Base64W encoding for hashes
    string serialized;
    if (!keyczar::base::Base64WEncode(pcrs, &serialized)) {
      LOG(ERROR) << "Can't serialize the PCRs";
      return false;
    }

    return IsAuthorized(serialized);
  }

  return (attestation.type() == ROOT);
}

bool WhitelistAuth::VerifyAttestation(const string &attestation,
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
  if (!CheckAuthorization(a)) {
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

bool WhitelistAuth::CheckRootSignature(const Attestation &a) const {
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

bool WhitelistAuth::CheckIntermediateSignature(const Attestation &a) const {
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

bool WhitelistAuth::CheckTPM12Quote(const Attestation &a) const {
  if (a.type() != TPM_1_2_QUOTE) {
    LOG(ERROR) << "This method can only verify TPM_1_2_QUOTE attestations";
    return false;
  }

  if (!a.has_cert()) {
    LOG(ERROR) << "A TPM 1.2 Quote attestation must have a certificate that "
                  "signs the AIK with the public policy key";
    return false;
  }

  // The data in the Statement in this Attestation should be the serialization
  // of a PEM OpenSSL public key that we can use to check the signature.
  string data;
  if (!VerifyAttestation(a.cert(), &data)) {
    LOG(ERROR) << "The attestation on the AIK did not pass verification";
    return false;
  }

  BIO *mem = BIO_new(BIO_s_mem());
  int bio_bytes_written =
      BIO_write(mem, reinterpret_cast<const void *>(data.data()),
                static_cast<int>(data.size()));
  if (bio_bytes_written != static_cast<int>(data.size())) {
    LOG(ERROR) << "Could not write the data to the BIO";
    return false;
  }

  RSA *aik_rsa = nullptr;
  if (!PEM_read_bio_RSAPublicKey(mem, &aik_rsa, NULL, NULL)) {
    LOG(ERROR) << "Could not read the RSA public key from the attestation";
    return false;
  }

  ScopedRsa aik(aik_rsa);

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
                 a.signature().size(), aik.get()) !=
      1) {
    LOG(ERROR) << "The RSA signature did not pass verification";
    return false;
  }

  return true;
}
}  // namespace tao
