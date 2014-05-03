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

#include <sstream>

#include <glog/logging.h>
#include <keyczar/base/base64w.h>
#include <keyczar/base/basictypes.h>
#include <keyczar/base/file_util.h>
#include <keyczar/keyczar.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "tao/attestation.pb.h"
#include "tao/hosted_programs.pb.h"
#include "tao/util.h"

using keyczar::Verifier;
using keyczar::base::ReadFileToString;
using keyczar::base::WriteStringToFile;

namespace tao {

bool WhitelistAuth::IsAuthorized(const string &full_name) const {
  LOG(ERROR) << "Not yet implemented: auth for " << full_name;
  return true;  // TODO(kwalsh)
}

bool WhitelistAuth::IsAuthorized(const string &hash, const string &alg,
                                 const string &name) const {
  for (int i = 0; i < whitelist_.programs_size(); i++) {
    if (whitelist_.programs(i).hash() == hash &&
        whitelist_.programs(i).hash_alg() == alg &&
        whitelist_.programs(i).name() == name)
      return true;
  }
  LOG(WARNING) << "The principal " << hash << ":" << alg << ":" << name
               << "\nwas not found on the whitelist, which contains:\n"
               << DebugString() << "\n";
  return false;
}

bool WhitelistAuth::IsAuthorized(const string &hash, const string &alg,
                                 string *name) const {
  for (int i = 0; i < whitelist_.programs_size(); i++) {
    if (whitelist_.programs(i).hash() == hash &&
        whitelist_.programs(i).hash_alg() == alg) {
      if (name != nullptr) name->assign(whitelist_.programs(i).name());
      return true;
    }
  }
  LOG(WARNING) << "The principal " << hash << ":" << alg << ":*"
               << "\nwas not found on the whitelist, which contains:\n"
               << DebugString() << "\n";
  return false;
}

bool WhitelistAuth::VerifyAttestation(const string &attestation,
                                      string *data) const {
  Attestation a;
  if (!a.ParseFromString(attestation)) {
    LOG(ERROR) << "Could not deserialize an Attestation";
    return false;
  }

  Statement s;
  if (!s.ParseFromString(a.serialized_statement())) {
    LOG(ERROR) << "Could not parse the statement";
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

  data->assign(s.data().data(), s.data().size());

  VLOG(1) << "The attestation passed verification.";
  VLOG(3) << "Attestation: " << tao::DebugString(a);

  return true;
}

bool WhitelistAuth::CheckAuthorization(const Attestation &attestation) const {
  Statement s;
  if (!s.ParseFromString(attestation.serialized_statement())) {
    LOG(ERROR) << "Could not parse the statement from an attestation";
    return false;
  }

  // Check the time to make sure it hasn't expired.
  time_t cur_time;
  time(&cur_time);
  // TODO(kwalsh) check notbefore as well
  // if (cur_time < s.time()) {
  //   LOG(ERROR) << "Signature is not yet valid";
  //   return false;
  // }
  if (cur_time > s.expiration()) {
    LOG(ERROR) << "This attestation has expired";
    return false;
  }

  if (s.hash_alg().empty()) {
    // Root attestations need not be on the whitelist.
    if (attestation.type() != ROOT) {
      LOG(WARNING) << "Only root may issue attestations without a hash";
      return false;
    }
    return true;
  } else if (s.hash_alg() == PcrSha1) {
    // Extract the PCRs as a single string and look for them in the whitelist.
    string quote(attestation.quote().data(), attestation.quote().size());
    size_t quote_len = quote.size();
    if (quote_len < sizeof(uint16)) {
      LOG(ERROR) << "The quote was not long enough to contain a mask length";
      return false;
    }

    const char *quote_bytes = quote.c_str();
    uint32 index = 0;
    uint16 mask_len =
        ntohs(*reinterpret_cast<const uint16 *>(quote_bytes + index));
    index += sizeof(uint16);

    // Skip the mask bytes.
    if ((quote_len < index) || (quote_len - index < mask_len)) {
      LOG(ERROR) << "The quote was not long enough to contain the mask";
      return false;
    }

    index += mask_len;

    if ((quote_len < index) || (quote_len - index < sizeof(uint32))) {
      LOG(ERROR) << "The quote was not long enough to contain the pcr length";
      return false;
    }

    uint32 pcr_len = ntohl(*(uint32 *)(quote_bytes + index));
    index += sizeof(uint32);

    if ((quote_len < index) || (quote_len - index < pcr_len)) {
      LOG(ERROR) << "The quote was not long enough to contain the PCRs";
      return false;
    }

    string pcrs(quote_bytes + index, pcr_len);

    // The whitelist uses Base64W encoding for hashes.
    string serialized_pcrs;
    if (!keyczar::base::Base64WEncode(pcrs, &serialized_pcrs)) {
      LOG(ERROR) << "Can't serialize the PCRs";
      return false;
    }

    // TODO(kwalsh): We should really return the name found here to the caller.
    if (!IsAuthorized(serialized_pcrs, PcrSha1, nullptr)) {
      LOG(WARNING) << "The TPM1.2 quote was issued by an unauthorized TPM";
      return false;
    }
    return true;
  } else {
    // Normal program-like hashes are checked against the whitelist directly.
    // TODO(kwalsh): We should really return the name found here to the caller.
    if (!IsAuthorized(s.hash(), s.hash_alg(), nullptr)) {
      LOG(WARNING) << "The attestation was issued by an unauthorized principal";
      return false;
    }
    return true;
  }
}

bool WhitelistAuth::CheckIntermediateSignature(const Attestation &a) const {
  if (a.type() != INTERMEDIATE) {
    LOG(ERROR) << "Expected Attestation to be INTERMEDIATE, but it was not";
    return false;
  }

  // Recurse on the attestation to get the key information from the cert.
  string key_data;
  if (!VerifyAttestation(a.cert(), &key_data)) {
    LOG(ERROR) << "Could not verify the public_key attestation";
    return false;
  }

  // TODO(kwalsh): This code assumes that all verified INTERMEDIATE attestations
  // are of serialized public keys.
  // Get a verifier corresponding to this public key.
  scoped_ptr<Verifier> v;
  if (!DeserializePublicKey(key_data, &v)) {
    LOG(ERROR) << "Could not deserialize the public key";
    return false;
  }

  if (!VerifySignature(*v, a.serialized_statement(),
                       Tao::AttestationSigningContext, a.signature())) {
    LOG(ERROR) << "The attestation statement was not properly signed";
    return false;
  }

  return true;
}

bool WhitelistAuth::CheckTPM12Quote(const Attestation &a) const {
  if (a.type() != TPM_1_2_QUOTE) {
    LOG(ERROR) << "Expected Attestation to be TPM_1_2_QUOTE, but it was not";
    return false;
  }

  if (!a.has_cert()) {
    LOG(ERROR) << "A TPM 1.2 Quote attestation must have a certificate that "
                  "signs the AIK with the public policy key";
    return false;
  }

  // The data in the Statement in this Attestation should be the serialization.
  // of a PEM OpenSSL public key that we can use to check the signature.
  string data;
  if (!VerifyAttestation(a.cert(), &data)) {
    LOG(ERROR) << "The attestation on the AIK did not pass verification";
    return false;
  }

  // TODO(kwalsh) Move this type of key handling to util
  BIO *mem = BIO_new(BIO_s_mem());
  int bio_bytes_written =
      BIO_write(mem, reinterpret_cast<const void *>(data.data()),
                static_cast<int>(data.size()));
  if (bio_bytes_written != static_cast<int>(data.size())) {
    LOG(ERROR) << "Could not write the data to the BIO";
    return false;
  }

  RSA *aik_rsa = nullptr;
  if (!PEM_read_bio_RSAPublicKey(mem, &aik_rsa, nullptr, nullptr)) {
    LOG(ERROR) << "Could not read the RSA public key from the attestation";
    return false;
  }

  ScopedRsa aik(aik_rsa);

  // Hash the statement with SHA1 for the external data part of the quote.
  uint8 statement_hash[20];
  SHA1(reinterpret_cast<const uint8 *>(a.serialized_statement().data()),
       a.serialized_statement().size(), statement_hash);

  // The quote can be verified in a qinfo, which has a header of 8 bytes, and
  // two hashes.  The first hash is the hash of the external data, and the
  // second is the hash of the quote itself. This can be hashed and verified
  // directly by OpenSSL.

  uint8 qinfo[8 + 2 * 20];
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

  SHA1(reinterpret_cast<const uint8 *>(a.quote().data()), a.quote().size(),
       qinfo + 8);
  memcpy(qinfo + 8 + 20, statement_hash, sizeof(statement_hash));

  uint8 quote_hash[20];
  SHA1(qinfo, sizeof(qinfo), quote_hash);
  if (RSA_verify(NID_sha1, quote_hash, sizeof(quote_hash),
                 reinterpret_cast<const uint8 *>(a.signature().data()),
                 a.signature().size(), aik.get()) !=
      1) {
    LOG(ERROR) << "The RSA signature did not pass verification";
    return false;
  }

  return true;
}

bool WhitelistAuth::Authorize(const string &hash, const string &alg,
                              const string &name) {
  HostedProgram *entry = whitelist_.add_programs();
  entry->set_name(name);
  entry->set_hash_alg(alg);
  entry->set_hash(hash);
  return SaveConfig();
}

bool WhitelistAuth::Forbid(const string &name) {
  bool found = false;
  for (int i = whitelist_.programs_size() - 1; i >= 0; i--) {
    if (whitelist_.programs(i).name() == name) {
      found = true;
      whitelist_.mutable_programs()->DeleteSubrange(i, 1);
    }
  }
  return found;
}

string WhitelistAuth::DebugString() const {
  std::stringstream out;
  out << "Whitelist of " << whitelist_.programs_size() << " authorizations";
  for (int i = 0; i < whitelist_.programs_size(); i++) {
    const HostedProgram &hp = whitelist_.programs(i);
    out << "\n " << i << ". ";
    out << hp.hash() << ":" << hp.hash_alg() << ":" << hp.name();
  }
  return out.str();
}

int WhitelistAuth::WhitelistCount() const { return whitelist_.programs_size(); }

bool WhitelistAuth::WhitelistEntry(int i, string *hash, string *alg,
                                   string *name) const {
  if (i < 0 || i > whitelist_.programs_size()) {
    LOG(ERROR) << "Invalid index into whitelist";
    return false;
  }
  const HostedProgram &hp = whitelist_.programs(i);
  hash->assign(hp.hash());
  alg->assign(hp.hash_alg());
  name->assign(hp.name());
  return true;
}

bool WhitelistAuth::ParseConfig() {
  // Load basic configuration.
  if (!TaoDomain::ParseConfig()) {
    LOG(ERROR) << "Can't load basic configuration";
    return false;
  }
  // Load the signed whitelist file.
  string path = GetConfigPath(JSONSignedWhitelistPath);
  string serialized;
  if (!ReadFileToString(path, &serialized)) {
    LOG(ERROR) << "Can't load signed whitelist from " << path;
    return false;
  }
  // Parse the signed whitelist.
  SignedWhitelist sw;
  if (!sw.ParseFromString(serialized)) {
    LOG(ERROR) << "Can't parse signed whitelist from " << path;
    return false;
  }
  // Verify its signature.
  if (!GetPolicyKeys()->VerifySignature(
          sw.serialized_whitelist(), WhitelistSigningContext, sw.signature())) {
    LOG(ERROR) << "Signature did not verify on signed whitelist " << path;
    return false;
  }
  // Parse the whitelist.
  if (!whitelist_.ParseFromString(sw.serialized_whitelist())) {
    LOG(ERROR) << "Can't parse serialized whitelist from " << path;
    return false;
  }
  return true;
}

bool WhitelistAuth::SaveConfig() const {
  if (GetPolicySigner() == nullptr) {
    LOG(ERROR) << "Can't sign whitelist, admin is currently locked.";
    return false;
  }
  // Save basic configuration.
  if (!TaoDomain::SaveConfig()) {
    LOG(ERROR) << "Can't save basic configuration";
    return false;
  }
  // Serialize whitelist.
  string serialized_whitelist;
  if (!whitelist_.SerializeToString(&serialized_whitelist)) {
    LOG(ERROR) << "Could not serialize the whitelist";
    return false;
  }
  string whitelist_signature;
  if (!GetPolicyKeys()->SignData(serialized_whitelist, WhitelistSigningContext,
                                 &whitelist_signature)) {
    LOG(ERROR) << "Can't sign whitelist";
    return false;
  }
  // Sign whitelist.
  SignedWhitelist sw;
  sw.set_serialized_whitelist(serialized_whitelist);
  sw.set_signature(whitelist_signature);
  string serialized;
  if (!sw.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the signed whitelist";
    return false;
  }
  // Save signed whitelist.
  string path = GetConfigPath(JSONSignedWhitelistPath);
  if (!WriteStringToFile(path, serialized)) {
    LOG(ERROR) << "Can't write signed whitelist to " << path;
    return false;
  }
  return true;
}

}  // namespace tao
