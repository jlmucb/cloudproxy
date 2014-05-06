//  File: attestation.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Implementation of attestation utilities.
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

#include "tao/attestation.h"

#include <sstream>

#include <glog/logging.h>
#include <keyczar/base/base64w.h>
#include <keyczar/base/file_util.h>
#include <keyczar/keyczar.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "tao/attestation.pb.h"
#include "tao/util.h"

using std::stringstream;

using keyczar::Verifier;
using keyczar::base::ReadFileToString;
using keyczar::base::WriteStringToFile;

namespace tao {

bool AttestKeyNameBinding(const Keys &key, const string &delegation,
                          const string &key_prin, const string &name,
                          string *attestation) {
  // Get signer name.
  string signer;
  if (!key.GetSignerUniqueID(&signer)) {
    LOG(ERROR) << "Could not get signer name";
    return false;
  }
  Statement s;
  s.set_key(key_prin);
  s.set_name(name);
  // Fill in timestamp.
  statement->set_time(CurrentTime());
  // Fill in expiration.
  statement->set_expiration(statement->time() + Tao::DefaultAttestationTimeout);
  // Serialize and sign the statement.
  string stmt, sig;
  if (!statement->SerializeToString(&stmt)) {
    LOG(ERROR) << "Could not serialize statement";
    return false;
  }
  if (!key.SignData(stmt, Tao::AttestationSigningContext, &sig)) {
    LOG(ERROR) << "Could not sign the statement";
    return false;
  }
  Attestation a;
  a.set_serialized_statement(stmt);
  a.set_signature(sig);
  a.set_signer(signer);
  if (!delegation.empty()) {
    a.set_serialized_delegation(delegation);
  } else {
    a.clear_serialized_delegation();
  }
  if (!a.SerializeToString(attestation)) {
    LOG(ERROR) << "Could not serialize attestation";
    return false;
  }
  VLOG(5) << "Generated key-to-name binding attestation\n"
          << " via signer nicknamed " << key.Name() << "\n"
          << " for name " << name << "\n"
          << " and Attestation " << DebugString(a) << "\n";
  return true;
}

bool GetNameFromKeyNameBinding(const string &attestation, string *name) {
  Attestation a;
  if (!a.ParseFromString(attestation)) {
    LOG(ERROR) << "Could not parse the key-to-name attestation";
    return false;
  }
  Statement s;
  if (!s.ParseFromString(a.serialized_statement())) {
    LOG(ERROR) << "Could not parse the key-to-name attestation statement";
    return false;
  }
  name->assign(s->name);
  return true;
}

bool GetKeyFromKeyNameBinding(const string &attestation, string *key_prin) {
  Attestation a;
  if (!a.ParseFromString(attestation)) {
    LOG(ERROR) << "Could not parse the key-to-name attestation";
    return false;
  }
  Statement s;
  if (!s.ParseFromString(a.serialized_statement())) {
    LOG(ERROR) << "Could not parse the key-to-name attestation statement";
    return false;
  }
  key_prin->assign(s->key());
  return true;
}

static bool IsSubPrincipalOrIdentical(const string &child_name,
                                      const string &parent_name) {
    return (child_name == parent_name) ||
           (child_name.substr(parent_name.size() + 2) == parent_name + "::");
}

static bool VerifyAttestationSignature(const Attestation &a) {
  string signer = a.signer();
  bool tpm_signature =  signer.substr(3) == "TPM";
  string key_data, key_text;
  stringstream in(signer);
  if (tpm_signature) {
    skip(in, "TPM(");
    getQuotedString(in, &key_text);
    skip(in, ")");
  } else {
    skip(in, "Key(");
    getQuotedString(in, &key_text);
    skip(in, ")");
  }
  if (!in || !in.str().empty()) {
    LOG(ERROR) << "Bad format for attestation signer key";
    return false;
  }

  scoped_ptr<Verifier> v;
  if (!Base64WDecode(key_text, &key_data) ||
      !DeserializePublicKey(key_data, &v)) {
    LOG(ERROR) << "Could not deserialize the attestation signer key";
    return false;
  }
  if (tpm_signature) {
    return TPMTaoChildChannel::VerifySignature(*v, a.serialized_statement(),
                                               a.signature());
  } else {
    return VerifySignature(*v, a.serialized_statement(),
                           Tao::AttestationSigningContext, a.signature());
  }
}

bool ValidateKeyNameBinding(const string &attestation, time_t check_time,
                            string *key_prin, string *name) {
  Attestation a;
  if (!a.ParseFromString(attestation)) {
    LOG(ERROR) << "Could not parse the key-to-name attestation";
    return false;
  }
  Statement s;
  if (!s.ParseFromString(a.serialized_statement())) {
    LOG(ERROR) << "Could not parse the key-to-name attestation statement";
    return false;
  }
  // Establish that the time restrictions are met.
  if (check_time < s.time()) {
    LOG(ERROR) << "Attestation is not yet valid";
    return false;
  }
  if (check_time >= s.expiration()) {
    LOG(ERROR) << "Attestation has expired";
    return false;
  }
  // Establish that signer says (name says ...)
  if (!VerifyAttestationSignature(a)) {
    LOG(ERROR) << "The attestation statement was not properly signed";
    return false;
  }
  // Establish that signer speaks for name
  if (!a.has_delegation()) {
    // Case (1), no delegation present.
    // Require that s.name be a subprincipal of (or identical to) a.signer.
    if (!IsSubPrincipalOrIdentical(s.name(), a.signer())) {
      LOG(ERROR) << "It is not evident that the signer speaks for the name in "
                    "the statement.";
      return false;
    }
  } else {
    // Case (2), delegation present.
    // Require that 
    // - delegation conveys a key-to-name binding, signer0 speaksfor name0,
    // - signer0 is identical to signer
    // - and name is a subprincipal of (or identical to) a.signer
    string delegation_key, delegation_name;
    if (!ValidateKeyNameBinding(a.serialized_delegation(),
          check_time, &delegation_key, &delegation_name)) {
      LOG(ERROR) << "Delegation failed to verify";
      return false;
    }
    if (delegation_key != a.signer()) {
      LOG(ERROR) << "Delegation is not for the signer key";
      return false;
    }
    if (!IsSubPrincipalOrIdentical(s.name(), delegation_name)) {
      LOG(ERROR) << "It is not evident that the signer's name speaks for the "
                    "name in the statement.";
      return false;
    }
  }
  key_prin->assign(s.key());
  name->assign(s.name());
  return true;
}

/// Indent each line of a string after the first line.
/// @param prefix The prefix to put after each newline.
/// @param s The string to be indented.
static string Indent(const string &prefix, const string &s) {
  stringstream out;
  for (unsigned int i = 0; i < s.size(); i++) {
    out << s[i];
    if (s[i] == '\n') out << prefix;
  }
  return out.str();
}

/// Pretty-print a timestamp in "ddd yyyy-mm-dd hh:mm:ss zzz" format.
/// @param t The 64-bit unix time to be pretty-printed.
static string DebugString(time_t t) {
  char buf[80];
  struct tm ts;
  localtime_r(&t, &ts);
  strftime(buf, sizeof(buf), "%a %Y-%m-%d %H:%M:%S %Z", &ts);
  return string(buf);
}

string DebugString(const Attestation &a) {
  stringstream out;
  string s;
  Statement stmt;
  Attestation delegation;
  const Descriptor *desc = a.GetDescriptor();
  const FieldDescriptor *fType =
      desc->FindFieldByNumber(Attestation::kTypeFieldNumber);
  const FieldDescriptor *fSigner =
      desc->FindFieldByNumber(Attestation::kSIgnerFieldNumber);
  const FieldDescriptor *fSignature =
      desc->FindFieldByNumber(Attestation::kSignatureFieldNumber);

  // type
  TextFormat::PrintFieldValueToString(a, fType, -1, &s);
  out << "type: " << s << "\n";

  // statement
  if (!a.has_serialized_statement())
    s = "(missing)";
  else if (!stmt.ParseFromString(a.serialized_statement()))
    s = "(unparsable)";
  else
    s = Indent("  ", DebugString(stmt));
  out << "statement: " << s << "\n";

  // signature
  if (!a.has_signature())
    s = "(missing)";
  else
    TextFormat::PrintFieldValueToString(a, fSignature, -1, &s);
  out << "signature: " << s << "\n";

  // quote
  if (a.has_signer())
    s = "(missing)";
  else
    TextFormat::PrintFieldValueToString(a, fSigner, -1, &s);
  out << "signer: " << s << "\n";

  // delegation
  if (!a.has_delegation())
    s = "(none)";
  else if (!delegation.ParseFromString(a.delegation()))
    s = "(unparsable)";
  else
    s = Indent("  ", DebugString(delegation));
  out << "delegation: " << s << "\n";

  return "{\n  " + Indent("  ", out.str()) + "}";
}

string DebugString(const Statement &stmt) {
  stringstream out;
  string s;
  const Descriptor *desc = stmt.GetDescriptor();
  const FieldDescriptor *fName =
      desc->FindFieldByNumber(Statement::kNameFieldNumber);
  const FieldDescriptor *fKey =
      desc->FindFieldByNumber(Statement::kKeyFieldNumber);

  TextFormat::PrintFieldValueToString(stmt, fName, -1, &s);
  out << "name:" << s << "\n";

  s = DebugString(static_cast<time_t>(stmt.time()));
  out << "time: " << s << "\n";

  s = DebugString(static_cast<time_t>(stmt.expiration()));
  out << "expiration: " << s << "\n";

  TextFormat::PrintFieldValueToString(stmt, fKey, -1, &s);
  out << "key: " << s << "\n";

  return "{\n  " + Indent("  ", out.str()) + "}";
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
  if (!VerifySignature(a)) {
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
                 a.signature().size(), aik.get()) != 1) {
    LOG(ERROR) << "The RSA signature did not pass verification";
    return false;
  }

  return true;
}

time_t CurrentTime() {
  time_t cur_time;
  time(&cur_time);
  return cur_time;
}

}  // namespace tao
