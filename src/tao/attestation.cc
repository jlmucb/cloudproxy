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
#include <keyczar/keyczar.h>

#include "tao/keys.h"
#include "tao/tpm_tao.h"

using std::stringstream;

using keyczar::Verifier;

namespace tao {
bool IsSubprincipalOrIdentical(const string &child_name,
                               const string &parent_name) {
  // TODO(kwalsh) Additional well-formedness checks?
  return (child_name == parent_name) ||
         (child_name.size() > parent_name.size() + 2 &&
          child_name.substr(0, parent_name.size() + 2) == parent_name + "::");
}

static bool CheckRestrictions(const Statement &s, time_t check_time) {
  if (check_time < s.time()) {
    LOG(ERROR) << "Attestation is not yet valid";
    return false;
  }
  if (check_time >= s.expiration()) {
    LOG(ERROR) << "Attestation has expired";
    return false;
  }
  return true;
}

static bool VerifyAttestationSignature(const Attestation &a) {
  string signer = a.signer();
  bool tpm_signature = signer.substr(0, 3) == "TPM";
  if (tpm_signature) {
    // TODO(kwalsh) TPMTaoChildChannel does its own key serialize/descerialize.
    // Maybe unify that with VerifierFromPrincipalName()?
    return TPMTao::VerifySignature(signer, a.serialized_statement(),
                                   a.signature());
  } else {
    scoped_ptr<Verifier> v;
    if (!VerifierFromPrincipalName(signer, &v)) {
      LOG(ERROR) << "Could not deserialize the attestation signer key";
      return false;
    }
    return VerifySignature(*v, a.serialized_statement(),
                           Tao::AttestationSigningContext, a.signature());
  }
}

bool ValidateAttestation(const string &attestation, Statement *s) {
  Attestation a;
  if (!a.ParseFromString(attestation)) {
    LOG(ERROR) << "Could not parse attestation";
    return false;
  }
  if (!s->ParseFromString(a.serialized_statement())) {
    LOG(ERROR) << "Could not parse attestation statement";
    return false;
  }
  // Establish that signer says (issuer says ...)
  if (!VerifyAttestationSignature(a)) {
    LOG(ERROR) << "The attestation statement was not properly signed";
    return false;
  }
  // Establish that signer speaks for issuer
  if (!a.has_serialized_delegation()) {
    // Case (1), no delegation present.
    // Require that s.issuer be a subprincipal of (or identical to) a.signer.
    if (!IsSubprincipalOrIdentical(s->issuer(), a.signer())) {
      LOG(ERROR) << "It is not evident that the signer speaks for the issuer";
      return false;
    }
  } else {
    // Case (2), delegation present.
    // Require that:
    // - delegation conveys delegate speaksfor issuer0,
    // - a.signer speaks for delegate
    // - and issuer0 speaks for s.issuer
    Statement delegation;
    if (!ValidateAttestation(a.serialized_delegation(), &delegation)) {
      LOG(ERROR) << "Delegation failed to verify";
      return false;
    }
    if (!delegation.has_delegate()) {
      LOG(ERROR) << "Invalid embedded delegation";
      return false;
    }
    string delegate = delegation.delegate();
    string issuer0 = delegation.issuer();
    if (!IsSubprincipalOrIdentical(delegate, a.signer())) {
      LOG(ERROR) << "Delegation is not relevant to signer";
      return false;
    }
    if (!IsSubprincipalOrIdentical(s->issuer(), issuer0)) {
      LOG(ERROR) << "Delegation is not relevant to issuer";
      return false;
    }
    // Modify the statement timestamps accordingly
    if (s->time() < delegation.time()) s->set_time(delegation.time());
    if (s->expiration() >= delegation.expiration())
      s->set_expiration(delegation.expiration());
  }
  return true;
}

bool GenerateAttestation(const Keys &key, const string &delegation,
                         const Statement &stmt, string *attestation) {
  // Get signer name.
  string signer;
  if (!key.GetPrincipalName(&signer)) {
    LOG(ERROR) << "Could not get signer principal name";
    return false;
  }
  // Fill in default expirations
  Statement s;
  s.MergeFrom(stmt);
  if (!s.has_time()) s.set_time(CurrentTime());
  if (!s.has_expiration())
    s.set_expiration(s.time() + Tao::DefaultAttestationTimeout);
  // Serialize and sign the statement.
  string serialized_stmt, sig;
  if (!s.SerializeToString(&serialized_stmt)) {
    LOG(ERROR) << "Could not serialize statement";
    return false;
  }
  if (!key.Sign(serialized_stmt, Tao::AttestationSigningContext, &sig)) {
    LOG(ERROR) << "Could not sign the statement";
    return false;
  }
  // Construct and serialize the attestation.
  Attestation a;
  a.set_serialized_statement(serialized_stmt);
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
  return true;
}

bool GetAttestationIssuer(const string &attestation, string *issuer) {
  Attestation a;
  if (!a.ParseFromString(attestation)) {
    LOG(ERROR) << "Could not parse attestation";
    return false;
  }
  Statement s;
  if (!s.ParseFromString(a.serialized_statement())) {
    LOG(ERROR) << "Could not parse attestation statement";
    return false;
  }
  issuer->assign(s.issuer());
  return true;
}

time_t CurrentTime() {
  time_t cur_time;
  time(&cur_time);
  return cur_time;
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

  // statement
  Statement stmt;
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
    s = elideBytes(a.signature());
  out << "signature: " << s << "\n";

  // quote
  if (!a.has_signer())
    s = "(missing)";
  else
    s = elideString(a.signer());
  out << "signer: " << s << "\n";

  // delegation
  Attestation delegation;
  if (!a.has_serialized_delegation())
    s = "(none)";
  else if (!delegation.ParseFromString(a.serialized_delegation()))
    s = "(unparsable)";
  else
    s = Indent("  ", DebugString(delegation));
  out << "delegation: " << s << "\n";

  return "{\n  " + Indent("  ", out.str()) + "}";
}

string DebugString(const Statement &stmt) {
  stringstream out;
  string s;

  out << "issuer: " << elideString(stmt.issuer()) << "\n";

  s = DebugString(static_cast<time_t>(stmt.time()));
  out << "time: " << s << "\n";

  s = DebugString(static_cast<time_t>(stmt.expiration()));
  out << "expiration: " << s << "\n";

  if (stmt.has_delegate()) {
    out << "delegate: " << elideString(stmt.delegate()) << "\n";
  }
  if (stmt.has_predicate_name()) {
    auto &args = stmt.predicate_args();
    out << "predicate: " << stmt.predicate_name();
    out << "(" << join(args.begin(), args.end(), ", ") << ")\n";
  }

  return "{\n  " + Indent("  ", out.str()) + "}";
}

bool AttestDelegation(const Keys &key, const string &delegation,
                      const string &delegate, const string &issuer,
                      string *attestation) {
  string signer;
  if (!key.GetPrincipalName(&signer)) {
    LOG(ERROR) << "Could not get signer principal name";
    return false;
  }
  Statement s;
  s.set_delegate(delegate);
  s.set_issuer(issuer);
  if (!GenerateAttestation(key, delegation, s, attestation)) {
    LOG(ERROR) << "Could not sign attestation";
    return false;
  }
  VLOG(5) << "Generated delegation attestation\n"
          << " via signer " << elideString(signer) << "\n"
          << " nicknamed " << key.Nickname() << "\n"
          << " for issuer " << elideString(issuer) << "\n"
          << " and delegate " << elideString(delegate) << "\n";
  return true;
}

bool ValidateDelegation(const string &attestation, time_t check_time,
                        string *delegate, string *issuer) {
  Statement s;
  if (!ValidateAttestation(attestation, &s)) {
    LOG(ERROR) << "Attestation did not validate";
    return false;
  }
  if (!CheckRestrictions(s, check_time)) {
    LOG(ERROR) << "Attestation restrictions not met";
    return false;
  }
  if (!s.has_delegate()) {
    LOG(ERROR) << "Attestation missing delegate";
    return false;
  }
  delegate->assign(s.delegate());
  issuer->assign(s.issuer());
  return true;
}

bool GetAttestationDelegate(const string &attestation, string *delegate) {
  Attestation a;
  if (!a.ParseFromString(attestation)) {
    LOG(ERROR) << "Could not parse attestation";
    return false;
  }
  Statement s;
  if (!s.ParseFromString(a.serialized_statement())) {
    LOG(ERROR) << "Could not parse attestation statement";
    return false;
  }
  delegate->assign(s.delegate());
  return true;
}

bool AttestPredicate(const Keys &key, const string &delegation,
                     const string &issuer, const string &predicate,
                     const list<string> &args, string *attestation) {
  string signer;
  if (!key.GetPrincipalName(&signer)) {
    LOG(ERROR) << "Could not get signer principal name";
    return false;
  }
  Statement s;
  s.set_predicate_name(predicate);
  for (auto &arg : args) s.add_predicate_args(arg);
  s.set_issuer(issuer);
  if (!GenerateAttestation(key, delegation, s, attestation)) {
    LOG(ERROR) << "Could not sign attestation";
    return false;
  }
  VLOG(5) << "Generated predicate attestation\n"
          << " via signer " << elideString(signer) << "\n"
          << " nicknamed " << key.Nickname() << "\n"
          << " for issuer " << elideString(issuer) << "\n"
          << " and predicate " << predicate << "(" << join(args, ", ") << ")\n";
  return true;
}

bool ValidatePredicate(const string &attestation, time_t check_time,
                       string *issuer, string *predicate, list<string> *args) {
  Statement s;
  if (!ValidateAttestation(attestation, &s)) {
    LOG(ERROR) << "Attestation did not validate";
    return false;
  }
  if (!CheckRestrictions(s, check_time)) {
    LOG(ERROR) << "Attestation restrictions not met";
    return false;
  }
  if (!s.has_predicate_name()) {
    LOG(ERROR) << "Attestation missing predicate";
    return false;
  }
  predicate->assign(s.predicate_name());
  args->clear();
  for (auto &arg : s.predicate_args()) args->push_back(arg);
  return true;
}

bool GetAttestationPredicate(const string &attestation, string *predicate,
                             list<string> *args) {
  Attestation a;
  if (!a.ParseFromString(attestation)) {
    LOG(ERROR) << "Could not parse attestation";
    return false;
  }
  Statement s;
  if (!s.ParseFromString(a.serialized_statement())) {
    LOG(ERROR) << "Could not parse attestation statement";
    return false;
  }
  predicate->assign(s.predicate_name());
  args->clear();
  for (auto &arg : s.predicate_args()) args->push_back(arg);
  return true;
}

}  // namespace tao
