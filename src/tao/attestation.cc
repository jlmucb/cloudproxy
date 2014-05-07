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
#include <google/protobuf/text_format.h>
#include <keyczar/base/base64w.h>
#include <keyczar/base/file_util.h>
#include <keyczar/keyczar.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#include "tao/attestation.pb.h"
#include "tao/keys.h"
#include "tao/tpm_tao_child_channel.h"
#include "tao/util.h"

using std::stringstream;

using google::protobuf::Descriptor;
using google::protobuf::FieldDescriptor;
using google::protobuf::TextFormat;
using keyczar::Verifier;
using keyczar::base::Base64WDecode;

namespace tao {

bool AttestKeyNameBinding(const Keys &key, const string &delegation,
                          const string &key_prin, const string &name,
                          string *attestation) {
  // Get signer name.
  string signer;
  if (!key.SignerUniqueID(&signer)) {
    LOG(ERROR) << "Could not get signer name";
    return false;
  }
  Statement s;
  s.set_key(key_prin);
  s.set_name(name);
  // Fill in timestamp.
  s.set_time(CurrentTime());
  // Fill in expiration.
  s.set_expiration(s.time() + Tao::DefaultAttestationTimeout);
  // Serialize and sign the statement.
  string stmt, sig;
  if (!s.SerializeToString(&stmt)) {
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
  name->assign(s.name());
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
  key_prin->assign(s.key());
  return true;
}

static bool IsSubPrincipalOrIdentical(const string &child_name,
                                      const string &parent_name) {
  return (child_name == parent_name) ||
         (child_name.substr(parent_name.size() + 2) == parent_name + "::");
}

static bool VerifyAttestationSignature(const Attestation &a) {
  string signer = a.signer();
  bool tpm_signature = signer.substr(3) == "TPM";
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
  if (!a.has_serialized_delegation()) {
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
    if (!ValidateKeyNameBinding(a.serialized_delegation(), check_time,
                                &delegation_key, &delegation_name)) {
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

  const Descriptor *desc = a.GetDescriptor();
  const FieldDescriptor *fSigner =
      desc->FindFieldByNumber(Attestation::kSignerFieldNumber);
  const FieldDescriptor *fSignature =
      desc->FindFieldByNumber(Attestation::kSignatureFieldNumber);

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
    TextFormat::PrintFieldValueToString(a, fSignature, -1, &s);
  out << "signature: " << s << "\n";

  // quote
  if (a.has_signer())
    s = "(missing)";
  else
    TextFormat::PrintFieldValueToString(a, fSigner, -1, &s);
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

time_t CurrentTime() {
  time_t cur_time;
  time(&cur_time);
  return cur_time;
}
}  // namespace tao
