//  File: datalog_guard.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Authorization guard based on predicates and datalog.
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
#include "tao/datalog_guard.h"

#include <list>
#include <regex>
#include <set>
#include <sstream>
#include <string>

#include <datalog.h>
#include <glog/logging.h>
#include <lua.h>

#include "tao/datalog_guard.pb.h"
#include "tao/util.h"

using std::regex;
using std::regex_match;

namespace tao {

struct DatalogEngine {
  dl_db_t db;
};

void datalog_close(DatalogEngine *dl) {
  dl_close(dl->db);
  dl->db = nullptr;
}

bool DatalogGuard::Init() {
      dl.reset(new DatalogEngine());
      dl->db = dl_open();
}

bool DatalogGuard::GetSubprincipalName(string *subprin) const {
  // Use policy key as part of name
  string key_prin;
  if (!GetPolicyKeys()->GetPrincipalName(&key_prin)) {
    LOG(ERROR) << "Could not get policy key principal name";
    return false;
  }
  subprin->assign("DatalogGuard(" + key_prin + ")");
  return true;
}

bool CheckPredicate(const DatalogPredicate &pred, list<string> *refvars) {
  if (pred.has_issuer() && pred.issuer().find('(') == string::npos) {
    // Does not appear to be a principal, assume it is a variable
    if (!regex_match(pred.issuer(), "[A-Z][a-zA-Z0-9_]*")) {
      LOG(ERROR) << "Illegal variable name: " << pred.issuer();
      return false;
    } 
    refvars.push_back(pred.issuer())
  } else {
    // TODO(kwalsh) We could enforce legal principal names here.
  }
  if (!regex_match(pred.pred(), "[a-zA-Z][a-zA-Z0-9_]*")) {
    LOG(ERROR) << "Illegal predicate name: " << pred.pred();
    return false;
  }
  for (const string &arg : pred.args()) {
    if (regex_match(arg, "[A-Z][a-zA-Z0-9_]*")) {
      refvars.push_back(arg);
    } else if (regex_match(arg, "[-][0-9]+")) {
      // integer, ok
    } else if (arg.size() >= 2 && arg[0] == '"' &&
               arg[arg.size() - 1] == '"') {
      stringstream in(...);
      string q;
      getQuotedString(in, &q);
      if (!in || (in.get() && !in.eof())) {
        LOG(ERROR) << "Illegal quoted string";
        return false;
      }
    } else {
      LOG(ERROR) << "Unrecognized term: " << arg;
      return false;
    }
  }
  return true;
}

bool CheckRule(const DatalogRule &rule) {
  // Check vars for legality.
  list<string> vars;
  for (const string &var : rule.vars()) {
    if (!regex_match(var, "[A-Z][a-zA-Z0-9_]*")) {
      LOG(ERROR) << "Illegal variable name: " << var;
      return false;
    } 
    if (std::find(vars.begin(), vars.end(), var) != vars.last()) {
      LOG(ERROR) << "Duplicate quntification variable: " << var;
      return false;
    }
  }
  // Check conditions for legality.
  list<string> cond_refvars;
  for (const auto &pred : rule.conds()) {
    if (!CheckPredicate(pred, &cond_refvars)) {
      LOG(ERROR) << "Illegal datalog predicate";
      return false;
    }
  }
  // Check consequent for legality.
  list<string> consequent_refvars;
  if (!CheckPredicate(rule.consequent(), &consequent_refvars)) {
    LOG(ERROR) << "Illegal datalog consequent";
    return false;
  }
  // Check that each quantification variable is referenced.
  list<missing> missing_vars;
  std::set_difference(vars.begin(), vars.end(), cond_refvars.begin(),
                      cond_refvars.end(), missing_vars.back_inserter());
  if (missing_vars.size() > 0) {
    LOG(ERROR) << "Unreferenced quantification variables: " << join(vars, ", ");
    return false;
  }
  // Check that each reference variable in conditions was quantified.
  std::set_difference(cond_refvars.begin(), cond_refvars.end(), vars.begin(),
                      vars.end(), missing_vars.back_inserter());
  if (missing_vars.size() > 0) {
    LOG(ERROR) << "Unquantified condition variables: " << join(vars, ", ");
    return false;
  }
  // Check that each reference variable in consequent was quantified.
  std::set_difference(consequent_refvars.begin(), consequent_refvars.end(),
                      vars.begin(), vars.end(), missing_vars.back_inserter());
  if (missing_vars.size() > 0) {
    LOG(ERROR) << "Unquantified consequent variables: " << join(vars, ", ");
    return false;
  }
  return true;
}

// TODO(kwalsh) sanity check principal names, add implied predicates for them
// here.

bool DatalogGuard::InstallRule(const DatalogRule &rule) {
  if (!CheckRule(rule)) {
    LOG(ERROR) << "Illegal rule";
    return false;
  }
  if (rule.conds_size() > 0) {
    PushPredicate( ... ) 

  }

}


bool DatalogGuard::IsAuthorized(const string &name, const string &op,
                            const list<string> &args) const {
  for (auto &entry : aclset_.entries()) {
    if (IsMatchingEntry(entry, name, op, args)) {
      LOG(INFO) << "Principal " << elideString(name)
                << " is authorized to perform " << op << "(...)";
      return true;
    }
  }
  LOG(INFO) << "Principal " << elideString(name)
            << " is not authorized to perform " << op << "(...)";
  LOG(INFO) << DebugString();
  return false;
}

bool DatalogGuard::Authorize(const string &name, const string &op,
                         const list<string> &args) {
  ACLEntry *entry = aclset_.add_entries();
  entry->set_name(name);
  entry->set_op(op);
  for (auto &arg : args) entry->add_args(arg);
  return SaveConfig();
}

bool DatalogGuard::Revoke(const string &name, const string &op,
                      const list<string> &args) {
  bool found = false;
  for (int i = aclset_.entries_size() - 1; i >= 0; i--) {
    if (IsMatchingEntry(aclset_.entries(i), name, op, args)) {
      found = true;
      aclset_.mutable_entries()->DeleteSubrange(i, 1);
    }
  }
  if (!found)
    LOG(WARNING) << "Principal " << name << " was not authorized to perform "
                 << op << "(...)";
  return found;
}

string DatalogGuard::DebugString() const {
  std::stringstream out;
  out << "Database of " << rules_.rules_size() << " policy rules:";
  int i = 0;
  for (auto &rule : rules_.entries())
    out << "\n  " << (i++) << ". " << DebugString(rule);
  return out.str();
}

int DatalogGuard::RuleCount() const { return rules_.rules_size(); }

bool DatalogGuard::GetRule(int i, string *desc) const {
  if (i < 0 || i > rules_.rules_size()) {
    LOG(ERROR) << "Invalid policy rule index";
    return false;
  }
  const DatalogRule &rule = rules_.rule(i);
  desc->assign(DebugString(rule));
  return true;
}

string DatalogGuard::DebugString(const DatalogRule &rule) const {
  std::stringstream out;
  bool need_paren = (rule.vars_size() > 0)
  if (need_paren) out << "(";
  if (rule.vars_size() > 0) {
    const auto &vars = rule.vars();
    out << "for all " << join(vars.begin(), vars.end(), ", ");
    out << " : ";
  }
  if (rule.conds_size() > 0) {
    string delim = "";
    for (const auto &cond : rule.conds()) {
      out << delim << DebugString(cond);
      delim = " and ";
    }
    out << " implies ";
  }
  out << DebugString(rule.consequent());
  if (need_paren) out << ")";
  return out.str();
}

string DatalogGuard::DebugString(const DatalogPredicate &pred) const {
  std::stringstream out;
  bool need_paren = pred.has_issuer();
  if (need_paren) out << "(";
  if (pred.has_issuer()) out << elideString(pred.issuer()) << " says ";
  out << "(";
  out << join(pred.args().start(), pred.args().end(), ", ");
  out << ")";
  if (need_paren) out << ")";
  return out.str();
}

bool DatalogGuard::ParseConfig() {
  // Load basic configuration.
  if (!TaoDomain::ParseConfig()) {
    LOG(ERROR) << "Can't load basic configuration";
    return false;
  }
  // Load the signed ACL set file.
  string path = GetConfigPath(JSONSignedDatalogRulesPath);
  string serialized;
  if (!ReadFileToString(path, &serialized)) {
    LOG(ERROR) << "Can't load signed policy rules from " << path;
    return false;
  }
  // Parse the signed rules.
  SignedDatalogRules srules;
  if (!srules.ParseFromString(serialized)) {
    LOG(ERROR) << "Can't parse signed policy rules from " << path;
    return false;
  }
  // Verify its signature.
  if (!GetPolicyKeys()->Verify(srules.serialized_rules(), DatalogSigningContext,
                               srules.signature())) {
    LOG(ERROR) << "Signature did not verify on signed policy rules from " << path;
    return false;
  }
  // Parse the ACL set.
  if (!rules_.ParseFromString(srules.serialized_rules())) {
    LOG(ERROR) << "Can't parse serialized policy rules from " << path;
    return false;
  }
  for (const auto &rule : rules_.rules()) {
    if (!InstallRule(rule)) {
      LOG(ERROR) << "Rule could not be installed";
      return false;
    }
  }
  return true;
}

bool DatalogGuard::SaveConfig() const {
  if (GetPolicySigner() == nullptr) {
    LOG(ERROR) << "Can't sign policy rules, admin is currently locked.";
    return false;
  }
  // Save basic configuration.
  if (!TaoDomain::SaveConfig()) {
    LOG(ERROR) << "Can't save basic configuration";
    return false;
  }
  // Serialize rules.
  string serialized_rules;
  if (!rules_.SerializeToString(&serialized_rules)) {
    LOG(ERROR) << "Could not serialize the policy rules";
    return false;
  }
  // Sign rules.
  string rules_signature;
  if (!GetPolicyKeys()->Sign(serialized_rules, DatalogSigningContext,
                             &rules_signature)) {
    LOG(ERROR) << "Can't sign policy rules";
    return false;
  }
  SignedDatalogRules srules;
  rules.set_serialized_rules(serialized_rules);
  rules.set_signature(rules_signature);
  string serialized;
  if (!rules.SerializeToString(&serialized)) {
    LOG(ERROR) << "Could not serialize the signed policy rules";
    return false;
  }
  // Save signed rules.
  string path = GetConfigPath(JSONSignedDatalogRulesPath);
  if (!WriteStringToFile(path, serialized)) {
    LOG(ERROR) << "Can't write signed policy rules to " << path;
    return false;
  }
  return true;
}

}  // namespace tao
