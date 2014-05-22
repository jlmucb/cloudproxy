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

#include <cctype>
#include <list>
#include <set>
#include <sstream>
#include <string>

#include <glog/logging.h>
extern "C" {
#include <lua.h>
#include <lauxlib.h>
}
// lua.h must come before datalog.h
#include <datalog.h>

#include "tao/auth.h"
#include "auth_lua.h"
#include "tao/datalog_guard.pb.h"
#include "tao/util.h"

namespace tao {

struct DatalogEngine {
  dl_db_t db;
};

void datalog_close(DatalogEngine *dl) {
  dl_close(dl->db);
  dl->db = nullptr;
}

static string LuaGetError(dl_db_t db) {
  const char *errmsg = lua_tostring(db, -1);
  string s(errmsg ? errmsg : "Unknown Lua Error");
  lua_pop(db, 1);
  return s;
}

static bool LuaLoadAuthModule(dl_db_t db) {
  int err = luaL_loadbuffer(db, (const char *)auth_lua_bytes,
                            sizeof(auth_lua_bytes), auth_lua_source);
  if (err) {
    LOG(ERROR) << "Could not load Lua module: " << LuaGetError(db);
    return false;
  }
  err = lua_pcall(db, 0 /* numargs */, 0 /* num results */, 0 /* err func */);
  if (err) {
    LOG(ERROR) << "Could not initialize Lua module: " << LuaGetError(db);
    return false;
  }
  return true;
}

bool DatalogGuard::Init() {
  dl.reset(new DatalogEngine());
  dl->db = dl_open();
  if (!LuaLoadAuthModule(dl->db)) {
    LOG(ERROR) << "Could not initialize Datalog auth module";
    return false;
  }
  if (!GetPolicyKeys()->GetPrincipalName(&policy_prin_)) {
    LOG(ERROR) << "Could not get policy key principal name";
    return false;
  }
  policy_term_.reset(Term::ParseFromString(policy_prin_));
  if (policy_term_.get() == nullptr) {
    LOG(ERROR) << "Could not parse policy key principal name";
    return false;
  }
  return true;
}

bool DatalogGuard::GetSubprincipalName(string *subprin) const {
  // Use policy key as part of name
  subprin->assign("DatalogGuard(" + policy_prin_ + ")");
  return true;
}

static bool ContainsNestedVariables(const Term &term) {
  if (term.IsVariable()) {
    return true;
  } else if (term.IsPredicate()) {
    const Predicate *pred = term.GetPredicate();
    for (int i = 0; i < pred->ArgumentCount(); i++) {
      if (ContainsNestedVariables(*pred->Argument(i))) return true;
    }
  } else if (term.IsPrincipal()) {
    for (const Principal *prin = term.GetPrincipal(); prin != nullptr;
         prin = prin->Parent()) {
      const Predicate *pred = prin->Extension();
      for (int i = 0; i < pred->ArgumentCount(); i++) {
        if (ContainsNestedVariables(*pred->Argument(i))) return true;
      }
    }
  }
  return false;
}

static void GetVariables(const Predicate &pred, set<string> *refvars) {
  for (int i = 0; i < pred.ArgumentCount(); i++) {
    const Term *term = pred.Argument(i);
    if (term->IsVariable()) {
      refvars->insert(term->GetVariable());
    } else if (term->IsPredicate()) {
      // Nested predicates get turned into strings, assume here they don't
      // contain variables.
    } else if (term->IsPrincipal()) {
      // Nested principals get turned into strings, assume here they don't
      // contain variables.
    }
  }
}

static bool IsLegalVariableName(const string &s) {
  if (s.size() < 1)
    return false;
  if (!isalpha(s[0]))
    return false;
  for (unsigned int i = 1; i < s.size(); i++) {
    if (!isalnum(s[i]) && s[i] != '_')
      return false;
  }
  return true;
}

static bool ParseRule(const DatalogRule &rule, list<std::shared_ptr<Predicate>> *conds, scoped_ptr<Predicate> *consequent) {
  // Check vars for legality.
  set<string> vars;
  for (const string &var : rule.vars()) {
    if (!IsLegalVariableName(var)) {
      LOG(ERROR) << "Illegal variable name: " << var;
      return false;
    } 
    if (vars.find(var) != vars.end()) {
      LOG(ERROR) << "Duplicate quntification variable: " << var;
      return false;
    }
    vars.insert(var);
  }
  // Check conditions for legality.
  for (const auto &serialized_cond : rule.conds()) {
    scoped_ptr<Predicate> cond(Predicate::ParseFromString(serialized_cond));
    if (cond.get() == nullptr) {
      LOG(ERROR) << "Could not parse datalog predicate";
      return false;
    }
    if (conds == nullptr) {
      LOG(ERROR) << "Conditions are not allowed in this rule";
      return false;
    }
    conds->push_back(std::shared_ptr<Predicate>(cond.release()));
  }
  // Check consequent for legality.
  consequent->reset(Predicate::ParseFromString(rule.consequent()));
  if (consequent->get() == nullptr) {
    LOG(ERROR) << "Could not parse datalog consequent";
    return false;
  }
  // Make sure nested terms in conditions don't contain variables (since we
  // convert nested terms into strings).
  if (conds != nullptr) {
    for (const auto &cond : *conds) {
      for (int i = 0; i < cond->ArgumentCount(); i++) {
        if (!cond->Argument(i)->IsVariable() &&
          ContainsNestedVariables(*cond->Argument(i))) {
          LOG(ERROR) << "Nested quantification variables in condition not allowed";
          return false;
        }
      }
    }
  }
  // Make sure nested terms in conditions don't contain variables (since we
  // convert nested terms into strings).
  for (int i = 0; i < (*consequent)->ArgumentCount(); i++) {
    if (!(*consequent)->Argument(i)->IsVariable() &&
      ContainsNestedVariables(*(*consequent)->Argument(i))) {
      LOG(ERROR) << "Nested quantification variables in consequent not allowed";
      return false;
    }
  }
  // Make list of variables referenced in conditions.
  set<string> cond_refvars;
  if (conds != nullptr) {
    for (const auto &cond : *conds) {
      GetVariables(*cond, &cond_refvars);
    }
  }
  // Make list of variables referenced in consequent.
  set<string> consequent_refvars;
  GetVariables(**consequent, &consequent_refvars);
  // Check that each quantification variable is referenced.
  set<string> missing_vars;
  std::set_difference(vars.begin(), vars.end(), cond_refvars.begin(),
                      cond_refvars.end(), std::inserter(missing_vars, missing_vars.begin()));
  if (missing_vars.size() > 0) {
    LOG(ERROR) << "Unreferenced quantification variables: " << join(missing_vars, ", ");
    if (conds != nullptr) {
      LOG(INFO) << "There were " << conds->size() << " conditions";
      int i = 0;
      for (const auto &cond : *conds) {
        LOG(INFO) << "Condition " << (i++) << ". " << cond->SerializeToString();
      }
      LOG(INFO) << "Using these variables: " << join(cond_refvars, ", ");
      LOG(INFO) << "Quantification variables were : " << join(cond_refvars, ", ");
    }
    return false;
  }
  // Check that each reference variable in conditions was quantified.
  std::set_difference(cond_refvars.begin(), cond_refvars.end(), vars.begin(),
                      vars.end(), std::inserter(missing_vars, missing_vars.begin()));
  if (missing_vars.size() > 0) {
    LOG(ERROR) << "Unquantified condition variables: " << join(missing_vars, ", ");
    if (conds != nullptr) {
      LOG(INFO) << "There were " << conds->size() << " conditions";
      int i = 0;
      for (const auto &cond : *conds) {
        LOG(INFO) << "Condition " << (i++) << ". " << cond->SerializeToString();
      }
      LOG(INFO) << "Using these variables: " << join(list<string>(cond_refvars.begin(), cond_refvars.end()), ", ");
      LOG(INFO) << "Quantification variables were : " << join(vars, ", ");
    }
    return false;
  }
  // Check that each reference variable in consequent was quantified.
  std::set_difference(consequent_refvars.begin(), consequent_refvars.end(),
                      vars.begin(), vars.end(), std::inserter(missing_vars, missing_vars.begin()));
  if (missing_vars.size() > 0) {
    LOG(ERROR) << "Unquantified consequent variables: " << join(list<string>(missing_vars.begin(), missing_vars.end()), ", ");
    return false;
  }
  return true;
}

static void PushPredicate(dl_db_t db, const Predicate &pred, stringstream &dl_transcript)  // NOLINT
{
  // pred = Name(args...)
  dl_pushliteral(db);  // ?(?)
  dl_pushstring(db, pred.Name().c_str());
  dl_addpred(db); // Name(?)
  dl_transcript << pred.Name() << "(";
  string delim = "";
  for (int i = 0; i < pred.ArgumentCount(); i++) {
    const Term *term = pred.Argument(i);
    switch (term->GetType()) {
      case Term::VARIABLE:
        dl_pushstring(db, term->GetVariable().c_str());
        dl_addvar(db);
        dl_transcript << delim << term->GetVariable();
        break;
      case Term::INTEGER:
      case Term::PREDICATE:
      case Term::PRINCIPAL:
        dl_pushstring(db, term->SerializeToString().c_str());
        dl_addconst(db);
        dl_transcript << delim << quotedString(term->SerializeToString());
        break;
      case Term::STRING:
        dl_pushstring(db, term->GetString().c_str());
        dl_transcript << delim << quotedString(term->GetString());
        dl_addconst(db);
        break;
      default:
        LOG(ERROR) << "Internal error, should never happen";
        break;
    }
    delim = ", ";
  }
  dl_transcript << ")";
  dl_makeliteral(db);
}

bool DatalogGuard::PushDatalogRule(const DatalogRule &rule) {
  list<std::shared_ptr<Predicate>> conds;
  scoped_ptr<Predicate> consequent;
  if (!ParseRule(rule, &conds, &consequent)) {
    LOG(ERROR) << "Illegal rule";
    return false;
  }
  PushPredicate(dl->db, *consequent, dl_transcript);
  dl_pushhead(dl->db);
  if (conds.size() > 0)
    dl_transcript << " :- ";
  string delim = "";
  for (const auto &cond : conds) {
    dl_transcript << delim;
    delim = ", ";
    PushPredicate(dl->db, *cond, dl_transcript);
    dl_addliteral(dl->db);
  }
  dl_makeclause(dl->db);
  return true;
}

static Predicate *AddPolicySays(const Predicate &pred, const Term &policy_term)
{
  if (pred.Name() == "says" || pred.Name() == "subprin") {
    return pred.DeepCopy();
  } else {
    scoped_ptr<Predicate> says_pred(new Predicate("says"));
    says_pred->AddArgument(policy_term.DeepCopy());
    says_pred->AddArgument(new Term(pred.Name(), Term::STRING));
    for (int i = 0; i < pred.ArgumentCount(); i++)
      says_pred->AddArgument(pred.Argument(i)->DeepCopy());
    return says_pred.release();
  }
}

bool DatalogGuard::ParsePolicySaysIsAuthorized(const string &name,
                                               const string &op,
                                               const list<unique_ptr<Term>> &args,
                                               DatalogRule *rule) const {
  scoped_ptr<Predicate> pred(new Predicate("says"));
  pred->AddArgument(policy_term_->DeepCopy());
  pred->AddArgument(new Term("IsAuthorized", Term::STRING));
  scoped_ptr<Term> prin(Term::ParseFromString(name));
  if (prin.get() == nullptr || !prin->IsPrincipal()) {
    LOG(ERROR) << "Could not parse name";
    return false;
  }
  pred->AddArgument(prin.release());
  pred->AddArgument(new Term(op, Term::STRING));
  for (const auto &arg : args) {
    if (ContainsNestedVariables(*arg)) {
      LOG(ERROR) << "Variable appears outside quantification";
      return false;
    } else {
      pred->AddArgument(arg->DeepCopy());
    }
  }
  rule->set_consequent(pred->SerializeToString());
  return true;
}

bool DatalogGuard::IsAuthorized(const string &name, const string &op,
                            const list<unique_ptr<Term>> &args) {
  DatalogRule rule;
  if (!ParsePolicySaysIsAuthorized(name, op, args, &rule)) {
    LOG(ERROR) << "Could not parse authorization query";
    return false;
  }
  scoped_ptr<Predicate> query;
  if (!ParseRule(rule, nullptr /* no conditions */, &query)) {
    LOG(ERROR) << "Illegal query";
    return false;
  }
  PushPredicate(dl->db, *query, dl_transcript);
  dl_transcript << "?";
  VLOG(3) << "Datalog transcript:\n" << dl_transcript.str();
  dl_transcript.str("");
  dl_transcript.clear();
  dl_answers_t a;
  dl_ask(dl->db, &a);
  if (a == nullptr) {
    LOG(INFO) << "Principal " << elideString(name)
              << " is not authorized to perform " << op << "(...)";
    
    LOG(INFO) << " There were " << RuleCount() << " rules:";
    for (int i = 0; i < RuleCount(); i++) {
      string desc;
      GetRule(i, &desc);
      LOG(INFO) << " Rule " << (i) << ". " << desc;
    }
    return false;
  }
  dl_free(a);
  LOG(INFO) << "Principal " << elideString(name)
            << " is authorized to perform " << op << "(...)";
  return true;
}

static void AddDatalogRule(const DatalogRule &rule, DatalogRules *rules)
{
  // Allocate and copy in rule (can't add existing one).
  DatalogRule *new_rule = rules->add_rules();
  for (int i = 0; i < rule.vars_size(); i++) {
    new_rule->add_vars(rule.vars(i));
  }
  for (int i = 0; i < rule.conds_size(); i++) {
    new_rule->add_conds(rule.conds(i));
  }
  new_rule->set_consequent(rule.consequent());
}

bool DatalogGuard::Authorize(const string &name, const string &op,
                         const list<unique_ptr<Term>> &args) {
  DatalogRule rule;
  if (!ParsePolicySaysIsAuthorized(name, op, args, &rule)) {
    LOG(ERROR) << "Could not parse authorization rule";
    return false;
  }
  if (!PushDatalogRule(rule)) {
    LOG(ERROR) << "Could not install authorization rule";
    return false;
  }
  dl_assert(dl->db);
  dl_transcript << ".";
  VLOG(3) << "Datalog transcript:\n" << dl_transcript.str();
  dl_transcript.str("");
  dl_transcript.clear();
  AddDatalogRule(rule, &rules_);

  // TODO(kwalsh) Also add implicit rules for subprincipals
  
  return SaveConfig();
}

bool DatalogGuard::Revoke(const string &name, const string &op,
                      const list<unique_ptr<Term>> &args) {
  DatalogRule rule;
  if (!ParsePolicySaysIsAuthorized(name, op, args, &rule)) {
    LOG(ERROR) << "Could not parse authorization rule";
    return false;
  }
  string serialized_rule;
  if (!rule.SerializeToString(&serialized_rule)) {
    LOG(ERROR) << "Could not serialize authorization rule";
    return false;
  }
  bool found = false;
  DatalogRules new_rules;
  for (int i = 0; i < rules_.rules_size(); i++) {
    string other_rule;
    if (!rules_.rules(i).SerializeToString(&other_rule)) {
      LOG(ERROR) << "Could not serialize authorization rule";
      return false;
    }
    if (serialized_rule != other_rule) {
      AddDatalogRule(rules_.rules(i), &new_rules);
    } else {
      found = true;
    }
  }
  if (!found) {
    // TODO(kwalsh) maybe we should instead use datalog negation?
    LOG(WARNING) << "Rule not found";
    return false;
  }
  if (!PushDatalogRule(rule)) {
    LOG(ERROR) << "Could not retract authorization rule";
    return false;
  }
  dl_retract(dl->db);
  dl_transcript << "~";
  VLOG(3) << "Datalog transcript:\n" << dl_transcript.str();
  dl_transcript.str("");
  dl_transcript.clear();
  rules_ = new_rules;
  // We don't have enough state to remvoe the implicit subprincipal rules, but
  // leaving them in should be safe.
  return SaveConfig();
}

bool DatalogGuard::AddRule(const Predicate &pred) {
  list<unique_ptr<Predicate>> conditions;
  list<string> variables;
  return AddRule(variables, conditions, pred);
}

bool DatalogGuard::AddRule(const list<unique_ptr<Predicate>> &conditions,
                           const Predicate &consequent) {
  list<string> variables;
  return AddRule(variables, conditions, consequent);
}

bool DatalogGuard::AddRule(const list<string> &variables,
                           const list<unique_ptr<Predicate>> &conditions,
                           const Predicate &consequent) {
  DatalogRule rule;
  for (const auto &var : variables) {
    rule.add_vars(var);
  }
  for (const auto &cond : conditions) {
    scoped_ptr<Predicate> policy_says_cond(AddPolicySays(*cond, *policy_term_));
    rule.add_conds(policy_says_cond->SerializeToString());
  }
  scoped_ptr<Predicate> policy_says_consequent(AddPolicySays(consequent, *policy_term_));
  rule.set_consequent(policy_says_consequent->SerializeToString());
  if (!PushDatalogRule(rule)) {
    LOG(ERROR) << "Could not install authorization rule";
    return false;
  }
  dl_assert(dl->db);
  dl_transcript << ".";
  VLOG(3) << "Datalog transcript:\n" << dl_transcript.str();
  dl_transcript.str("");
  dl_transcript.clear();
  AddDatalogRule(rule, &rules_);

  // TODO(kwalsh) Also add implicit rules for subprincipals
  
  return SaveConfig();
}

bool DatalogGuard::AddRule(const string &desc) {
  stringstream in(desc);
  bool quantified = (in.peek() == '(');
  list<string> vars;
  if (quantified) {
    skip(in, "(forall ");
    if (!in) {
      LOG(ERROR) << "Expecting 'forall ' after parentheses";
      return false;
    }
    for (;;) {
      vars.push_back(GetIdentifier(in));
      if (!in) {
        LOG(ERROR) << "Expecting variable name after 'forall'";
        return false;
      }
      if (in.peek() != ',')
        break;
      skip(in, ", ");
      if (!in) {
        LOG(ERROR) << "Expecting space after comma";
        return false;
      }
    }
    skip(in, ": ");
    if (!in) {
      LOG(ERROR) << "Expecting ': ' after variable list";
      return false;
    }
  }
  list<unique_ptr<Predicate>> conds;
  scoped_ptr<Predicate> consequent;
  scoped_ptr<Predicate> pred(Predicate::ParseFromStream(in));
  if (!in) {
    LOG(ERROR) << "Expecting condition or consequent after variable list";
    return false;
  }
  if (in.peek() == ' ') {
    conds.push_back(std::move(unique_ptr<Predicate>(pred.release())));
    skip(in, " ");
    while (in && in.peek() == 'a') {
      skip(in, "and ");
      pred.reset(Predicate::ParseFromStream(in));
      if (!in) {
        LOG(ERROR) << "Expecting condition after 'and'";
        return false;
      }
      conds.push_back(std::move(unique_ptr<Predicate>(pred.release())));
      skip(in, " ");
    } 
    if (!in) {
      LOG(ERROR) << "Expecting space after condition";
      return false;
    }
    skip(in, "implies ");
    if (!in) {
      LOG(ERROR) << "Expecting 'and ' or 'implies ' after condition";
      return false;
    }
    consequent.reset(Predicate::ParseFromStream(in));
    if (!in) {
      LOG(ERROR) << "Expecting consequent after 'implies'";
      return false;
    }
  } if (in.eof()) {
    if (quantified) {
      LOG(ERROR) << "Expecting implication inside quantification";
      return false;
    }
    // no conditions
    consequent.reset(pred.release());
  }

  if (quantified) {
    skip(in, ")");
    if (!in) {
      LOG(ERROR) << "Expecting ')' after consequent";
      return false;
    }
  }
  if (!in || (in.get() && !in.eof())) {
    LOG(ERROR) << "Trailing text after rule";
    return false;
  }
  return AddRule(vars, conds, *consequent);
}

// TODO(kwalsh) Add RemoveRule() methods.

string DatalogGuard::DebugString() const {
  std::stringstream out;
  out << "Database of " << rules_.rules_size() << " policy rules:";
  int i = 0;
  for (auto &rule : rules_.rules())
    out << "\n  " << (i++) << ". " << DebugString(rule);
  return out.str();
}

int DatalogGuard::RuleCount() const { return rules_.rules_size(); }

bool DatalogGuard::GetRule(int i, string *desc) const {
  if (i < 0 || i > rules_.rules_size()) {
    LOG(ERROR) << "Invalid policy rule index";
    return false;
  }
  desc->assign(DebugString(rules_.rules(i)));
  return true;
}

string DatalogGuard::DebugString(const DatalogRule &rule) const {
  std::stringstream out;
  bool need_paren = (rule.vars_size() > 0);
  if (need_paren) out << "(";
  if (rule.vars_size() > 0) {
    const auto &vars = rule.vars();
    out << "forall " << join(vars.begin(), vars.end(), ", ");
    out << " : ";
  }
  if (rule.conds_size() > 0) {
    string delim = "";
    for (const auto &cond : rule.conds()) {
      out << delim << cond;
      delim = " and ";
    }
    out << " implies ";
  }
  out << rule.consequent();
  if (need_paren) out << ")";
  return out.str();
}

bool DatalogGuard::ParseConfig() {
  // Load basic configuration.
  if (!TaoDomain::ParseConfig()) {
    LOG(ERROR) << "Can't load basic configuration";
    return false;
  }
  // Load the signed rule file.
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
  // Parse the rules.
  if (!rules_.ParseFromString(srules.serialized_rules())) {
    LOG(ERROR) << "Can't parse serialized policy rules from " << path;
    return false;
  }
  for (const auto &rule : rules_.rules()) {
    if (!PushDatalogRule(rule)) {
      LOG(ERROR) << "Rule could not be installed";
      return false;
    }
    dl_assert(dl->db);
    dl_transcript << ".";
    VLOG(3) << "Datalog transcript:\n" << dl_transcript.str();
    dl_transcript.str("");
    dl_transcript.clear();
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
  srules.set_serialized_rules(serialized_rules);
  srules.set_signature(rules_signature);
  string serialized;
  if (!srules.SerializeToString(&serialized)) {
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
