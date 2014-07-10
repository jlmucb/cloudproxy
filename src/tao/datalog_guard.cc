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
#include <lauxlib.h>
#include <lua.h>
}
// lua.h must come before datalog.h
#include <datalog.h>

#include "tao/auth.h"
#include "tao/auth_lua.h"
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
  dl_.reset(new DatalogEngine());
  dl_->db = dl_open();
  if (!LuaLoadAuthModule(dl_->db)) {
    LOG(ERROR) << "Could not initialize Datalog auth module";
    return false;
  }
  policy_prin_ = GetPolicyVerifier()->ToPrincipalName();
  if (policy_prin_ == "") {
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

static bool CheckRule(const set<string> &vars,
                      const list<unique_ptr<Predicate>> &conds,
                      const Predicate &consequent) {
  // Make sure nested predicates in conditions don't contain variables (since we
  // convert nested predicates into strings).
  for (const auto &cond : conds) {
    for (int i = 0; i < cond->ArgumentCount(); i++) {
      if (!cond->Argument(i)->IsVariable() &&
          ContainsNestedVariables(*cond->Argument(i))) {
        LOG(ERROR)
            << "Nested quantification variables in condition not allowed";
        return false;
      }
    }
  }
  // Make sure nested predicates in conditions don't contain variables (since we
  // convert nested terms into strings).
  for (int i = 0; i < consequent.ArgumentCount(); i++) {
    if (!consequent.Argument(i)->IsVariable() &&
        ContainsNestedVariables(*consequent.Argument(i))) {
      LOG(ERROR) << "Nested quantification variables in consequent not allowed";
      return false;
    }
  }
  // Make list of variables referenced in conditions.
  set<string> cond_refvars;
  for (const auto &cond : conds) {
    GetVariables(*cond, &cond_refvars);
  }
  // Make list of variables referenced in consequent.
  set<string> consequent_refvars;
  GetVariables(consequent, &consequent_refvars);
  // Check that each quantification variable is referenced.
  // And check that each reference variable in conditions was quantified.
  set<string> missing_qvars;
  std::set_difference(vars.begin(), vars.end(), cond_refvars.begin(),
                      cond_refvars.end(),
                      std::inserter(missing_qvars, missing_qvars.begin()));
  set<string> missing_cvars;
  std::set_difference(cond_refvars.begin(), cond_refvars.end(), vars.begin(),
                      vars.end(),
                      std::inserter(missing_cvars, missing_cvars.begin()));
  if (missing_qvars.size() > 0 || missing_cvars.size() > 0) {
    if (missing_qvars.size() > 0)
      LOG(ERROR) << "Unreferenced quantification variables: "
                 << join(missing_qvars, ", ");
    if (missing_cvars.size() > 0)
      LOG(ERROR) << "Unquantified condition variables: " << join(missing_cvars,
                                                                 ", ");
    LOG(INFO) << "Condition variables: " << join(cond_refvars, ", ");
    LOG(INFO) << "Quantification variables were : " << join(vars, ", ");
    return false;
  }
  // Check that each reference variable in consequent was quantified.
  set<string> missing_vars;
  std::set_difference(consequent_refvars.begin(), consequent_refvars.end(),
                      vars.begin(), vars.end(),
                      std::inserter(missing_vars, missing_vars.begin()));
  if (missing_vars.size() > 0) {
    LOG(ERROR) << "Unquantified consequent variables: " << join(missing_vars,
                                                                ", ");
    LOG(INFO) << "Consequent variables: " << join(consequent_refvars, ", ");
    LOG(INFO) << "Quantification variables were : " << join(vars, ", ");
    return false;
  }
  return true;
}

void DatalogGuard::PushPredicate(const Predicate &pred) {
  // pred = Name(args...)
  dl_pushliteral(dl_->db);  // ?(?)
  dl_pushstring(dl_->db, pred.Name().c_str());
  dl_addpred(dl_->db);  // Name(?)
  dl_transcript_ << pred.Name() << "(";
  string delim = "";
  for (int i = 0; i < pred.ArgumentCount(); i++) {
    const Term *term = pred.Argument(i);
    switch (term->GetType()) {
      case Term::VARIABLE:
        dl_pushstring(dl_->db, term->GetVariable().c_str());
        dl_addvar(dl_->db);
        dl_transcript_ << delim << term->GetVariable();
        break;
      case Term::INTEGER:
      case Term::PREDICATE:
      case Term::PRINCIPAL:
        dl_pushstring(dl_->db, term->SerializeToString().c_str());
        dl_addconst(dl_->db);
        dl_transcript_ << delim << quotedString(term->SerializeToString());
        break;
      case Term::STRING:
        dl_pushstring(dl_->db, term->GetString().c_str());
        dl_transcript_ << delim << quotedString(term->GetString());
        dl_addconst(dl_->db);
        break;
      default:
        LOG(ERROR) << "Internal error, should never happen";
        break;
    }
    delim = ", ";
  }
  dl_transcript_ << ")";
  dl_makeliteral(dl_->db);
}

void DatalogGuard::PushRule(const set<string> &vars,
                            const list<unique_ptr<Predicate>> &conds,
                            const Predicate &consequent) {
  PushPredicate(consequent);
  dl_pushhead(dl_->db);
  if (conds.size() > 0) dl_transcript_ << " :- ";
  string delim = "";
  for (const auto &cond : conds) {
    dl_transcript_ << delim;
    delim = ", ";
    PushPredicate(*cond);
    dl_addliteral(dl_->db);
  }
  dl_makeclause(dl_->db);
}

static Predicate *AddPolicySays(const Predicate &pred,
                                const Term &policy_term) {
  if (pred.Name() == "says" || pred.Name() == "subprin") {
    return pred.DeepCopy();
  } else {
    unique_ptr<Predicate> says_pred(new Predicate("says"));
    says_pred->AddArgument(policy_term.DeepCopy());
    says_pred->AddArgument(new Term(pred.Name(), Term::STRING));
    for (int i = 0; i < pred.ArgumentCount(); i++)
      says_pred->AddArgument(pred.Argument(i)->DeepCopy());
    return says_pred.release();
  }
}

bool DatalogGuard::ParseRule(const string &rule, set<string> *vars,
                             list<unique_ptr<Predicate>> *conds,
                             unique_ptr<Predicate> *consequent) {
  stringstream in(rule);
  bool quantified = (in.peek() == '(');
  // Get the variables, if any.
  vars->clear();
  if (quantified) {
    skip(in, "(forall ");
    if (!in) {
      LOG(ERROR) << "Expecting 'forall ' after parentheses";
      return false;
    }
    for (;;) {
      string var = GetIdentifier(in);
      if (vars->find(var) != vars->end()) {
        LOG(ERROR) << "Duplicate quantification variable ";
        return false;
      }
      vars->insert(var);
      if (!in) {
        LOG(ERROR) << "Expecting variable name after 'forall'";
        return false;
      }
      if (in.peek() != ',') break;
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
  // Check for conditions.
  conds->clear();
  unique_ptr<Predicate> pred(Predicate::ParseFromStream(in));
  if (!in) {
    LOG(ERROR) << "Expecting condition or consequent";
    return false;
  }
  if (in.peek() != ' ' && in.eof()) {
    // No conditions, get the consequent.
    if (quantified) {
      LOG(ERROR) << "Expecting implication inside quantification";
      return false;
    }
    // no conditions
    consequent->reset(AddPolicySays(*pred, *policy_term_));
  } else {
    // Have conditions, get them.
    conds->push_back(
        std::move(unique_ptr<Predicate>(AddPolicySays(*pred, *policy_term_))));
    skip(in, " ");
    while (in && in.peek() == 'a') {
      skip(in, "and ");
      pred.reset(Predicate::ParseFromStream(in));
      if (!in) {
        LOG(ERROR) << "Expecting condition after 'and'";
        return false;
      }
      conds->push_back(std::move(
          unique_ptr<Predicate>(AddPolicySays(*pred, *policy_term_))));
      skip(in, " ");
    }
    if (!in) {
      LOG(ERROR) << "Expecting space after condition";
      return false;
    }
    // Get the implication and consequent after the conditions.
    skip(in, "implies ");
    if (!in) {
      LOG(ERROR) << "Expecting 'and ' or 'implies ' after condition";
      return false;
    }
    pred.reset(Predicate::ParseFromStream(in));
    if (!in) {
      LOG(ERROR) << "Expecting consequent after 'implies'";
      return false;
    }
    consequent->reset(AddPolicySays(*pred, *policy_term_));
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
  return true;
}

bool DatalogGuard::ProcessRule(const string &rule, bool retract) {
  set<string> vars;
  list<unique_ptr<Predicate>> conds;
  unique_ptr<Predicate> consequent;
  if (!ParseRule(rule, &vars, &conds, &consequent)) {
    LOG(ERROR) << "Could not parse rule";
    return false;
  }
  if (!CheckRule(vars, conds, *consequent)) {
    LOG(ERROR) << "Rejecting unsafe rule";
    return false;
  }
  PushRule(vars, conds, *consequent);
  if (retract) {
    dl_retract(dl_->db);
    dl_transcript_ << "~";
  } else {
    dl_assert(dl_->db);
    dl_transcript_ << ".";
  }
  VLOG(3) << "Datalog transcript:\n" << dl_transcript_.str();
  dl_transcript_.str("");
  dl_transcript_.clear();
  return true;
}

bool DatalogGuard::AddRule(const string &rule) {
  if (!ProcessRule(rule, false /* do not retract */)) {
    LOG(ERROR) << "Could not process rule";
    return false;
  }
  rules_.add_rules(rule);
  // TODO(kwalsh) Also add implicit rules for subprincipals
  return SaveConfig();
}

bool DatalogGuard::RetractRule(const string &rule) {
  if (!ProcessRule(rule, true /* retract */)) {
    LOG(ERROR) << "Could not process rule";
    return false;
  }
  bool found = false;
  for (int i = rules_.rules_size() - 1; i >= 0; i--) {
    if (rules_.rules(i) == rule) {
      found = true;
      rules_.mutable_rules()->DeleteSubrange(i, 1);
    }
  }
  if (!found) {
    LOG(WARNING) << "Rule to be revoked was not found";
    return false;
  }
  // We don't have enough state to remove the implicit subprincipal rules, but
  // leaving them in should be safe.
  return SaveConfig();
}

bool DatalogGuard::Clear() {
  rules_.clear_rules();
  dl_close(dl_->db);
  dl_->db = dl_open();
  return SaveConfig();
}

bool DatalogGuard::Query(const string &query) {
  unique_ptr<Predicate> pred(Predicate::ParseFromString(query));
  if (pred.get() == nullptr) {
    LOG(ERROR) << "Could not parse query";
    return false;
  }
  pred.reset(AddPolicySays(*pred, *policy_term_));
  PushPredicate(*pred);
  dl_transcript_ << "?";
  VLOG(3) << "Datalog transcript:\n" << dl_transcript_.str();
  dl_transcript_.str("");
  dl_transcript_.clear();
  dl_answers_t a;
  dl_ask(dl_->db, &a);
  if (a == nullptr) {
    return false;
  }
  dl_free(a);
  return true;
}

int DatalogGuard::RuleCount() const { return rules_.rules_size(); }

string DatalogGuard::GetRule(int i) const { return rules_.rules(i); }

bool DatalogGuard::ParseConfig() {
  // Load basic configuration.
  if (!TaoDomain::ParseConfig()) {
    LOG(ERROR) << "Can't load basic configuration";
    return false;
  }
  // Load the signed rule file.
  rules_path_ = GetConfigPath(JSONSignedDatalogRulesPath);
  rules_mod_time_ = 0;  // force refresh
  return ReloadRulesIfModified();
}

bool DatalogGuard::ReloadRulesIfModified() {
  string path = rules_path_;
  time_t mod_time = FileModificationTime(path);
  if (mod_time == 0) {
    LOG(ERROR) << "Can't stat rules from " << path;
    return false;
  }
  if (mod_time < rules_mod_time_) {
    LOG(WARNING) << "Ignoring bogus timestamp for " << path;
  } else if (mod_time - rules_mod_time_ < RulesFileRefreshTimeout) {
    return true;
  }
  // Read the file.
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
  if (!GetPolicyVerifier()->Verify(srules.serialized_rules(),
                                   DatalogSigningContext, srules.signature())) {
    LOG(ERROR) << "Signature did not verify on signed policy rules from "
               << path;
    return false;
  }
  // Parse the rules.
  if (!rules_.ParseFromString(srules.serialized_rules())) {
    LOG(ERROR) << "Can't parse serialized policy rules from " << path;
    // TODO(kwalsh) Does this leave rules_ out of sync with datalog engine?
    return false;
  }
  for (const auto &rule : rules_.rules()) {
    if (!ProcessRule(rule, false /* do not retract */)) {
      LOG(ERROR) << "Could not process rule";
      // TODO(kwalsh) This leaves datalog engine in an incomplete state.
      return false;
    }
  }
  rules_mod_time_ = mod_time;
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
  if (!GetPolicySigner()->Sign(serialized_rules, DatalogSigningContext,
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
