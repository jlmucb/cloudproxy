//  File: datalog_guard.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Authorization guard based on predicates and datalog.
//
//  Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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
#ifndef TAO_DATALOG_GUARD_H_
#define TAO_DATALOG_GUARD_H_

#include <list>
#include <set>
#include <string>

#include <keyczar/base/values.h>

#include "tao/datalog_guard.pb.h"
#include "tao/tao_domain.h"
#include "tao/util.h"

namespace tao {

/// A struct to contain datalog engine state.
struct DatalogEngine;

/// Cleanup routine for datalog engine state.
void datalog_close(DatalogEngine *dl);

/// A smart pointer to datalog engine state.
typedef unique_free_ptr<DatalogEngine, datalog_close> ScopedDatalogEngine;

/// An guard that uses policy rules stored in a single file, signed by the
/// policy key, as the basis of authorization, and a datalog engine for making
/// authorization decisions. The guard translates the policy rules into a set of
/// datalog rules. Authorization queries are then translated into datalog
/// queries and solved using the datalog engine.
///
/// Datalog translation: We assume K_policy speaksfor Guard, and all deduction
/// takes place within the worldview of Guard. Aside from that case, and from
/// the speaksfor logic implemented in attestation.cc for verifying signed
/// attestations, we do not use any speaksfor operators. So we do not fully
/// model the logic of says and speaksfor in datalog.
///
/// Term: integer or quoted string
/// Datalog: left as is
///
/// Term: principal
/// Datalog: converted to quoted string
/// Note: Principals are "::"-separated lists of components of the form
/// Name(args...), where args is a comma-separated list of integers or quoted
///   strings.
///
/// Attestation: P says Pred(args...)
/// Datalog: says(P, Pred, args...)
/// Note: args is a comma-separated list of terms.
///
/// Policy rule: K_policy says
///                (forall V1, V2, ...
///                   (Cond1 and Cond2 and ...) implies Pred(args...))
/// Datalog rule: says(K_policy, Pred, args...) :- c1, c2, ..
///   where each condition can be either P says Pred(...), translated as above
///   to says(P,...), a predicate Pred(...), translated as above to
///   says(K_policy,...), or P = O::E, translated to the built-in predicate
///   subprin(P, O, E).
/// Note: Variable Vi can appear in place of a term in the conditions, and each
///   Vi must appear at least once in the conditions to ensure the datalog rule
///   will be safe. A variable Vi can also appear in place of a term in the
///   consequent. In all other cases, the arguments to predicates must be terms.
///   By convention, datalog variables start with an uppercase and predicates
///   start with a lowercase. We require instead that variables and predicates
///   match [a-zA-Z][a-zA-Z0-9_]*.
///
/// Authorization query: IsAuthorized(P, op, args...)
/// Datalog query: says(K_policy, "IsAuthorized", P, op, args...)
/// Note: Op is a string, and arguments are terms.
///
/// Predicates from principal names: For a principal P of the form
/// Parent::Pred(args...), we assume that parent is also attesting that this
/// principal has the property indicated by its name. So for every such
/// principal name, we automatically deduce Parent says Pred(P, args...).
///
/// The guard provides a built-in predicate subprin/3, where subprin(A, B, C)
/// iff either A is a string constant or B and C are, and A is equal to B::C,
/// and all can be used as principal names.
///
/// Example policy:
///   Program P can execute only if P has a trusted hash, as evidenced by its
///   subprin name, P is running on an OS with trusted PCRs, as evidenced by its
///   subprin name, and OS is running on a trusted TPM, as evidenced by its AIK.
/// Policy rules involving quantification and implication:
///   K_policy says forall P, O, E, H :
///       subprin(P, O, E) and
///       isTrustedOS(O) and
///       O says Program(P, H) and
///       isTrustedProgramHash(H)
///     implies
///       isAuthorized(P, "Execute")
///   K_policy says forall P, O, E, I, V :
///       subprin(P, O, E) and
///       isTrustedPlatform(O) and
///       O says PCRs(P, I, V) and
///       isTrustedOSPCRs(I, V)
///     implies
///       isTrustedOS(P)
/// Policy rules without quantification or implication:
///   K_policy says isTrustedPlatform(TPM("aaa")), ...
///   K_policy says isTrustedOSPCRs("17, 18", "xxx, yyy"), ...
///   K_policy says isTrustedProgramHash("hhh"), ...
/// Platform and OS attestations (automatically derived from principal names):
///   TPM("aaa") says
///      PCRs(TPM("aaa")::PCRs("17, 18", "xxx, yyy"), "17, 18", "xxx, yyy")
///   TPM("aaa")::PCRs("17, 18", "xxx, yyy") says
///      Program(TPM("aaa")::PCRs("17, 18", "xxx, yyy")::Program("hhh"), "hhh")
///
class DatalogGuard : public TaoDomain {
 public:
  /// Name strings for name:value pairs in JSON config.
  constexpr static auto JSONSignedDatalogRulesPath = "signed_rules_path";

  /// Example json strings useful for constructing domains for testing.
  constexpr static auto ExampleGuardDomain =
      "{\n"
      "   \"name\": \"Tao example Datalog-based domain\",\n"
      "\n"
      "   \"policy_keys_path\":     \"policy_keys\",\n"
      "   \"policy_x509_details\":  \"country: \\\"US\\\" state: "
      "\\\"Washington\\\" organization: \\\"Google\\\" commonname: \\\"tao "
      "example domain\\\"\",\n"
      "   \"policy_x509_last_serial\": 0,\n"
      "\n"
      "   \"guard_type\": \"Datalog\",\n"
      "   \"signed_rules_path\": \"domain_rules\",\n"
      "\n"
      "   \"tao_ca_host\": \"localhost\",\n"
      "   \"tao_ca_port\": \"11238\"\n"
      "}";

  DatalogGuard(const string &path, DictionaryValue *value)
      : TaoDomain(path, value) {}
  virtual ~DatalogGuard() {}

  virtual string GuardTypeName() const { return "DatalogGuard"; }

  /// These methods have the same semantics as in TaoGuard. DatalogGuard
  /// supports the basic syntax for rules and queries, i.e.
  ///   Authorized(P, op, args...).
  ///
  /// DatalogGuard also supports two built-in predicates for rules or queries:
  ///   says(P, "Pred", args...)
  /// and
  ///   subprin(P, Parent, Extension).
  ///
  /// DatalogGuard also supports any other predicate for rules or queries:
  ///   Pred(args...).
  /// Internally, predicates other than the built-in ones are translated to
  /// says()-style predicates with the policy principal as the speaker, i.e.:
  ///   says("Key(\"policy key material...\")", "Pred", args...)
  /// where each arg is converted to a string or integer or, in some cases, to a
  /// quantification variable.
  ///
  /// DatalogGuard also supports conditional predicates for rules:
  ///   Condition and ... implies Consequent.
  /// Here, the conditions and consequent are predicates as above.
  ///
  /// DatalogGuard also supports quantified conditional predicates for rules:
  ///   (forall Variable...: Condition and ... implies Consequent).
  /// Here, the conditions and consequent are predicates as above, and the
  /// variables are simple identifiers. In order to ensure Datalog safety, all
  /// quantification variables must appear somewhere in the conditions, and a
  /// subset of them may appear in the consequent.
  ///
  /// @{
  virtual bool AddRule(const string &rule);
  virtual bool RetractRule(const string &rule);
  virtual bool Clear();
  virtual bool Query(const string &query);
  virtual int RuleCount() const;
  virtual string GetRule(int i) const;
  /// @}

  constexpr static auto DatalogSigningContext =
      "tao::SignedDatalogRules Version 1";

  constexpr static auto GuardType = "Datalog";

 protected:
  virtual bool Init();

  /// Push a predicate to the datalog engine.
  /// @param pred The predicate.
  virtual void PushPredicate(const Predicate &pred);

  /// Push a rule to the datalog engine. No checking is done for rule safety.
  /// @param vars The quantification variables, if any.
  /// @param conds The conditions, if any.
  /// @param consequent The consequent.
  virtual void PushRule(const set<string> &vars,
                        const list<unique_ptr<Predicate>> &conds,
                        const Predicate &consequent);

  /// Parse a rule, adding implicitly says(K_Policy, ...) as needed. No checking
  /// is done for variable usage (i.e. Datalog rule safety).
  /// @param rule The rule.
  /// @param[out] vars The quantification variables, if any.
  /// @param[out] conds The conditions, if any.
  /// @param[out] consequent The consequent.
  virtual bool ParseRule(const string &rule, set<string> *vars,
                         list<unique_ptr<Predicate>> *conds,
                         unique_ptr<Predicate> *consequent);

  /// Push a rule to the datalog policy engine stack.
  /// @param rule The rule.
  /// @param revoke Whether to retract the rule (vs. assert it).
  virtual bool ProcessRule(const string &rule, bool retract);

  /// Parse all configuration parameters from the configuration file and load
  /// keys and other state. This loads and checks the signature on the
  /// ACLs, then imports it into a local data store.
  virtual bool ParseConfig();

  /// Save all configuration parameters to the configuration file and save all
  /// other state. This signs and saves the ACLs. This fails if the
  /// TaoDomain is locked.
  virtual bool SaveConfig() const;

  /// Reload rules from disk if they were changed recently.
  bool ReloadRulesIfModified();

 private:
  // The set of datalog rules.
  DatalogRules rules_;

  // Datalog engine state.
  ScopedDatalogEngine dl_;

  // The principal name for the policy key.
  string policy_prin_;

  // The principal Term for the policy key.
  unique_ptr<Term> policy_term_;

  // Transcript of recent datalog API calls (for debugging).
  stringstream dl_transcript_;

  // The path to the signed rules file.
  string rules_path_;

  // Modification time of signed rules file when it was read.
  time_t rules_mod_time_;

  // Minimum time in seconds before re-checking modification time of rules file.
  constexpr static int RulesFileRefreshTimeout = 10;

  DISALLOW_COPY_AND_ASSIGN(DatalogGuard);
};
}  // namespace tao

#endif  // TAO_DATALOG_GUARD_H_
