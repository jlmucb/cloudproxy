//  File: auth.h
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Authorization logic utilities.
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
#ifndef TAO_AUTH_H_
#define TAO_AUTH_H_

#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "tao/util.h"

namespace tao {
using std::string;
using std::stringstream;
using std::vector;

class Predicate;
class Principal;

// TODO(kwalsh) Revise attestation code to use these classes where appropriate.

string GetIdentifier(stringstream &in);  // NOLINT

class Term {
 public:
  enum TermType { STRING, INTEGER, VARIABLE, PREDICATE, PRINCIPAL };

  Term(const string &s, TermType type)
      : type_(type),
        string_val_(type == STRING ? s : ""),
        var_val_(type == VARIABLE ? s : "") {}
  explicit Term(int i) : type_(INTEGER), int_val_(i) {}
  explicit Term(Predicate *pred) : type_(PREDICATE), pred_val_(pred) {}
  explicit Term(Principal *prin) : type_(PRINCIPAL), prin_val_(prin) {}

  /// Parse a term from a stream.
  /// @param[in, out] in Stream containing the name and maybe more.
  static Term *ParseFromStream(stringstream &in);  // NOLINT

  /// Parse a term from a string.
  /// @param name The name of the principal.
  static Term *ParseFromString(const string &ext);

  ~Term() {}

  /// Create a deep copy of this Term.
  Term *DeepCopy() const;

  /// Produce a string representation.
  string SerializeToString() const;

  // /// Compare this Term with another for equality.
  // /// @param other The other Term.
  // bool Equals(const Term &other) const {
  //   return SerializeToString() == other.SerializeToString();
  // }

  /// Get the type of this term.
  TermType GetType() const { return type_; }

  /// Check whether this term is a quoted string.
  bool IsString() const { return type_ == STRING; }

  /// Check whether this term is a quoted string and get it.
  string GetString() const { return string_val_; }

  /// Check whether this term is an integer.
  bool IsInteger() const { return type_ == INTEGER; }

  /// Check whether this term is an integer and get it.
  int GetInteger() const { return int_val_; }

  /// Check whether this term is a quantification variable.
  bool IsVariable() const { return type_ == VARIABLE; }

  /// Check whether this term is a quantification variable and get it.
  string GetVariable() const { return var_val_; }

  /// Check whether this term is a nested predicate.
  bool IsPredicate() const;

  /// Check whether this term is a nested term and get it.
  const Predicate *GetPredicate() const;

  /// Check whether this term is a principal name (or a nested term).
  bool IsPrincipal() const { return type_ == PRINCIPAL; }

  /// Check whether this term is a principal name (or a nested term) and get it.
  const Principal *GetPrincipal() const { return prin_val_.get(); }

 private:
  /// The type of term.
  TermType type_;

  /// The contents of the term (at most one will be used).
  /// @{
  string string_val_;
  int int_val_;
  string var_val_;
  unique_ptr<Predicate> pred_val_;
  unique_ptr<Principal> prin_val_;
  /// @}

  DISALLOW_COPY_AND_ASSIGN(Term);
};

/// A class to represent a predicate of the form Pred(args...), where each arg
/// is a Term.
class Predicate {
 public:
  /// Parse a predicate from a stream.
  /// @param[in, out] in Stream containing the name and maybe more.
  static Predicate *ParseFromStream(stringstream &in);  // NOLINT

  /// Parse a predicate from a string.
  /// @param name The name of the principal.
  static Predicate *ParseFromString(const string &ext);

  explicit Predicate(const string &name) : name_(name) {}

  /// Add an argument to this predicate.
  /// @param t The term to add. Ownership is taken.
  void AddArgument(Term *t) { args_.push_back(std::shared_ptr<Term>(t)); }

  ~Predicate() {}

  /// Create a deep copy of this Predicate.
  Predicate *DeepCopy() const;

  /// Produce a string representation.
  string SerializeToString() const;

  /// Get the name of the predicate.
  const string &Name() const { return name_; }

  /// Get the predicate arity.
  int ArgumentCount() const { return args_.size(); }

  /// Get one argument.
  /// @param i The index of the argument.
  const Term *Argument(int i) const {
    return (i < 0 || (unsigned)i >= args_.size()) ? nullptr : args_[i].get();
  }

 private:
  /// The predicate name.
  string name_;

  /// The list of arguments.
  vector<std::shared_ptr<Term>> args_;

  DISALLOW_COPY_AND_ASSIGN(Predicate);
};

/// A class to represent a principal name.
class Principal {
 public:
  /// Parse a name from a stream.
  /// @param[in, out] in Stream containing the name and maybe more.
  static Principal *ParseFromStream(stringstream &in);  // NOLINT

  /// Parse a name from a string.
  /// @param name The name of the principal.
  static Principal *ParseFromString(const string &name);

  ~Principal() {}

  /// Create a deep copy of this Principal.
  Principal *DeepCopy() const;

  /// Produce a string representation.
  string SerializeToString() const;

  /// Check whether this principal has a parent.
  bool HasParent() const { return parent_.get() != nullptr; }

  /// Get this principal's parent, if it exists.
  const Principal *Parent() const { return parent_.get(); }

  /// Get this principal's extension (or "base name"), the last component of its
  /// full name.
  const Predicate *Extension() const { return ext_.get(); }

 private:
  Principal(Principal *parent, Predicate *ext) : parent_(parent), ext_(ext) {}

  unique_ptr<Principal> parent_;
  unique_ptr<Predicate> ext_;

  DISALLOW_COPY_AND_ASSIGN(Principal);
};

}  // namespace tao
#endif  // TAO_AUTH_H_
