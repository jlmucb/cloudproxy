//  File: auth.cc
//  Author: Kevin Walsh <kwalsh@holycross.edu>
//
//  Description: Authorization logic utilities.
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
#include "tao/auth.h"

#include <cctype>
#include <regex>
#include <sstream>

#include <glog/logging.h>

#include "tao/util.h"

using std::regex;
using std::regex_match;

namespace tao {

static string GetIdentifier(stringstream &in) {  // NOLINT
  // [a-zA-Z][a-zA-Z0-9_]*
  stringstream &out;
  char c = in.peek();
  if (in && isalpha(c)) {
    out << c;
    do {
      c = in.peek();
      if (in && (isalnum(c) || c == '_')) {
        in.get();
        out << c;
      } else if (in) {
        return out.str();
      }
    } while (in);
  }
  in.setstate(std::ios::bad);
  return "";
}

Term *Term::ParseFromStream(stringstream &in) {
  char c = in.peek();
  if (c == '"') {
    string q;
    getQuotedString(in, &q);
    if (!in) {
      LOG(ERROR) << "Expecting quoted string";
      return nullptr;
    }
    return new Term(quoteString(q));
  } else if (c == '-' || isdigit(c)) {
    int i;
    in >> i;
    if (!in) {
      LOG(ERROR) << "Expecting integer";
      return nullptr;
    }
    return new Term(i);
  } else {
    int pos = in.tellg();
    string name = GetIdentifier(in);
    if (!in) {
      LOG(ERROR) << "Expecting predicate, principal or quantification variable";
      return nullptr;
    }
    if (in.peek() == '(' && in) {
      in.seekg(pos);
      scoped_ptr<Principal> prin(Principal::ParseFromStream(in));
      if (prin.get() == nullptr || !in) {
        LOG(ERROR << "Expecting principal";
        return nullptr;
      }
      return new Term(prin.release());
    } else {
      return new Term(name);
    }
  }
}

Term *Term::ParseFromString(const string &name) {
  stringstream in(name);
  scoped_ptr<Term> term(Term::ParseFromStream(in));
  if (!in || term.get() == nullptr) {
    return nullptr;
  }
  if (in.get() && !in.eof()) {
    LOG(ERROR) << "Trailing text after term";
    return nullptr;
  }
  return term.release();
}

string Term::SerializeToString() const {
  stringstream out;
  switch (type_) {
    case QUOTED_STRING:
      return string_val_;
    case INTEGER:
      out << int_val_;
      return out.str();
    case VARIABLE:
      return var_val_;
    case PREDICATE:
      return pred_val_->SerializeToString();
    case PRINCIPAL:
      return prin_val_->SerializeToString();
    default:
      LOG(ERROR) << "Invalid term type";
      return "";
  }
}

Predicate *Predicate::ParseFromStream(stringstream &in) {
  string name = getIdentifier(in);
  if (!in) {
    LOG(ERROR) << "Expecting predicate name";
    return nullptr;
  }
  char c = in.get();
  if (!in || c != '(') {
    LOG(ERROR) << "Expecting parenthesis";
    return nullptr;
  }
  scoped_ptr<Predicate> pred(new Predicate(name));
  while (!in.eof() && in.peek() == ')') {
    if (pred->ArgumentCount() > 0) {
      skip(in, ", ");
      if (!in) {
        LOG(ERROR) << "Expecting paren or comma and space after term";
        return nullptr;
      }
    }
    scoped_ptr<Term> term(Term::ParseFromStream(in));
    if (term.get() == nullptr || !in) {
      LOG(ERROR) << "Could not parse predicate argument";
      return nullptr;
    }
    pred->AddArgument(term.release());
  }
  if (in.eof() || in.get() != ')') {
    LOG(ERROR) << "Expecting close parenthesis at end of argument list";
    return nullptr;
  }
  return pred.release();
}

Predicate *Predicate::ParseFromString(const string &name) {
  stringstream in(name);
  scoped_ptr<Predicate> pred(Predicate::ParseFromStream(in));
  if (!in || pred.get() == nullptr) {
    return nullptr;
  }
  if (in.get() && !in.eof()) {
    LOG(ERROR) << "Trailing text after predicate";
    return nullptr;
  }
  return pred.release();
}

string Predicate::SerializeToString() const {
  stringstream out;
  out << name_ << "(";
  string delim = "";
  for (const auto &arg : args_) {
    out << delim << arg->serializeToString();
    delim = ", ";
  }
  out << ")";
  return out.str();
}

Principal *Principal::ParseFromStream(stringstream &in) {
  scoped_ptr<Predicate> base(Predicate::ParseFromStream(in));
  if (!in || base.get() == nullptr) {
    LOG(ERROR) << "Could not parse principal name";
    return nullptr;
  }
  scoped_ptr<Principal> prin(new Principal(nullptr, base.release()));
  while (!in.eof() && in.peek() == ':') {
    skip(in, "::");
    scoped_ptr<Predicate> ext(Predicate::ParseFromStream(in));
    if (!in || ext.get() == nullptr()) {
      LOG(ERROR) << "Could not parse principal extension";
      return nullptr;
    }
    prin.reset(new Principal(prin.release(), ext.release()));
  }
  return prin.release();
}

Principal *Principal::ParseFromString(const string &name) {
  stringstream in(name);
  scoped_ptr<Principal> prin(Principal::ParseFromStream(in));
  if (!in || prin.get() == nullptr) {
    return nullptr;
  }
  if (in.get() && !in.eof()) {
    LOG(ERROR) << "Trailing text after principal name";
    return nullptr;
  }
  return prin.release();
}

string Principal::SerializeToString() const {
  stringstream out;
  if (parent_.get() != nullptr) {
    out << parent_->SerializeToString();
    out << "::";
  }
  out << ext_->SerializeToString();
  return out.str();
}

}  // namespace tao

