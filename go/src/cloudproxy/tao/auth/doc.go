// Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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

// Package auth supports Tao authorization and authentication, primarily by
// defining and implementing a logic for describing principals, their trust
// relationships, and their beliefs.
//
// The grammar for a formula in the logic is roughly:
//   Form ::= Prin [from Time] [until Time] says Form 
//          | Prin speaksfor Prin
//          | Form implies Form
//          | Form or Form or ...
//          | Form and Form and ...
//          | not Form
//          | Pred | false | true
//
// Times are integers interpreted as 64-bit unix timestamps.
//   Time ::= int64
//
// Predicates are like boolean-valued pure functions, with a name and zero or
// more terms as arguments.
//   Pred ::= Identifier(Term, Term, ...)
//          | Identifier()
//          | Identifier
// 
// Terms are concrete values, like strings, integers, or names of principals.
//   Term ::= string | int | Prin
//
// Principal names specify a key, and zero or more extensions to specify a
// sub-principal of that key.
//   Prin ::= key(string)
//          | key(string).PredExt.PredExt...
//   PredExt ::= Identifier(Term, Term, ...)
//             | Identifier()
//             | Identifier
//
// Identifiers for predicate and principal extension names are limited to simple
// ascii printable identifiers, with inital upper-case, and no punctuation
// except '_':
//   PredName ::= [A-Z][a-zA-Z0-9_]*
//   ExtName ::= [A-Z][a-zA-Z0-9_]*
//
// The keywords used in the above grammar are:
//   from, until, says, speaskfor, implies, or, and, not, false, true, key
// The punctuation used are:
//   '(', ')', ',', '.'
//
// All of the above elements have three distinct representations. The first
// representation is ast-like, with each element represented by an appropriate
// Go type, e.g. an int, a string, or a struct containing pointers (or
// interfaces) for child elements. This representation is meant to be easy to
// programmatically construct, split apart using type switches, rearrange,
// traverse, etc.
//
// The second representation is textual, which is convenient for humans but
// isn't canonical and can involve tricky parsing. When parsing elements from
// text, whitespace is ignored between elements, the above list shows the
// productions in order of increasing precedence for binary Form operators when
// parenthesis are omitted, parenthesis can be used for specifying precedence
// explicitly, and elements of the same precedence are parsed left to right.
// When pretty-printing elements to text, a single space is used before and
// after keywords and after commas. Elements can also be pretty-printed with
// elision, in which case keys and long strings are truncated.
//
// The third representation is an encoded sequence of bytes. This is meant to be
// compact, relatively easy to parse, and suitable for passing over sockets,
// network connections, etc. It is roughly similar to the format used by the
// encoding/binary package.
package auth
