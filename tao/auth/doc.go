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
//   Form ::= Term [from Time] [until Time] says Form
//          | Term speaksfor Term
//          | forall TermVar : Form
//          | exists TermVar : Form
//          | Form implies Form
//          | Form or Form or ...
//          | Form and Form and ...
//          | not Form
//          | Pred | false | true
//
// Quantification variables range over Terms.
//  TermVar : Identifier
//
// Times are integers interpreted as 64-bit unix timestamps.
//   Time ::= int64
//
// Predicates are like boolean-valued pure functions, with a name and zero or
// more terms as arguments.
//   Pred ::= Identifier(Term, Term, ...)
//          | Identifier()
//
// Terms are concrete values, like strings, integers, or names of principals.
//   Term ::= Str | Bytes | Int | Prin | PrinTail | TermVar
//
// Int can be any Go int. Str is a double-quoted Go string. Bytes is written as
// pairs of hex digits, optionally separated by whitespace, between square
// brackets. Bytes can also be written as base64w without whitespace between
// curly braces.
//
// Principal names specify a key or a tpm, and zero or more extensions to
// specify a sub-principal of that key.
//   PrinType ::= key | tpm
//   Prin ::= PrinType(Term)
//          | PrinType(Term).PrinExt.PrinExt...
//   PrinExt ::= Identifier(Term, Term, ...)
//             | Identifier()
//
// Principal tails represent a sequence of extensions that are not rooted in a
// principal. They are used to make statements about authorized extensions
// independent of the root principal. For example, they are used to specify that
// a given program is authorized to execute on any platform. A PrinTail must be
// followed by at least one extension.
//   PrinTail ::= ext.PrinExt.PrinExt...
//
// Identifiers for predicate and principal extension names and quantification
// variables are limited to simple ascii printable identifiers, with inital
// upper-case, and no punctuation except '_':
//   PredName ::= [A-Z][a-zA-Z0-9_]*
//   ExtName ::= [A-Z][a-zA-Z0-9_]*
//
// The keywords used in the above grammar are:
//   from, until, says, speaskfor, forall, exists, implies, or, and, not, false,
//   true, key
// The punctuation used are those for strings and byte slices, plus:
//   '(', ')', ',', '.', ':'
//
// It is possible to represent nonsensical formulas, so some sanity checking may
// be called for. For example, in general:
//   1. The left operand of Says should be Prin or TermVar, as should both
//   operands of Speaksfor.
//   2. All TermVar variables should be bound.
//   3. Conjunctions should have at least one conjunct.
//   4. Disjunctions should have at least one disjunct.
//   5. Identifiers should be legal using the above rules.
//   6. The parameter for key() should be TermVar or Bytes.
// Specific applications may impose additional restrictions on the structure of
// formulas they accept.
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
// text:
//   Whitespace is ignored between elements (except around the suprincipal dot
//     operator, and before the open paren of a Pred, Prin, or, PrinExt);
//   For binary operators taking two Forms, the above list shows the productions
//     in order of increasing precedence;
//   In all other cases, operations are parsed left to right;
//   Parenthesis can be used for specifying precedence explicitly.
// When pretty-printing elements to text, a single space is used before and
// after keywords, commas, and colons. Elements can also be pretty-printed with
// elision, in which case keys and long strings are truncated.
//
// The third representation is an encoded sequence of bytes. This is meant to be
// compact, relatively easy to parse, and suitable for passing over sockets,
// network connections, etc. The encoding format is custom-designed, but is
// roughly similar to the format used by protobuf.
//
// Several alternative encodings were considered:
//
//   Protobuf encoding with protobuf definitions: This would require either
//   duplicating all Form and Term types as proto definitions, then writing
//   conversion and validation code. The encoding would likely not be space
//   efficient, and it would be essentially Tao's only hard dependency on
//   protobuf.
//
//   Protobuf encoding with hand-written encoding/decoding: The goprotobuf
//   library currently lacks good support for this. Also, protobuf allows
//   encoded data to be shuffled, making decoding much more complicated than
//   necessary.
//
//   encoding/gob: Not language-agnostic. The self-describing datatype encoding
//   scheme is probably overkill as well.
//
//   strings using textual representation of Form and Term elements: This
//   pulls into all TCB a somewhat complex lexer and parser. The encoding is
//   also not space efficient.
//
// The encoding we use instead is meant to be conceptually simple, reasonably
// space efficient, and simple to decode. And unlike most of the other schemes
// agove, strictness rather than flexibility is preferred. For example, when
// decoding a Form used for authorization, unrecognized fields should not be
// silently skipped, and unexpected types should not be silently coerced.
//
// Each element is encoded as a type tag followed by encodings for one or more
// values. The tag is encoded as a plain (i.e. not zig-zag encoded) varint, and
// it determines the meaning, number, and types of the values. Values are
// encoded according to their type:
//
//   An integer or bool is encoded as plain varint.
//
//   A string is encoded as a length (plain varint) followed by raw bytes.
//
//   A pointer is encoded the same as a boolean optionally followed by a value.
//
//   Variable-length slices (e.g. for conjuncts, disjuncts, predicate arguments)
//   are encoded as a count (plain varint) followed by the encoding for the each
//   element.
//
//   An embedded struct or interface is encoded as a tag and encoded value.
//
// Differences from protobuf:
//
//   Our tags carry implicit type information. In protobuf, the low 3 bits of
//   each tag carries an explicit type marker. That allows protobuf to skip over
//   unrecognized fields (not a design goal for us). It also means protobuf can
//   only handle 15 unique tags before overflowing to 2 byte encodings.
//
//   Our tags describe both the meaning and the type of all enclosed values, and
//   we use tags only when the meaning or type can vary (i.e. for interface
//   types). Protobuf uses tags for every enclosed value, and those tags also
//   carry type information. Protobuf is more efficient when there are many
//   optional fields. For us, nearly all fields are required.
//
//   Enclosed values in our encoding must appear in order. Protobuf values can
//   appear in any order. Protobuf encodings can concatenated, truncated, etc.,
//   all non-features for us.
//
// Note: In most cases, a tag appears only when the type would be ambiguous,
// i.e. when encoding Term or Form.
package auth
