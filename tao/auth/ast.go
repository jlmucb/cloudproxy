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

package auth

import (
	"bytes"
	"fmt"
)

// AuthLogicElement is any element of the authorization logic, i.e. a formula, a
// term, or a principal extension.
type AuthLogicElement interface {

	// Marshal writes a binary encoding of the element into b.
	Marshal(b *Buffer)

	// String returns verbose pretty-printing text for the element.
	String() string

	// ShortString returns short debug-printing text for the element.
	ShortString() string

	// fmt.Formatter is satisfied by all elements. Using format %v will result in
	// verbose pretty-printing, using format %s will result in short
	// debug-printing, and other formats will use an unspecified format.
	fmt.Formatter // Format(out fmt.State, verb rune)

	isAuthLogicElement() // marker
}

// isAuthLogicElement ensures only appropriate types can be assigned to an
// AuthLogicElement.
func (t Prin) isAuthLogicElement()      {}
func (t SubPrin) isAuthLogicElement()   {}
func (t Str) isAuthLogicElement()       {}
func (t Bytes) isAuthLogicElement()     {}
func (t Int) isAuthLogicElement()       {}
func (t TermVar) isAuthLogicElement()   {}
func (f Pred) isAuthLogicElement()      {}
func (f Const) isAuthLogicElement()     {}
func (f Not) isAuthLogicElement()       {}
func (f And) isAuthLogicElement()       {}
func (f Or) isAuthLogicElement()        {}
func (f Implies) isAuthLogicElement()   {}
func (f Speaksfor) isAuthLogicElement() {}
func (f Says) isAuthLogicElement()      {}
func (f Forall) isAuthLogicElement()    {}
func (f Exists) isAuthLogicElement()    {}

// These declarations ensure all the appropriate types can be assigned to an
// AuthLogicElement.
var _ AuthLogicElement = Prin{}
var _ AuthLogicElement = SubPrin{}
var _ AuthLogicElement = Str("")
var _ AuthLogicElement = Bytes(nil)
var _ AuthLogicElement = Int(0)
var _ AuthLogicElement = TermVar("X")
var _ AuthLogicElement = Pred{}
var _ AuthLogicElement = Const(false)
var _ AuthLogicElement = Not{}
var _ AuthLogicElement = And{}
var _ AuthLogicElement = Or{}
var _ AuthLogicElement = Implies{}
var _ AuthLogicElement = Speaksfor{}
var _ AuthLogicElement = Says{}
var _ AuthLogicElement = Forall{}
var _ AuthLogicElement = Exists{}

// These declarations ensure all the appropriate types can be assigned to a
// fmt.Scanner.
var _ fmt.Scanner = &Prin{}
var _ fmt.Scanner = &SubPrin{}
var _ fmt.Scanner = new(Str)
var _ fmt.Scanner = new(Bytes)
var _ fmt.Scanner = new(Int)
var _ fmt.Scanner = new(TermVar)
var _ fmt.Scanner = &Pred{}
var _ fmt.Scanner = new(Const)
var _ fmt.Scanner = &Not{}
var _ fmt.Scanner = &And{}
var _ fmt.Scanner = &Or{}
var _ fmt.Scanner = &Implies{}
var _ fmt.Scanner = &Speaksfor{}
var _ fmt.Scanner = &Says{}
var _ fmt.Scanner = &Forall{}
var _ fmt.Scanner = &Exists{}
var _ fmt.Scanner = &AnyForm{}
var _ fmt.Scanner = &AnyTerm{}

// Prin uniquely identifies a principal by a public key, used to verify
// signatures on credentials issued by the principal, and a sequence of zero or
// more extensions to identify the subprincipal of that key.
type Prin struct {
	Type string  // either "key" or "tpm"
	Key  Term    // TermVar or Bytes with marshalled CryptoKey protobuf structure with purpose CryptoKey.VERIFYING. Or this can be a marshalled TPM AIK, or a X.509 certificate, marshalled as ASN.1 DER.
	Ext  SubPrin // one or more extensions for descendents
}

// PrinExt is an extension of a principal.
type PrinExt struct {
	Name string // [A-Z][a-zA-Z0-9_]*
	Arg  []Term
}

// SubPrin is a series of extensions of a principal.
type SubPrin []PrinExt

// Term is an argument to a predicate or a principal extension.
type Term interface {
	AuthLogicElement
	Identical(other Term) bool
	isTerm() // marker
}

// isTerm ensures only appropriate types can be assigned to a Term.
func (t Prin) isTerm()    {}
func (t Str) isTerm()     {}
func (t Bytes) isTerm()   {}
func (t Int) isTerm()     {}
func (t TermVar) isTerm() {}

// Str is a string used as a Term.
type Str string

// Bytes is a byte slice used as a Term.
type Bytes []byte

// Int is an int used as a Term.
type Int int

// TermVar is a term-valued variable.
type TermVar string

// Form is a formula in the Tao authorization logic.
type Form interface {
	AuthLogicElement
	isForm() // marker
}

// isForm ensures only appropriate types can be assigned to a Form.
func (f Pred) isForm()      {}
func (f Const) isForm()     {}
func (f Not) isForm()       {}
func (f And) isForm()       {}
func (f Or) isForm()        {}
func (f Implies) isForm()   {}
func (f Speaksfor) isForm() {}
func (f Says) isForm()      {}
func (f Forall) isForm()    {}
func (f Exists) isForm()    {}

// Pred is a predicate, i.e. a boolean-valued (pure) function.
type Pred struct {
	Name string // [A-Z][a-zA-Z0-9_]*
	Arg  []Term
}

// Const conveys formula "true" or formula "false"
type Const bool

// Not conveys formula "not Negand"
type Not struct {
	Negand Form
}

// And conveys formula "Conjunct[0] and Conjunct[1] and ... and Conjunct[n]"
type And struct {
	Conjunct []Form
}

// Or conveys formula "Disjunct[0] or Disjunct[1] or ... or Disjunct[n]"
type Or struct {
	Disjunct []Form
}

// Implies conveys formula "Antecedent implies Consequent"
type Implies struct {
	Antecedent Form
	Consequent Form
}

// Speaksfor conveys formula "Delegate speaksfor Delegator"
type Speaksfor struct {
	Delegate  Term
	Delegator Term
}

// Says conveys formula "Speaker from Time until Expiration says Message"
type Says struct {
	Speaker    Term
	Time       *int64 // nil to omit
	Expiration *int64 // nil to omit
	Message    Form
}

// Commences checks if statement f has a commencement time.
func (f Says) Commences() bool {
	return f.Time != nil
}

// Expires checks if statement f has an expiration time.
func (f Says) Expires() bool {
	return f.Expiration != nil
}

// Forall conveys formula "(forall Var : Body)" where Var ranges over Terms.
type Forall struct {
	Var  string
	Body Form
}

// Exists conveys formula "(exists Var : Body)" where Var ranges over Terms.
type Exists struct {
	Var  string
	Body Form
}

// Identical checks if an Int is identical to another Term.
func (t Int) Identical(other Term) bool {
	return t == other
}

// Identical checks if a Str is identical to another Term.
func (t Str) Identical(other Term) bool {
	return t == other
}

// Identical checks if a Bytes is identical to another Term.
func (t Bytes) Identical(other Term) bool {
	// other must be type Bytes or *Bytes
	var b *Bytes
	if ptr, ok := other.(*Bytes); ok {
		b = ptr
	} else if val, ok := other.(Bytes); ok {
		b = &val
	} else {
		return false
	}
	return bytes.Equal([]byte(t), []byte(*b))
}

// Identical checks if a Prin is identical to another Term.
func (t Prin) Identical(other Term) bool {
	// other must be type Prin or *Prin
	var p *Prin
	if ptr, ok := other.(*Prin); ok {
		p = ptr
	} else if val, ok := other.(Prin); ok {
		p = &val
	} else {
		return false
	}
	return t.Type == p.Type && t.Key.Identical(p.Key) && t.Ext.Identical(p.Ext)
}

// Identical checks if a TermVar is identical to another Term.
func (t TermVar) Identical(other Term) bool {
	return t == other
}

// Identical checks if one PrinExt is identical to another.
func (e PrinExt) Identical(other PrinExt) bool {
	if e.Name != other.Name || len(e.Arg) != len(other.Arg) {
		return false
	}
	for i, a := range e.Arg {
		if !a.Identical(other.Arg[i]) {
			return false
		}
	}
	return true
}

// Identical checks if one SubPrin is identical to another.
func (s SubPrin) Identical(other SubPrin) bool {
	if len(s) != len(other) {
		return false
	}
	for i, e := range s {
		if !e.Identical(other[i]) {
			return false
		}
	}
	return true
}

// SubprinOrIdentical checks whether child is a subprincipal of parent or is
// identical to parent.
func SubprinOrIdentical(child, parent Term) bool {
	// Both must be type Prin or *Prin
	var c, p *Prin
	if ptr, ok := child.(*Prin); ok {
		c = ptr
	} else if val, ok := child.(Prin); ok {
		c = &val
	} else {
		return false
	}
	if ptr, ok := parent.(*Prin); ok {
		p = ptr
	} else if val, ok := parent.(Prin); ok {
		p = &val
	} else {
		return false
	}
	if p.Type != c.Type || !p.Key.Identical(c.Key) || len(p.Ext) > len(c.Ext) {
		return false
	}
	for i, a := range p.Ext {
		if !a.Identical(c.Ext[i]) {
			return false
		}
	}
	return true
}

// MakeSubprincipal creates principal p.e... given principal p and extensions e.
func (p Prin) MakeSubprincipal(e SubPrin) Prin {
	other := Prin{Type: p.Type, Key: p.Key, Ext: append([]PrinExt{}, p.Ext...)}
	other.Ext = append(other.Ext, []PrinExt(e)...)
	return other
}

// MakePredicate creates a predicate with the given name and arguments.
// Arguments can be Prin, Int (or integer types that be coerced to it), Str (or
// string), or Prin. Anything else is coerced to Str.
func MakePredicate(name string, arg ...interface{}) Pred {
	terms := make([]Term, len(arg))
	for i, a := range arg {
		switch a := a.(type) {
		case Int:
			terms[i] = a
		case Str:
			terms[i] = a
		case Bytes:
			terms[i] = a
		case Prin:
			terms[i] = a
		case *Int:
			terms[i] = a
		case *Str:
			terms[i] = a
		case *Bytes:
			terms[i] = a
		case *Prin:
			terms[i] = a
		case int:
			terms[i] = Int(a)
		case int32:
			terms[i] = Int(int(a))
		case int16:
			terms[i] = Int(int(a))
		case byte:
			terms[i] = Int(int(a))
		case string:
			terms[i] = Str(a)
		case []byte:
			terms[i] = Bytes(a)
		default:
			terms[i] = Str(fmt.Sprintf("%v", a))
		}
	}
	return Pred{name, terms}
}

// NewKeyPrin returns a new Prin of type "key" with the given key material.
func NewKeyPrin(material []byte) Prin {
	return Prin{Type: "key", Key: Bytes(material)}
}
