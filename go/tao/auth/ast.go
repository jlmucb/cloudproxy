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
	"crypto/sha256"
	"fmt"
)

// LogicElement is any element of the authorization logic, i.e. a formula, a
// term, or a principal extension.
type LogicElement interface {

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

	isLogicElement() // marker
}

// isLogicElement ensures only appropriate types can be assigned to an
// LogicElement.
func (t Prin) isLogicElement()      {}
func (t PrinTail) isLogicElement()  {}
func (t SubPrin) isLogicElement()   {}
func (t Str) isLogicElement()       {}
func (t Bytes) isLogicElement()     {}
func (t Int) isLogicElement()       {}
func (t TermVar) isLogicElement()   {}
func (f Pred) isLogicElement()      {}
func (f Const) isLogicElement()     {}
func (f Not) isLogicElement()       {}
func (f And) isLogicElement()       {}
func (f Or) isLogicElement()        {}
func (f Implies) isLogicElement()   {}
func (f Speaksfor) isLogicElement() {}
func (f Says) isLogicElement()      {}
func (f Forall) isLogicElement()    {}
func (f Exists) isLogicElement()    {}

// These declarations ensure all the appropriate types can be assigned to an
// LogicElement.
var _ LogicElement = Prin{}
var _ LogicElement = PrinTail{}
var _ LogicElement = SubPrin{}
var _ LogicElement = Str("")
var _ LogicElement = Bytes(nil)
var _ LogicElement = Int(0)
var _ LogicElement = TermVar("X")
var _ LogicElement = Pred{}
var _ LogicElement = Const(false)
var _ LogicElement = Not{}
var _ LogicElement = And{}
var _ LogicElement = Or{}
var _ LogicElement = Implies{}
var _ LogicElement = Speaksfor{}
var _ LogicElement = Says{}
var _ LogicElement = Forall{}
var _ LogicElement = Exists{}

// These declarations ensure all the appropriate types can be assigned to a
// fmt.Scanner.
var _ fmt.Scanner = &Prin{}
var _ fmt.Scanner = &PrinTail{}
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
	Type    string  // The keyword of a principal token, e.g. "key" or "tpm".
	KeyHash Term    // TermVar or Bytes with hashed CryptoKey protobuf structure with purpose CryptoKey.VERIFYING. Or this can be a hashed marshalled TPM AIK, or a X.509 certificate, marshalled as ASN.1 DER then hashed.
	Ext     SubPrin // zero or more extensions for descendents
}

// PrinExt is an extension of a principal.
type PrinExt struct {
	Name string // [A-Z][a-zA-Z0-9_]*
	Arg  []Term
}

// SubPrin is a series of extensions of a principal.
type SubPrin []PrinExt

// A PrinTail is a Term that represents a free-floating sequence of PrinExt
// values. It represents the tail of a list of Prin extensions. Its textual
// representation always starts with the keyword "ext".
type PrinTail struct {
	Ext SubPrin // one or more extensions
}

// Term is an argument to a predicate or a principal extension.
type Term interface {
	LogicElement
	Identical(other Term) bool
	isTerm() // marker
}

// isTerm ensures only appropriate types can be assigned to a Term.
func (t Prin) isTerm()     {}
func (t PrinTail) isTerm() {}
func (t Str) isTerm()      {}
func (t Bytes) isTerm()    {}
func (t Int) isTerm()      {}
func (t TermVar) isTerm()  {}

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
	LogicElement
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
	return t.Type == p.Type && t.KeyHash.Identical(p.KeyHash) && t.Ext.Identical(p.Ext)
}

// Identical checks if a PrinTail is identical to another Term.
func (t PrinTail) Identical(other Term) bool {
	// other must be type PrinTail or *PrinTail
	var p *PrinTail
	if ptr, ok := other.(*PrinTail); ok {
		p = ptr
	} else if val, ok := other.(PrinTail); ok {
		p = &val
	} else {
		return false
	}
	return t.Ext.Identical(p.Ext)
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
func (t SubPrin) Identical(other SubPrin) bool {
	if len(t) != len(other) {
		return false
	}
	for i, e := range t {
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
	if p.Type != c.Type || !p.KeyHash.Identical(c.KeyHash) || len(p.Ext) > len(c.Ext) {
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
func (t Prin) MakeSubprincipal(e SubPrin) Prin {
	other := Prin{Type: t.Type, KeyHash: t.KeyHash, Ext: append([]PrinExt{}, t.Ext...)}
	other.Ext = append(other.Ext, []PrinExt(e)...)
	return other
}

// MakePredicate creates a predicate with the given name and arguments.
// Arguments can be Prin, Int (or integer types that be coerced to it), Str (or
// string), or PrinTail. Anything else is coerced to Str.
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
		case PrinTail:
			terms[i] = a
		case *Int:
			terms[i] = a
		case *Str:
			terms[i] = a
		case *Bytes:
			terms[i] = a
		case *Prin:
			terms[i] = a
		case *PrinTail:
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

// NewPrin returns a new Prin with the given key type and material.
func NewPrin(keytype string, material []byte) Prin {
	// TODO: This might depend on the CryptoSuite.
	// by calling MakeUniversalKeyNameFromCanonicalBytes in keys.go.
	// this causes an import cycle now.
	hash := sha256.Sum256(material)
	return Prin{Type: keytype, KeyHash: Bytes(hash[:])}
}

// NewKeyPrin returns a new Prin of type "key" with the given key material.
func NewKeyPrin(material []byte) Prin {
	return NewPrin("key", material)
}

// NewTpmPrin returns a new Prin of type "tpm" with the given (aik) key material.
func NewTPMPrin(material []byte) Prin {
	return NewPrin("tpm", material)
}

// NewTpm2Prin returns a new Prin of type "tpm2" with the given (ek) key material.
func NewTPM2Prin(material []byte) Prin {
	return NewPrin("tpm2", material)
}
