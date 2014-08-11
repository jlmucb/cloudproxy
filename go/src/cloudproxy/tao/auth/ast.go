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
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"cloudproxy/util"
)

// AuthLogicElement is any element of the authorization logic, i.e. a formula, a
// term, or a principal extension.
type AuthLogicElement interface {
	Marshal() []byte
	isAuthLogicElement() // marker
}

// isAuthLogicElement ensures only appropriate types can be assigned to an
// AuthLogicElement.
func (t Prin) isAuthLogicElement() {}
func (t String) isAuthLogicElement() {}
func (t Int) isAuthLogicElement() {}
func (f Pred) isAuthLogicElement() {}
func (f Const) isAuthLogicElement() {}
func (f Not) isAuthLogicElement() {}
func (f And) isAuthLogicElement() {}
func (f Or) isAuthLogicElement() {}
func (f Implies) isAuthLogicElement() {}
func (f Speaksfor) isAuthLogicElement() {}
func (f Says) isAuthLogicElement() {}

// Prin uniquely identifies a principal by a public key, used to verify
// signatures on credentials issued by the principal, and a sequence of zero or
// more extensions to identify the subprincipal of that key.
type Prin struct {
	Key string // a base64w-encoded, marshalled, CryptoKey protobuf structure with purpose CryptoKey.VERIFYING)
	Ext []PrinExt // one or more extensions for descendents
}

// PrinExt is an extension of a principal.
type PrinExt struct {
	Name string // [A-Z][a-zA-Z0-9_]*
	Arg  []Term
}

// Term is an argument to a predicate or a principal extension.
type Term interface {
	String() string
	isTerm() // marker
}

// isTerm ensures only appropriate types can be assigned to a Term.
func (t Prin) isTerm() {}
func (t String) isTerm() {}
func (t Int) isTerm() {}

// String is a string used as a Term.
type String string

// Int is an int used as a Term.
type Int int

// Form is a formula in the Tao authorization logic.
type Form interface {
	String() string
	isForm() // marker
}

// isForm ensures only appropriate types can be assigned to a Form.
func (f Pred) isForm() {}
func (f Const) isForm() {}
func (f Not) isForm() {}
func (f And) isForm() {}
func (f Or) isForm() {}
func (f Implies) isForm() {}
func (f Speaksfor) isForm() {}
func (f Says) isForm() {}

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
	Delegate Prin
	Delegator Prin
}

// Says conveys formula "Speaker from Time until Expiration says Message"
type Says struct {
	Speaker Prin
	Time *int64 // nil to omit
	Expiration *int64 // nil to omit
	Message Form
}

// Commences checks if statement f has a commencement time.
func (f Says) Commences() bool {
	return f.Time != nil
}

// Expires checks if statement f has an expiration time.
func (f Says) Expires() bool {
	return f.Expiration != nil
}

// TODO(kwalsh) add Copy()

func (t Term) Identical(other Term) bool {
	switch t := t.val.(type) {
	case int64:
		if t2, ok := other.val.(int64); !ok || t2 != t {
			return false
		}
	case string:
		if t2, ok := other.val.(string); !ok || t2 != t {
			return false
		}
	case Prin:
		if t2, ok := other.val.(Prin); !ok || !t2.Identical(t) {
			return false
		}
	}
	return true
}

func (p Pred) Identical(other Pred) bool {
	if p.Name != other.Name {
		return false
	}
	if len(p.Arg) != len(other.Arg) {
		return false
	}
	for i := range p.Arg {
		if !p.Arg[i].Identical(&other.Arg[i]) {
			return false
		}
	}
	return true
}

func (p Prin) Identical(other Prin) bool {
	if len(p.Part) != len(other.Part) {
		return false
	}
	for i, e := range p.Part {
		if !e.Identical(&other.Part[i]) {
			return false
		}
	}
	return true
}

// SubprinOrIdentical checks whether child is a subprincipal of parent or
// identical to parent.
func SubprinOrIdentical(child, parent Prin) bool {
	if len(parent.Part) <= len(child.Part) {
		return false
	}
	for i, e := range parent.Part {
		if !e.Identical(&child.Part[i]) {
			return false
		}
	}
	return true
}

/*
func NewTerm(s string) (*Term, error) {
	var t Term
	_, err := fmt.Sscanf(s, "^%v$", &t)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func NewPred(s string) (*Pred, error) {
	var p Pred
	_, err := fmt.Sscanf(s, "^%v$", &p)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func NewPrin(s string) (*Prin, error) {
	var p Prin
	_, err := fmt.Sscanf(s, "^%v$", &p)
	if err != nil {
		return nil, err
	}
	return &p, nil
}
*/
