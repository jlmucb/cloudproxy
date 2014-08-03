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

// Pred is a predicate, i.e. a boolean-valued (pure) function.
type Pred struct {
	Name string // [A-Z][a-zA-Z0-9_]*
	Arg  []Term
}

// Term is an argument to a predicate or a principal extension.
type Term interface {
	isTerm() // marker
}

// StringTerm is a string used as a Term.
type StringTerm string
func (t StringTerm) isTerm() {}

// IntTerm is an int used as a Term.
type IntTerm int
func (t IntTerm) isTerm() {}

// PrinTerm is a Prin used as a Term.
type PrinTerm Prin
func (t PrinTerm) isTerm() {}

// Form is a formula in the Tao authorization logic.
type Form interface {
	isForm() // marker
}

// ConstForm conveys formula "true" or formula "false"
type ConstForm bool

// NotForm conveys formula "not Negand"
type NotForm struct {
	Negand Form
}

// AndForm conveys formula "Conjunct[0] and Conjunct[1] and ... and Conjunct[n]"
type AndForm struct {
	Conjunct []Form
}

// OrForm conveys formula "Disjunct[0] or Disjunct[1] or ... or Disjunct[n]"
type OrForm struct {
	Disjunct []Form
}

// ImpliesForm conveys formula "Antecedent implies Consequent"
type ImpliesForm struct {
	Antecedent Form
	Consequent Form
}

// SpeaksforForm conveys formula "Delegate speaksfor Delegator"
type SpeaksforForm struct {
	Delegate Prin
	Delegator Prin
}

// SaysForm conveys formula "Speaker from Time until Expiration says Message"
type SaysForm struct {
	Speaker Prin
	Time Term
	Expiration Term
	Message Form
}

// ArbitraryForm is a containter that holds one formula. It is meant to be used
// as a concrete type when scanning arbitrary formulas.
type ArbitraryForm struct {
	f Form
}

// isForm is used to ensure only certain types can be assigned to a Form.
func (f *ConstForm) isForm() {}
func (f *Pred) isForm() {}
func (f *NotForm) isForm() {}
func (f *AndForm) isForm() {}
func (f *OrForm) isForm() {}
func (f *ImpliesForm) isForm() {}
func (f *SpeaksforForm) isForm() {}
func (f *SaysForm) isForm() {}

const (
	precedenceAtomic = -iota  // highest precedence
	precedenceNot
	precedenceAnd
	precedenceOr
	precedenceImplies
	precedenceSpeaksfor
	precedenceSays
)

func precedence(f Form) int {
	switch v := f.(type) {
	case *ConstForm, *Pred:
		return precedenceAtomic
	case *NotForm:
		return precedenceNot
	case *AndForm:
		if len(v.Conjunct) == 0 {
			return precedenceConst
		} else if len(v.Conjunct) == 1 {
			return precedence(v.Conjunct[0])
		}
		return precedenceAnd
	case *OrForm:
		if len(v.Disjunct) == 0 {
			return precedenceConst
		} else if len(v.Disjunct) == 1 {
			return precedence(v.Disjunct[0])
		}
		return precedenceOr
	case *ImpliesForm:
		return precedenceImplies
	case *SpeaksforForm:
		return precedenceSpeaksfor
	case *SaysForm:
		return precedenceSays
	default:
		panic("not reached")
	}
}

func (f ConstForm) String() string {
	if f == true {
		return "true"
	} else {
		return "false"
	}
}

func printWithParens(out io.Writer, contextPrecedence int, f Form) {
	if precedence(f) < contextPrecedence {
		fmt.Fprintf(out, "(%v)", f)
	} else {
		fmt.Fprintf(out, "%v", f)
	}
}

func (f *NotForm) String() string {
	var out bytes.Buffer
	fmt.Fprintf(&out, "not ")
	printWithParens(&out, precedenceNot, f.Negand)
	return out.String()
}

func (f *AndForm) String() string {
	if len(f.Conjunct) == 0 {
		return "true"
	} else if len(f.Conjunct) == 1 {
		return f.Conjunct[0].String()
	} else {
		var out bytes.Buffer
		for i, e := range f.Conjunct {
			if i > 0 {
				fmt.Fprintf(&out, " and ")
			}
			printWithParens(&out, precedenceAnd, e)
		}
		return out.String()
	}
}

func (f *OrForm) String() string {
	if len(f.Disjunct) == 0 {
		return "false"
	} else if len(f.Disjunct) == 1 {
		return f.Disjunct[0].String()
	} else {
		var out bytes.Buffer
		for i, e := range f.Disjunct {
			if i > 0 {
				fmt.Fprintf(&out, " or ")
			}
			printWithParens(&out, precedenceOr, e)
		}
		return out.String()
	}
}

func (f *ImpliesForm) String() string {
	var out bytes.Buffer
	printWithParens(&out, precedenceImplies+1, f.Antecedent)
	fmt.Fprintf(&out, " implies ")
	printWithParens(&out, precedenceImplies, f.Consequent)
	return out.String()
}

func (f *SpeaksforForm) String() string {
	return fmt.Sprintf("%v speaksfor %v", f.Delegate, f.Delegator)
}

func (f *SaysForm) Expires() bool {
	if t, ok := f.Expiration.val.(int64); ok {
		return t != 0
	}
	return true
}

func (f *SaysForm) Commences() bool {
	if t, ok := f.Time.val.(int64); ok {
		return t != 0
	}
	return true
}

func (f *SaysForm) String() string {
	if f.Commences() && f.Expires() {
		return fmt.Sprintf("%v from %v until %v says %v", f.Speaker, f.Time, f.Expiration, f.Message)
	} else if f.Commences() {
		return fmt.Sprintf("%v from %v says %v", f.Speaker, f.Time, f.Message)
	} else if f.Expires() {
		return fmt.Sprintf("%v until %v says %v", f.Speaker, f.Expiration, f.Message)
	} else {
		return fmt.Sprintf("%v says %v", f.Speaker, f.Message)
	}
}

func (f *ConstForm) Scan(state fmt.ScanState, verb rune) error {
	r, _, err := state.ReadRune()
	if err != nil {
		return util.Logged(err)
	}
	if r == 't' {
		_, err := fmt.Fscan(state, "rue")
		return err
	} else if r == 'f' {
		_, err := fmt.Fscan(state, "alse")
		return err
	} else {
		return fmt.Errorf("expecting \"true\" or \"false\" in ConstForm: %c", r)
	}
}

func (f *NotForm) Scan(state fmt.ScanState, verb rune) error {
	var negand ArbitraryForm
	_, err := fmt.Fscan(state, "not %v", &negand)
	if err != nil {
		return err
	}
	f.Negand = negand.f
	return nil
}

/*
func (f *AndForm) Scan(state fmt.ScanState, verb rune) error {
	var conjunct ArbitraryForm
	fmt.Fscan(state, "%v", &conjunct)
	return nil
}
*/

func (t Term) String() string {
	switch v := t.val.(type) {
	case int64:
		return fmt.Sprintf("%d", v)
	case string:
		return strconv.Quote(v)
	case *Prin:
		return v.String()
	default:
		panic("invalid Term type")
	}
}

func (p Pred) String() string {
	a := make([]string, len(p.Arg))
	for i, e := range p.Arg {
		a[i] = e.String()
	}
	return p.Name + "(" + strings.Join(a, ", ") + ")"
}

func (p Prin) String() string {
	a := make([]string, 1 + len(p.Ext))
	a[0] = fmt.Sprintf("Key(%q)", p.Key)
	for i, e := range p.Ext {
		a[i+1] = e.String()
	}
	return strings.Join(a, "::")
}

func ascii(r rune) bool {
	return 0 <= r && r <= 127
}

var ErrNonAscii = errors.New("encountered non-ascii rune")

func digit(r rune) bool {
	return '0' <= r && r <= '9'
}

func lower(r rune) bool {
	return 'a' <= r && r <= 'z'
}

func upper(r rune) bool {
	return 'A' <= r && r <= 'Z'
}

func scanInt64(state fmt.ScanState) (int64, error) {
	var i int64
	if _, err := fmt.Fscanf(state, "%d", &i); err != nil {
		return 0, err
	}
	return i, nil
}

func scanString(state fmt.ScanState) (string, error) {
	// For now, accept both back-quoted and double-quoted strings.
	var s string
	if _, err := fmt.Fscanf(state, "%q", &s); err != nil {
		return "", err
	}
	return s, nil
}

func skip(state fmt.ScanState, string token) error {
	for _, expected := range token {
		r, err := state.ReadRune()
		if err != nil {
			return err
		}
		if r != expected {
			return fmt.Errorf("unexpected rune: %v", r)
		}
	}
	return nil
}

func peek(state fmt.ScanState) (rune, error) {
	r, _, err := state.ReadRune()
	if err != nil {
		return util.Logged(err)
	}
	err := state.UnreadRune(r)
	if err != nil {
		return util.Logged(err)
	}
	return r, nil
}

func (p *Prin) Scan(state fmt.ScanState, verb rune) error {
	if _, err := fmt.Fscanf(state, "Key("); err != nil {
		return Prin{}, err
	}
	state.SkipSpace()
	var key string
	if _, err := fmt.Fscanf(state, "%q", &key); err != nil {
		return Prin{}, err
	}
	state.SkipSpace()
	if _, err := fmt.Fscanf(state, ")"); err != nil {
		return Prin{}, err
	}
	var ext []Pred
	for {
		if r, err := peek(state); err != nil || r != ':' {
			p.Key = key
			p.ext = ext
			return nil
		}
		var e Pred
		if _, err := fmt.Fscanf(state, "::%v", &e); err != nil {
			return err
		}
		ext = append(ext, e)
	}
}

func (t *Term) Scan(state fmt.ScanState, verb rune) error {
	r, err := peek(state)
	if err != nil {
		return err
	}
	var val interface{}
	if digit(r) || r == '-' {
		val, err = scanInt64(state)
	} else if r == '"' || r == '`' {
		val, err = scanString(state)
	} else if r == 'K' {
		var p = new(Prin)
		err = p.Scan(state, 'v')
		val = p
	} else {
		// TODO(kwalsh) Maybe allow lowercase for (meta-)variables?
		return fmt.Errorf("unexpected rune: %v", r)
	}
	if err != nil {
		return err
	}
	t.val = val
	return nil
}

/*
func (p *Pred) Scan(state fmt.ScanState, verb rune) error {
	// first char is A-Z
	r, _, err := state.ReadRune()
	if err != nil {
		return util.Logged(err)
	}
	if !upper(r) {
		return fmt.Errorf("unrecognized rune in auth.Pred: %c", r)
	}
	// rest of name is a-zA-Z0-9_
	token, err := state.Token(false, func(r rune) bool {
		return lower(r) || upper(r) || digit(r) || r == '_'
	})
	if err != nil {
		return util.Logged(err)
	}
	name := string(r) + string(token)
	r, _, err = state.ReadRune()
	if err != nil {
		return util.Logged(err)
	}
	if r != '(' {
		return fmt.Errorf("expecting '(' in auth.Pred: %c", r)
	}
	var args []Term
	for {
		state.SkipSpace()
		r, _, err = state.ReadRune()
		if err != nil {
			return util.Logged(err)
		}
		if r == ')' {
			break
		}
		if len(args) == 0 {
			err = state.UnreadRune()
			if err != nil {
				return util.Logged(err)
			}
		} else if r == ',' {
			state.SkipSpace()
		} else {
			return fmt.Errorf("expecting ')' or ',' or auth.Term in auth.Pred: %c", r)
		}
		var a Term
		err = (&a).Scan(state, verb)
		if err != nil {
			return util.Logged(err)
		}
		args = append(args, a)
	}
	p.Name = name
	p.Arg = args
	return nil
}
*/

func (t *Term) Identical(other *Term) bool {
	switch t := t.val.(type) {
	case int64:
		if t2, ok := other.val.(int64); !ok || t2 != t {
			return false
		}
	case string:
		if t2, ok := other.val.(string); !ok || t2 != t {
			return false
		}
	case *Prin:
		if t2, ok := other.val.(Prin); !ok || !t2.Identical(t) {
			return false
		}
	}
	return true
}

func (p *Pred) Identical(other *Pred) bool {
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

func (p *Prin) Identical(other *Prin) bool {
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
func SubprinOrIdentical(child, parent *Prin) bool {
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
