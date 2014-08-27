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

// This file implements Scan() functions for all elements so they can be used
// with fmt.Scanf() and friends.

import (
	"fmt"
)

// Scan parses a Prin, with optional outer parens.
func (p *Prin) Scan(state fmt.ScanState, verb rune) error {
	parser := newParser(state)
	prin, err := parser.parsePrin()
	if err != nil {
		return err
	}
	*p = prin
	return nil
}

// Scan parses a PrinExt.
func (e *PrinExt) Scan(state fmt.ScanState, verb rune) error {
	parser := newParser(state)
	name, args, err := parser.expectNameAndArgs()
	if err != nil {
		return err
	}
	e.Name = name
	e.Arg = args
	return nil
}

// Scan parses a SubPrin.
func (e *SubPrin) Scan(state fmt.ScanState, verb rune) error {
	parser := newParser(state)
	subprin, err := parser.expectSubPrin()
	if err != nil {
		return err
	}
	*e = subprin
	return nil
}

// AnyTerm is a struct that can be used in when scanning for a Term, since Term
// itself is an interface and interface pointers are not valid receivers.
// TODO(kwalsh) Can this be accomplished with a pointer to interface?
type AnyTerm struct {
	Term Term
}

// Scan parses a Term, with optional outer parens.
func (t *AnyTerm) Scan(state fmt.ScanState, verb rune) error {
	parser := newParser(state)
	term, err := parser.parseTerm()
	if err != nil {
		return err
	}
	t.Term = term
	return nil
}

// Scan parses a Str, with optional outer parens.
func (t *Str) Scan(state fmt.ScanState, verb rune) error {
	parser := newParser(state)
	s, err := parser.parseStr()
	if err != nil {
		return err
	}
	*t = s
	return nil
}

// Scan parses a Bytes, with optional outer parens.
func (t *Bytes) Scan(state fmt.ScanState, verb rune) error {
	parser := newParser(state)
	b, err := parser.parseBytes()
	if err != nil {
		return err
	}
	*t = b
	return nil
}

// Scan parses an Int, with optional outer parens.
func (t *Int) Scan(state fmt.ScanState, verb rune) error {
	parser := newParser(state)
	i, err := parser.parseInt()
	if err != nil {
		return err
	}
	*t = i
	return nil
}

// Scan parses a TermVar, with optional outer parens.
func (t *TermVar) Scan(state fmt.ScanState, verb rune) error {
	parser := newParser(state)
	v, err := parser.parseTermVar()
	if err != nil {
		return err
	}
	*t = v
	return nil
}

// AnyForm is a struct that can be used in when scanning for a Form, since Form
// itself is an interface and interface pointers are not valid receivers.
// TODO(kwalsh) Can this be accomplished with a pointer to interface?
type AnyForm struct {
	Form Form
}

// Scan parses a Form, with optional outer parens. This function is not greedy:
// it consumes only as much input as necessary to obtain a valid formula. For
// example, "(p says a and b ...)" and "p says (a and b ...) will be parsed in
// their entirety, but given "p says a and b ... ", only "p says a" will be
// parsed.
func (f *AnyForm) Scan(state fmt.ScanState, verb rune) error {
	parser := newParser(state)
	form, err := parser.parseForm(false)
	if err != nil {
		return err
	}
	f.Form = form
	return nil
}

// Scan parses a Pred, with optional outer parens.
func (f *Pred) Scan(state fmt.ScanState, verb rune) error {
	parser := newParser(state)
	pred, err := parser.parsePred()
	if err != nil {
		return err
	}
	*f = pred
	return nil
}

// Scan parses a Const, with optional outer parens. This function is not greedy.
func (f *Const) Scan(state fmt.ScanState, verb rune) error {
	parser := newParser(state)
	c, err := parser.parseConst()
	if err != nil {
		return err
	}
	*f = c
	return nil
}

// Scan parses a Not, with optional outer parens. This function is not greedy.
func (f *Not) Scan(state fmt.ScanState, verb rune) error {
	parser := newParser(state)
	form, err := parser.parseForm(false)
	if err != nil {
		return err
	}
	n, ok := form.(Not)
	if !ok {
		return fmt.Errorf(`expecting "not": %s`, form)
	}
	*f = n
	return nil
}

// Scan parses an And, with required outer parens. This function is not greedy.
func (f *And) Scan(state fmt.ScanState, verb rune) error {
	parser := newParser(state)
	form, err := parser.parseForm(false)
	if err != nil {
		return err
	}
	n, ok := form.(And)
	if ok {
		*f = n
		return nil
	}
	err = parser.expect(tokenAnd)
	if err != nil {
		return err
	}
	m, err := parser.parseForm(false)
	*f = And{Conjunct: []Form{n, m}}
	return nil
}

// Scan parses an Or, with required outer parens. This function is not greedy.
func (f *Or) Scan(state fmt.ScanState, verb rune) error {
	parser := newParser(state)
	form, err := parser.parseForm(false)
	if err != nil {
		return err
	}
	n, ok := form.(Or)
	if ok {
		*f = n
		return nil
	}
	err = parser.expect(tokenOr)
	if err != nil {
		return err
	}
	m, err := parser.parseForm(false)
	*f = Or{Disjunct: []Form{n, m}}
	return nil
}

// Scan parses an Implies, with required outer parens. This function is not
// greedy.
func (f *Implies) Scan(state fmt.ScanState, verb rune) error {
	parser := newParser(state)
	form, err := parser.parseForm(false)
	if err != nil {
		return err
	}
	n, ok := form.(Implies)
	if ok {
		*f = n
		return nil
	}
	err = parser.expect(tokenImplies)
	if err != nil {
		return err
	}
	m, err := parser.parseForm(false)
	*f = Implies{n, m}
	return nil
}

// Scan parses a Says, with optional outer parens. This function is not greedy.
func (f *Says) Scan(state fmt.ScanState, verb rune) error {
	parser := newParser(state)
	form, err := parser.parseForm(false)
	if err != nil {
		return err
	}
	n, ok := form.(Says)
	if !ok {
		return fmt.Errorf(`expecting "says": %s`, form)
	}
	*f = n
	return nil
}

// Scan parses a Speaksfor, with optional outer parens. This function is not
// greedy.
func (f *Speaksfor) Scan(state fmt.ScanState, verb rune) error {
	parser := newParser(state)
	form, err := parser.parseForm(false)
	if err != nil {
		return err
	}
	n, ok := form.(Speaksfor)
	if !ok {
		return fmt.Errorf(`expecting "speaksfor": %s`, form)
	}
	*f = n
	return nil
}

// Scan parses a Forall, with optional outer parens. This function is not greedy.
func (f *Forall) Scan(state fmt.ScanState, verb rune) error {
	parser := newParser(state)
	form, err := parser.parseForm(false)
	if err != nil {
		return err
	}
	n, ok := form.(Forall)
	if !ok {
		return fmt.Errorf(`expecting "forall": %s`, form)
	}
	*f = n
	return nil
}

// Scan parses an Exists, with optional outer parens. This function is not greedy.
func (f *Exists) Scan(state fmt.ScanState, verb rune) error {
	parser := newParser(state)
	form, err := parser.parseForm(false)
	if err != nil {
		return err
	}
	n, ok := form.(Exists)
	if !ok {
		return fmt.Errorf(`expecting "exists": %s`, form)
	}
	*f = n
	return nil
}
