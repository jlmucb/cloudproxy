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

// Package auth supports Tao authorization and authentication.
package auth

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"cloudproxy/util"
)

// Term represents a string, integer, or Prin value in an auth formula.
type Term struct {
	val interface {
	}
}

// Pred is a predicate or a component of a Prin.
type Pred struct {
	Name string
	Arg  []Term
}

// Prin is used to uniquely identify a principal using a series of
// predicates.
type Prin struct {
	Part []Pred
}

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

func (n Prin) String() string {
	p := make([]string, len(n.Part))
	for i, e := range n.Part {
		p[i] = e.String()
	}
	return strings.Join(p, "::")
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

func alpha(r rune) bool {
	return lower(r) || upper(r)
}

func (t *Term) Scan(state fmt.ScanState, verb rune) error {
	r, _, err := state.ReadRune()
	if err != nil {
		return util.Logged(err)
	}
	if digit(r) || r == '-' {
		token, err := state.Token(false, digit)
		if err != nil {
			return util.Logged(err)
		}
		i, err := strconv.ParseInt(string(r)+string(token), 10, 64)
		if err != nil {
			return util.Logged(err)
		}
		t.val = i
	} else if r == '"' {
		// TODO(kwalsh) This assumes the function will be called once for each rune,
		// in sequence. This seems reasonable and it is consistent with fmt/scan.go,
		// but it isn't actually specified in the pkg fmt documentation.
		escape := false
		token, err := state.Token(false, func(r rune) bool {
			if escape {
				escape = false
			} else if r == '\\' {
				escape = true
			} else if r == '"' {
				return false
			}
			return true
		})
		if err != nil {
			return util.Logged(err)
		}
		r, _, err = state.ReadRune()
		if err != nil {
			return util.Logged(err)
		}
		s, err := strconv.Unquote(`"` + string(token) + `"`)
		if err != nil {
			return util.Logged(err)
		}
		t.val = s
	} else if upper(r) {
		state.UnreadRune()
		var p Prin
		err = (&p).Scan(state, verb)
		if err != nil {
			return util.Logged(err)
		}
		t.val = &p
	} else {
		// TODO(kwalsh) maybe allow lowercase for (meta-)variables?
		return fmt.Errorf("unrecognized rune in auth.Term: %c", r)
	}
	return nil
}

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
		return alpha(r) || digit(r) || r == '_'
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

func (p *Prin) Scan(state fmt.ScanState, verb rune) error {
	var part []Pred
	var c Pred
	err := (&c).Scan(state, verb)
	if err != nil {
		return util.Logged(err)
	}
	part = append(part, c)
	for {
		r, _, err := state.ReadRune()
		if err == io.EOF {
			break
		}
		if err != nil {
			return util.Logged(err)
		}
		if r != ':' {
			err = state.UnreadRune()
			if err != nil {
				return util.Logged(err)
			}
			break
		}
		r, _, err = state.ReadRune()
		if err != nil {
			return util.Logged(err)
		}
		if r != ':' {
			return fmt.Errorf("expecting ':' in auth.Pred: %c", r)
		}
		var sub Pred
		err = (&sub).Scan(state, verb)
		if err != nil {
			return util.Logged(err)
		}
		part = append(part, sub)
	}
	p.Part = part
	return nil
}

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
