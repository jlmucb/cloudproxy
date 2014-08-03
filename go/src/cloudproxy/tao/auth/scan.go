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
	case Const, Pred:
		return precedenceAtomic
	case Not:
		return precedenceNot
	case And:
		if len(v.Conjunct) == 0 {
			return precedenceConst
		} else if len(v.Conjunct) == 1 {
			return precedence(v.Conjunct[0])
		}
		return precedenceAnd
	case Or:
		if len(v.Disjunct) == 0 {
			return precedenceConst
		} else if len(v.Disjunct) == 1 {
			return precedence(v.Disjunct[0])
		}
		return precedenceOr
	case Implies:
		return precedenceImplies
	case Speaksfor:
		return precedenceSpeaksfor
	case Says:
		return precedenceSays
	default:
		panic("not reached")
	}
}

func printWithParens(out io.Writer, contextPrecedence int, f Form) {
	if precedence(f) < contextPrecedence {
		fmt.Fprintf(out, "(%v)", f)
	} else {
		fmt.Fprintf(out, "%v", f)
	}
}

func (f *Const) Scan(state fmt.ScanState, verb rune) error {
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
		return fmt.Errorf("expecting \"true\" or \"false\" in Const: %c", r)
	}
}

func (f *Not) Scan(state fmt.ScanState, verb rune) error {
	var negand Arbitrary
	_, err := fmt.Fscan(state, "not %v", &negand)
	if err != nil {
		return err
	}
	f.Negand = negand.f
	return nil
}

/*
func (f *And) Scan(state fmt.ScanState, verb rune) error {
	var conjunct Arbitrary
	fmt.Fscan(state, "%v", &conjunct)
	return nil
}
*/


func (t *String) Scan(state fmt.ScanState, verb rune) error {
	var s string
	if _, err := fmt.Fscanf(state, "%q", &s); err != nil {
		return err
	}
	*t = s
	return nil
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
