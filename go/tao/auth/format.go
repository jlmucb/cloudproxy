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

// This file implements Format() functions for pretty-printing elements.
// When printed with format verb %v, the "verbose" long form is used.
// When printed with format verb %s, the "short" elided form is used.
// When printed with other verbs, the output format is unspecified.

import (
	"encoding/base64"
	"fmt"
)

// ElisionCutoff is the maximum length a String or Byte can be without being elided.
var ElisionCutoff int = 32

// ElisionLength is the number of characters to show in an elided String or Byte.
var ElisionLength int = 24

// Format outputs a pretty-printed Prin.
func (p Prin) Format(out fmt.State, verb rune) {
	fmt.Fprintf(out, "%s(", p.Type)
	p.KeyHash.Format(out, verb)
	fmt.Fprint(out, ")")
	p.Ext.Format(out, verb)
}

// Format outputs a pretty-printed PrinTail.
func (p PrinTail) Format(out fmt.State, verb rune) {
	fmt.Fprintf(out, "ext")
	p.Ext.Format(out, verb)
}

// Format outputs a pretty-printed PrinExt.
func (e PrinExt) Format(out fmt.State, verb rune) {
	formatNameAndArg(out, e.Name, e.Arg, verb)
}

// formatNameAndArg outputs a pretty-printed name and argument list using short
// or long formats.
func formatNameAndArg(out fmt.State, name string, arg []Term, verb rune) {
	fmt.Fprintf(out, "%s(", name)
	for i, a := range arg {
		if i > 0 {
			fmt.Fprint(out, ", ")
		}
		a.Format(out, verb)
	}
	fmt.Fprint(out, ")")
}

// Format outputs a pretty-printed SubPrin.
func (p SubPrin) Format(out fmt.State, verb rune) {
	for _, e := range p {
		fmt.Fprint(out, ".")
		e.Format(out, verb)
	}
}

// Format outputs a pretty-printed Str.
func (t Str) Format(out fmt.State, verb rune) {
	if verb == 's' && len(string(t)) > ElisionCutoff {
		fmt.Fprintf(out, "%q...", string(t)[:ElisionLength])
	} else {
		fmt.Fprintf(out, "%q", string(t))
	}
}

// Format outputs a pretty-printed Bytes.
func (t Bytes) Format(out fmt.State, verb rune) {
	if out.Flag('#') {
		// use alternate format: base64w
		s := base64.URLEncoding.EncodeToString([]byte(t))
		if verb == 's' && len(string(t)) > ElisionCutoff {
			fmt.Fprintf(out, "{%s...}", s[:ElisionLength])
		} else {
			fmt.Fprintf(out, "{%s}", s)
		}
	} else {
		// use default format: hex
		if verb == 's' && len(string(t)) > ElisionCutoff {
			fmt.Fprintf(out, "[%02x...]", []byte(t)[:ElisionLength])
		} else {
			fmt.Fprintf(out, "[%02x]", []byte(t))
		}
	}
}

// Format outputs a pretty-printed Int.
func (t Int) Format(out fmt.State, verb rune) {
	fmt.Fprintf(out, "%d", int64(t))
}

// Format outputs a pretty-printed TermVar.
func (t TermVar) Format(out fmt.State, verb rune) {
	fmt.Fprint(out, string(t))
}

// Format outputs a pretty-printed Pred.
func (f Pred) Format(out fmt.State, verb rune) {
	formatNameAndArg(out, f.Name, f.Arg, verb)
}

// Format outputs a pretty-printed Const.
func (f Const) Format(out fmt.State, verb rune) {
	if f == true {
		fmt.Fprint(out, "true")
	} else {
		fmt.Fprint(out, "false")
	}
}

// Format outputs a pretty-printed Not.
func (f Not) Format(out fmt.State, verb rune) {
	fmt.Fprint(out, "not ")
	formatFormWithParens(out, precedenceHigh, true, f.Negand, verb)
}

// Format outputs a pretty-printed And.
func (f And) Format(out fmt.State, verb rune) {
	if len(f.Conjunct) == 0 {
		fmt.Fprint(out, "true")
	} else if len(f.Conjunct) == 1 {
		f.Conjunct[0].Format(out, verb)
	} else {
		n := len(f.Conjunct)
		for i, e := range f.Conjunct {
			if i > 0 {
				fmt.Fprint(out, " and ")
			}
			formatFormWithParens(out, precedenceAnd, i == n-1, e, verb)
		}
	}
}

// Format outputs a pretty-printed Or.
func (f Or) Format(out fmt.State, verb rune) {
	if len(f.Disjunct) == 0 {
		fmt.Fprint(out, "false")
	} else if len(f.Disjunct) == 1 {
		f.Disjunct[0].Format(out, verb)
	} else {
		n := len(f.Disjunct)
		for i, e := range f.Disjunct {
			if i > 0 {
				fmt.Fprint(out, " or ")
			}
			formatFormWithParens(out, precedenceOr, i == n-1, e, verb)
		}
	}
}

// Format outputs a pretty-printed Implies.
func (f Implies) Format(out fmt.State, verb rune) {
	formatFormWithParens(out, precedenceLow+1, false, f.Antecedent, verb)
	fmt.Fprint(out, " implies ")
	formatFormWithParens(out, precedenceLow, true, f.Consequent, verb)
}

// Format outputs a pretty-printed Speaksfor.
func (f Speaksfor) Format(out fmt.State, verb rune) {
	f.Delegate.Format(out, verb)
	fmt.Fprint(out, " speaksfor ")
	f.Delegator.Format(out, verb)
}

// Format outputs a pretty-printed Says.
func (f Says) Format(out fmt.State, verb rune) {
	f.Speaker.Format(out, verb)
	if f.Commences() {
		fmt.Fprintf(out, " from %d", *f.Time)
	}
	if f.Expires() {
		fmt.Fprintf(out, " until %d", *f.Expiration)
	}
	fmt.Fprint(out, " says ")
	f.Message.Format(out, verb)
}

// Format outputs a pretty-printed Forall.
func (f Forall) Format(out fmt.State, verb rune) {
	fmt.Fprintf(out, "forall %s: ", f.Var)
	f.Body.Format(out, verb)
}

// Format outputs a pretty-printed Exists.
func (f Exists) Format(out fmt.State, verb rune) {
	fmt.Fprintf(out, "exists %s: ", f.Var)
	f.Body.Format(out, verb)
}

const (
	precedenceLow = iota // lowest: implies, says, right speaksfor, right forall, right exists
	precedenceOr
	precedenceAnd
	precedenceHigh // not, true, false, Pred, left speaksfor, left forall, left exists
)

// precedence returns an integer indicating the relative precedence of f.
func precedence(f Form, right bool) int {
	switch f := f.(type) {
	case Says, Speaksfor, Forall, Exists, *Says, *Speaksfor, *Forall, *Exists:
		if right {
			return precedenceHigh
		}
		return precedenceLow
	case Implies, *Implies:
		return precedenceLow
	case Or:
		if len(f.Disjunct) == 0 {
			return precedenceHigh // Or{} == false
		} else if len(f.Disjunct) == 1 {
			return precedence(f.Disjunct[0], right) // Or{f} == f
		} else {
			return precedenceOr
		}
	case *Or:
		if len(f.Disjunct) == 0 {
			return precedenceHigh // Or{} == false
		} else if len(f.Disjunct) == 1 {
			return precedence(f.Disjunct[0], right) // Or{f} == f
		} else {
			return precedenceOr
		}
	case And:
		if len(f.Conjunct) == 0 {
			return precedenceHigh // And{} == true
		} else if len(f.Conjunct) == 1 {
			return precedence(f.Conjunct[0], right) // And{f} == f
		} else {
			return precedenceAnd
		}
	case *And:
		if len(f.Conjunct) == 0 {
			return precedenceHigh // And{} == true
		} else if len(f.Conjunct) == 1 {
			return precedence(f.Conjunct[0], right) // And{f} == f
		} else {
			return precedenceAnd
		}
	case Not, Pred, Const, *Not, *Pred, *Const:
		return precedenceHigh
	default:
		panic("not reached")
	}
}

// formatFormWithParens outputs either f or (f), depending on how level compares
// to the precedence of f and whether f appears on the right side of a binary
// operator.
func formatFormWithParens(out fmt.State, level int, right bool, f Form, verb rune) {
	if level > precedence(f, right) {
		fmt.Fprint(out, "(")
		f.Format(out, verb)
		fmt.Fprint(out, ")")
	} else {
		f.Format(out, verb)
	}
}
