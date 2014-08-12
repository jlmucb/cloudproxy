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

// This file implements String() functions for pretty-printing elements.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
)

// String returns a pretty-printed Prin.
func (p Prin) String() string {
	var out bytes.Buffer
	fmt.Fprintf(&out, "%s(%q)", p.Type, base64.URLEncoding.EncodeToString(p.Key))
	for _, e := range p.Ext {
		fmt.Fprintf(&out, ".%s", e.String())
	}
	return out.String()
}

// String returns a pretty-printed PrinExt.
func (e PrinExt) String() string {
	return nameAndArgString(e.Name, e.Arg)
}

// nameAndArgString returns a pretty-printed name and argument list.
func nameAndArgString(name string, arg []Term) string {
	if len(arg) == 0 {
		return name
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "%s(", name)
	for i, a := range arg {
		if i > 0 {
			fmt.Fprintf(&out, ", ")
		}
		fmt.Fprintf(&out, "%s", a.String())
	}
	fmt.Fprintf(&out, ")")
	return out.String()
}

// String returns a pretty-printed Int.
func (t Int) String() string {
	return fmt.Sprintf("%d", int64(t))
}

// String returns a pretty-printed Str.
func (t Str) String() string {
	return fmt.Sprintf("%q", string(t))
}

// String returns a pretty-printed Pred.
func (p Pred) String() string {
	return nameAndArgString(p.Name, p.Arg)
}

// String returns a pretty-printed Const.
func (f Const) String() string {
	if f == true {
		return "true"
	} else {
		return "false"
	}
}

// String returns a pretty-printed Not.
func (f Not) String() string {
	var out bytes.Buffer
	fmt.Fprintf(&out, "not ")
	printFormWithParens(&out, precedenceHigh, f.Negand)
	return out.String()
}

// String returns a pretty-printed And.
func (f And) String() string {
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
			printFormWithParens(&out, precedenceAnd, e)
		}
		return out.String()
	}
}

// String returns a pretty-printed Or.
func (f Or) String() string {
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
			printFormWithParens(&out, precedenceOr, e)
		}
		return out.String()
	}
}

// String returns a pretty-printed Implies.
func (f Implies) String() string {
	var out bytes.Buffer
	printFormWithParens(&out, precedenceImplies+1, f.Antecedent)
	fmt.Fprintf(&out, " implies ")
	printFormWithParens(&out, precedenceImplies, f.Consequent)
	return out.String()
}

// String returns a pretty-printed Speaksfor.
func (f Speaksfor) String() string {
	return fmt.Sprintf("%s speaksfor %s", f.Delegate.String(), f.Delegator.String())
}

// String returns a pretty-printed Says.
func (f Says) String() string {
	speaker := f.Speaker.String()
	message := f.Message.String()
	if f.Commences() && f.Expires() {
		return fmt.Sprintf("%s from %d until %d says %s", speaker, *f.Time, *f.Expiration, message)
	} else if f.Commences() {
		return fmt.Sprintf("%s from %d says %s", speaker, *f.Time, message)
	} else if f.Expires() {
		return fmt.Sprintf("%s until %d says %s", speaker, *f.Expiration, message)
	} else {
		return fmt.Sprintf("%s says %s", speaker, message)
	}
}

const (
	precedenceSays = iota // lowest
	precedenceSpeaksfor
	precedenceImplies
	precedenceOr
	precedenceAnd
	precedenceHigh // not, true, false, Pred
)

// precedence returns an integer indicating the relative precedence of f.
func precedence(f Form) int {
	switch f := f.(type) {
	case Says:
		return precedenceSays
	case Speaksfor:
		return precedenceSpeaksfor
	case Implies:
		return precedenceImplies
	case Or:
		if len(f.Disjunct) == 0 {
			return precedenceHigh // Or{} == false
		} else if len(f.Disjunct) == 1 {
			return precedence(f.Disjunct[0]) // Or{f} == f
		} else {
			return precedenceOr
		}
	case And:
		if len(f.Conjunct) == 0 {
			return precedenceHigh // And{} == true
		} else if len(f.Conjunct) == 1 {
			return precedence(f.Conjunct[0]) // And{f} == f
		} else {
			return precedenceAnd
		}
	case Not, Pred, Const:
		return precedenceHigh
	default:
		panic("not reached")
	}
}

// printFormWithParens prints either f or (f), depending on ho level compares to
// the precedence of f.
func printFormWithParens(out io.Writer, level int, f Form) {
	if level > precedence(f) {
		fmt.Fprintf(out, "(%s)", f.String())
	} else {
		fmt.Fprintf(out, "%s", f.String())
	}
}
