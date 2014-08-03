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
	"fmt"
)

// String returns a pretty-printed Prin.
func (p Prin) String() string {
	var out bytes.Buffer
	fmt.Fprintf(&out, "Key(%q)", p.Key)
	for _, e := range p.Ext {
		fmt.Fprintf(&out, ".%s", e.String())
	}
	return out.String()
}

func (e PrinExt) String() string {
	return nameAndArgString(e.Name, e.Arg)
}

func nameAndArgString(name string, arg []Term) string {
	if len(arg) == 0 {
		return name
	}
	var out bytes.Buffer
	for i, a := range arg {
		if i > 0 {
			fmt.Fprintf(&out, ", ")
		}
		fmt.Fprintf(&out, "%s", a.String())
	}
}

func (t Term) String() string {
	switch v := t.(type) {
	case Int:
		return v.String()
	case String:
		return v.String()
	case Prin:
		return v.String()
	default:
		panic("not reached")
	}
}

// String returns a pretty-printed Int.
func (t Int) String() string {
	return fmt.Sprintf("%d", t.(int64))
}

// String returns a pretty-printed String.
func (t String) String() string {
	return fmt.Sprintf("%q", t.(string))
}

// String returns a pretty-printed Form, with reasonably few parens.
func (f Form) String() string {

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
		return "False"
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
	return fmt.Sprintf("%v speaksfor %v", f.Delegate, f.Delegator)
}

// String returns a pretty-printed Says.
func (f Says) String() string {
	if f.Commences() && f.Expires() {
		return fmt.Sprintf("%v from %v until %v says %v", f.Speaker, *f.Time, *f.Expiration, f.Message)
	} else if f.Commences() {
		return fmt.Sprintf("%v from %v says %v", f.Speaker, *f.Time, f.Message)
	} else if f.Expires() {
		return fmt.Sprintf("%v until %v says %v", f.Speaker, *f.Expiration, f.Message)
	} else {
		return fmt.Sprintf("%v says %v", f.Speaker, f.Message)
	}
}

func printFormWithParens(out fmt.Writer, level int, f Form) string {
	var op int
	switch f.(type) {
	case Says:
		op = precedenceSays
	case Speaksfor:
		op = precedenceSpeaksfor
	case Implies:
		op = precedenceImplies
	case Or:
		op = precedenceOr
	case And:
		op = precedenceAnd
	case Not:
	case Pred:
	case Const:
		op = precedenceHigh
	default:
		panic("not reached")
	}
	if level > op {
		return "(" + f.String() + ")"
	}
  return f.String()
}

