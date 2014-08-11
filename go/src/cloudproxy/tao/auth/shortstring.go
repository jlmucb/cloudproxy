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

// This file implements ShortString() functions for pretty-printing elements
// with elision.

// TODO(kwalsh) Perhaps elision can be supported under fmt.Printf() using verb
// modifiers, flags, precision, etc.?

import (
	"bytes"
	"fmt"
	"io"
)

// ShortString returns an elided pretty-printed Prin.
func (p Prin) ShortString() string {
	var out bytes.Buffer
	fmt.Fprintf(&out, "Key(%.10q...)", p.Key)
	for _, e := range p.Ext {
		fmt.Fprintf(&out, ".%s", e.ShortString())
	}
	return out.String()
}

func (e PrinExt) ShortString() string {
	return nameAndArgShortString(e.Name, e.Arg)
}

func nameAndArgShortString(name string, arg []Term) string {
	if len(arg) == 0 {
		return name
	}
	var out bytes.Buffer
	for i, a := range arg {
		if i > 0 {
			fmt.Fprintf(&out, ", ")
		}
		fmt.Fprintf(&out, "%s", a.ShortString())
	}
	return out.String()
}

// ShortString returns an elided pretty-printed Int.
func (t Int) ShortString() string {
	return fmt.Sprintf("%d", int64(t))
}

// ShortString returns an elided pretty-printed Str.
func (t Str) ShortString() string {
	if len(string(t)) > 15 {
		return fmt.Sprintf("%.10q...", string(t))
	} else {
		return fmt.Sprintf("%q", string(t))
	}
}

// ShortString returns an elided pretty-printed Pred.
func (p Pred) ShortString() string {
	return nameAndArgShortString(p.Name, p.Arg)
}

// ShortString returns an elided pretty-printed Const.
func (f Const) ShortString() string {
	if f == true {
		return "true"
	} else {
		return "False"
	}
}

// ShortString returns an elided pretty-printed Not.
func (f Not) ShortString() string {
	var out bytes.Buffer
	fmt.Fprintf(&out, "not ")
	printShortFormWithParens(&out, precedenceHigh, f.Negand)
	return out.String()
}

// ShortString returns an elided pretty-printed And.
func (f And) ShortString() string {
	if len(f.Conjunct) == 0 {
		return "true"
	} else if len(f.Conjunct) == 1 {
		return f.Conjunct[0].ShortString()
	} else {
		var out bytes.Buffer
		for i, e := range f.Conjunct {
			if i > 0 {
				fmt.Fprintf(&out, " and ")
			}
			printShortFormWithParens(&out, precedenceAnd, e)
		}
		return out.String()
	}
}

// ShortString returns an elided pretty-printed Or.
func (f Or) ShortString() string {
	if len(f.Disjunct) == 0 {
		return "false"
	} else if len(f.Disjunct) == 1 {
		return f.Disjunct[0].ShortString()
	} else {
		var out bytes.Buffer
		for i, e := range f.Disjunct {
			if i > 0 {
				fmt.Fprintf(&out, " or ")
			}
			printShortFormWithParens(&out, precedenceOr, e)
		}
		return out.String()
	}
}

// ShortString returns an elided pretty-printed Implies.
func (f Implies) ShortString() string {
	var out bytes.Buffer
	printShortFormWithParens(&out, precedenceImplies+1, f.Antecedent)
	fmt.Fprintf(&out, " implies ")
	printShortFormWithParens(&out, precedenceImplies, f.Consequent)
	return out.String()
}

// ShortString returns an elided pretty-printed Speaksfor.
func (f Speaksfor) ShortString() string {
	return fmt.Sprintf("%v speaksfor %v", f.Delegate, f.Delegator)
}

// ShortString returns an elided pretty-printed Says.
func (f Says) ShortString() string {
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

func printShortFormWithParens(out io.Writer, level int, f Form) string {
	if level > precedence(f) {
		return "(" + f.ShortString() + ")"
	}
	return f.ShortString()
}
