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
	"fmt"
	"strings"
	"testing"
)

var key []string = []string{
	`key("S2V5MQo=")`, // base64w("Key1")
	`key("S2V5Mgo=")`, // base64w("Key2")
	`tpm("S2V5Mwo=")`, // base64w("Key3")
}

var termtests []string = []string{
	"42",
	"0",
	"-1",
	`"Hello World"`,
	`"Includes \n newlines and \t tabs"`,
	key[0],
	key[1],
	key[0] + ".Extension(1)",
	key[0] + `.Extension(1).A.B(1).C(1, "Hello").D(` + key[1] + `.E(` + key[2] + `.G.H))`,
	key[0] + ".E()",
}

func TestParseTerm(t *testing.T) {
	for i, s := range termtests {
		var x AnyTerm
		n, err := fmt.Sscanf(s, "%v", &x)
		if err != nil {
			t.Fatal(err.Error())
		}
		if n != 1 {
			t.Fatal("incomplete parse")
		}
		if (i != len(termtests)-1) != (x.Term.String() == s) {
			t.Fatalf("bad print: %v vs %v", x.Term.String(), s)
		}
	}

	s := termtests[0] + " " + termtests[3] + " " + termtests[4] + " " + termtests[6]
	var w, x, y, z AnyTerm
	n, err := fmt.Sscanf(s, "%v %v %v %v", &w, &x, &y, &z)
	if err != nil {
		t.Fatal(err.Error())
	}
	if n != 4 {
		t.Fatal("incomplete parse")
	}
}

func TestBinaryTerm(t *testing.T) {
	for _, s := range termtests {
		var x AnyTerm
		fmt.Sscanf("("+s+")", "%v", &x)
		f := x.Term

		buf := Marshal(f)
		g, err := UnmarshalTerm(buf)
		if err != nil {
			t.Fatalf("can't unmarshal: %s", s)
		}
		if f.String() != g.String() {
			t.Fatalf("bad binary: %s vs %s", f.String(), g.String())
		}
	}
}

func TestScanTerm(t *testing.T) {
	var i1, i2 Int
	n, err := fmt.Sscanf("42 -17", "%v %v", &i1, &i2)
	if err != nil {
		t.Fatal(err.Error())
	}
	if n != 2 || i1 != Int(42) || i2 != Int(-17) {
		t.Fatal("incomplete parse")
	}

	var s1, s2 Str
	n, err = fmt.Sscanf(`"a" "b"`, "%v %v", &s1, &s2)
	if err != nil {
		t.Fatal(err.Error())
	}
	if n != 2 || s1 != Str("a") || s2 != Str("b") {
		t.Fatal("incomplete parse")
	}

	var p Prin
	n, err = fmt.Sscanf(key[0]+`.A(1).B("2", "3")`, "%v", &p)
	if err != nil {
		t.Fatal(err.Error())
	}
	p2 := Prin{Key: []byte("abc"), Ext: SubPrin{
		PrinExt{"A", []Term{Int(1)}},
		PrinExt{"B", []Term{Str("2"), Str("#")}},
	}}
	if n != 1 || p2.Identical(p) {
		t.Fatal("incomplete parse")
	}
}

func TestParseSentence(t *testing.T) {
	var x Prin
	s := `My name is ` + key[0] + `.Prog("foo", 1).Args("foo", "bar")`
	n, err := fmt.Sscanf(s, "My name is %v", &x)
	if err != nil {
		t.Fatal(err.Error())
	}
	if n != 1 {
		t.Fatal("incomplete parse")
	}
}

func TestParsePred(t *testing.T) {
	predtests := []string{
		`P(42)`,
		`Foo`,
		`Pred(1, 2, 3)`,
		`Foo(1, "a", ` + key[0] + `)`,
		`Foo()`,
	}

	for _, s := range predtests {
		var x Pred
		n, err := fmt.Sscanf(s, "%v", &x)
		if err != nil {
			t.Fatal(err.Error())
		}
		if n != 1 {
			t.Fatal("incomplete parse")
		}
		if s != "Foo()" && x.String() != s {
			t.Fatalf("bad print: %v vs %s", x.String(), s)
		}
	}

	s := predtests[0] + " " + predtests[1] + " " + predtests[2] + " " + predtests[3]
	var w, x, y, z Pred
	n, err := fmt.Sscanf(s, "%v %v %v %v", &w, &x, &y, &z)
	if err != nil {
		t.Fatal(err.Error())
	}
	if n != 4 {
		t.Fatal("incomplete parse")
	}
}

var formtests []string = []string{
	`true`,
	`false`,
	key[0] + ` says true`,
	key[0] + ` from 1 says true`,
	key[0] + ` until 2 says true`,
	key[0] + ` from 1 until 2 says true`,
	key[0] + ` speaksfor ` + key[2],
	key[0] + `.Sub(1).Sub(2) speaksfor ` + key[2] + `.Sub(1).Sub`,
	`P(1)`,
	`P(1) and P(2)`,
	`P(1) and P(2) and P(3) and P(4)`,
	`P(1) or P(2)`,
	`P(1) or P(2) or P(3) or P(4)`,
	`P(1) implies P(2)`,
	`P(1) implies P(2) implies P(3) or P(4)`,
	`not P(1)`,
	`not not P(1)`,
	`not not not not P(1)`,
	`P(1) and (` + key[0] + ` speaksfor ` + key[2] + `)`,
	`P(1) and P(2) and P(3) or P(4)`,
	`P(1) and P(2) and (P(3) or P(4))`,
	`P(1) and (P(2) or P(3)) and P(4)`,
	`(P(1) or P(2)) and P(3) and P(4)`,
	`P(1) and P(2) and P(3) implies P(4)`,
	`P(1) and P(2) and (P(3) implies P(4))`,
	`P(1) and (P(2) implies P(3)) and P(4)`,
	`(P(1) implies P(2)) and P(3) and P(4)`,
	`P(1) or P(2) or P(3) implies P(4)`,
	`P(1) or P(2) or (P(3) implies P(4))`,
	`P(1) or (P(2) implies P(3)) or P(4)`,
	`(P(1) implies P(2)) or P(3) or P(4)`,
	`P(1) or (` + key[0] + ` says P(2) or P(3))`,
	`P(1) or (` + key[0] + ` says P(2)) or P(3)`,
	`(((P(((1)), ("a")))))`,
}

func TestParseForm(t *testing.T) {
	for i, s := range formtests {
		var x AnyForm
		n, err := fmt.Sscanf("("+s+")", "%v", &x)
		if err != nil {
			t.Fatal(err.Error())
		}
		if n != 1 {
			t.Fatal("incomplete parse")
		}
		if i != len(formtests)-1 && x.Form.String() != s && "("+x.Form.String()+")" != s {
			t.Fatalf("bad print: %v vs %s", x.Form.String(), s)
		}

		// Try parsing with the specific type
		switch v := x.Form.(type) {
		case Says:
			n, err = fmt.Sscanf("("+s+")", "%v", &v)
			x.Form = v
		case Speaksfor:
			n, err = fmt.Sscanf("("+s+")", "%v", &v)
			x.Form = v
		case Implies:
			n, err = fmt.Sscanf("("+s+")", "%v", &v)
			x.Form = v
		case And:
			n, err = fmt.Sscanf("("+s+")", "%v", &v)
			x.Form = v
		case Or:
			n, err = fmt.Sscanf("("+s+")", "%v", &v)
			x.Form = v
		case Not:
			n, err = fmt.Sscanf("("+s+")", "%v", &v)
			x.Form = v
		case Pred:
			n, err = fmt.Sscanf("("+s+")", "%v", &v)
			x.Form = v
		case Const:
			n, err = fmt.Sscanf("("+s+")", "%v", &v)
			x.Form = v
		default:
			t.Fatalf("not reached")
		}
		if err != nil {
			t.Fatal(err.Error())
		}
		if n != 1 {
			t.Fatal("incomplete parse")
		}
		if i != len(formtests)-1 && x.Form.String() != s && "("+x.Form.String()+")" != s {
			t.Fatalf("bad print: %v vs %s", x.Form.String(), s)
		}
	}
}

func TestParseShortForm(t *testing.T) {
	for _, s := range formtests {
		var x, y AnyForm
		fmt.Sscanf("("+s+")", "%v", &x)
		if x.Form.String() != x.Form.ShortString() {
			t.Fatalf("bad short string: %s vs %s", x.Form.String(), x.Form.ShortString())
		}

		longstr := `"abcdefghijklmnopqrstuvwxyz"`
		shortstr := `"abcdefghij"...`
		short := strings.Replace(s, `"a"`, longstr, -1)
		fmt.Sscanf("("+short+")", "%v", &y)
		shortened := strings.Replace(x.Form.String(), `"a"`, shortstr, -1)
		if shortened != y.Form.ShortString() {
			t.Fatalf("bad short string: %s vs %s", y.Form.ShortString(), shortened)
		}

		if y.Form.String() != fmt.Sprintf("%v", y.Form) {
			t.Fatalf("bad long format: %s vs %s", x.Form.String(), fmt.Sprintf("%v", x.Form))
		}
		if shortened != fmt.Sprintf("%s", y.Form) {
			t.Fatalf("bad short format: %s vs %s", shortened, fmt.Sprintf("%s", x.Form))
		}

	}
}

func TestBinaryForm(t *testing.T) {
	for _, s := range formtests {
		var x AnyForm
		fmt.Sscanf("("+s+")", "%v", &x)
		f := x.Form

		buf := Marshal(f)
		g, err := UnmarshalForm(buf)
		if err != nil {
			t.Fatalf("can't unmarshal: %s", s)
		}
		if f.String() != g.String() {
			t.Fatalf("bad binary: %s vs %s", f.String(), g.String())
		}
	}
}

func TestPrinIdentical(t *testing.T) {
	p := make([]Prin, 6)
	fmt.Sscanf(key[0], "%s", &p[0])
	fmt.Sscanf(key[0]+`.Kid(1)`, "%s", &p[1])
	fmt.Sscanf(key[0]+`.Kid(1).Kid(2)`, "%s", &p[2])
	fmt.Sscanf(key[1]+`.Kid(1).Kid(2)`, "%s", &p[3])
	fmt.Sscanf(key[0]+`.Kid(2).Kid(2)`, "%s", &p[4])
	fmt.Sscanf(key[0]+`.Kid(1, 2).Kid(2)`, "%s", &p[5])

	for i, prin := range p {
		for j, other := range p {
			if (i == j) != prin.Identical(other) || (i == j) != other.Identical(prin) {
				t.Fatalf("identical failed for %v vs %v", prin, other)
			}
			if ((i <= j && j <= 2) || (i == 0 && j >= 4) || (i == j)) !=
				SubprinOrIdentical(other, prin) {
				t.Fatalf("subprin failed for %v vs %v", prin, other)
			}
		}
	}

	if p[0].Identical(Str("a")) {
		t.Fatalf("identical failed against str")
	}
}

func TestTrivialConjuncts(t *testing.T) {
	p := And{}
	if p.String() != "true" || p.ShortString() != p.String() {
		t.Fatalf("bad print for empty conjunct ")
	}
	q := Or{}
	if q.String() != "false" || q.ShortString() != q.String() {
		t.Fatalf("bad print for empty disnjunct ")
	}
	var f AnyForm
	s := "P(1, 2, 3)"
	fmt.Sscanf(s, "%v", &f)
	p = And{Conjunct: []Form{f.Form}}
	if p.String() != s || p.ShortString() != s {
		t.Fatalf("bad print for unary conjunct ")
	}
	q = Or{Disjunct: []Form{f.Form}}
	if q.String() != s || q.ShortString() != s {
		t.Fatalf("bad print for unary disnjunct ")
	}
}
