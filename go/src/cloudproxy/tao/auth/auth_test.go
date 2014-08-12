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
	"testing"
)

func TestParseTerm(t *testing.T) {
	tests := []string{
		"42",
		"0",
		"-1",
		`"Hello World"`,
		`"Includes \n newlines and \t tabs"`,
		`key("foo")`,
		`key("123").Extension(1)`,
		`key("123").Extension(1).A.B(1).C(1, "Hello").D(key("456").E(key("789").G.H))`,
		`key("123").E()`,
	}

	for _, s := range tests {
		var x AnyTerm
		n, err := fmt.Sscanf(s, "%v", &x)
		if err != nil {
			t.Fatal(err.Error())
		}
		if n != 1 {
			t.Fatal("incomplete parse")
		}
		if s != `key("123").E()` && x.Term.String() != s {
			t.Fatalf("bad print: %v %v", x.Term.String(), s)
		}
	}

	s := tests[0] + " " + tests[3] + " " + tests[4] + " " + tests[6]
	var w, x, y, z AnyTerm
	n, err := fmt.Sscanf(s, "%v %v %v %v", &w, &x, &y, &z)
	if err != nil {
		t.Fatal(err.Error())
	}
	if n != 4 {
		t.Fatal("incomplete parse")
	}

	var i1, i2 Int
	n, err = fmt.Sscanf("42 -17", "%v %v", &i1, &i2)
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
	n, err = fmt.Sscanf(`key("abc").A(1).B("2", "3")`, "%v", &p)
	if err != nil {
		t.Fatal(err.Error())
	}
	p2 := Prin{Key: "abc", Ext: []PrinExt{
		PrinExt{"A", []Term{Int(1)}},
		PrinExt{"B", []Term{Str("2"), Str("#")}},
	}}
	if n != 1 || p2.Identical(p) {
		t.Fatal("incomplete parse")
	}
}

func TestParseSentence(t *testing.T) {
	var x Prin
	s := `My name is key("xxxx").Prog("foo", 1).Args("foo", "bar")`
	n, err := fmt.Sscanf(s, "My name is %v", &x)
	if err != nil {
		t.Fatal(err.Error())
	}
	if n != 1 {
		t.Fatal("incomplete parse")
	}
}

func TestParsePred(t *testing.T) {
	tests := []string{
		`P(42)`,
		`Foo`,
		`Pred(1, 2, 3)`,
		`Foo(1, "a", key("k"))`,
		`Foo()`,
	}

	for _, s := range tests {
		var x Pred
		n, err := fmt.Sscanf(s, "%v", &x)
		if err != nil {
			t.Fatal(err.Error())
		}
		if n != 1 {
			t.Fatal("incomplete parse")
		}
		if s != "Foo()" && x.String() != s {
			t.Fatalf("bad print: %v", x.String())
		}
	}

	s := tests[0] + " " + tests[1] + " " + tests[2] + " " + tests[3]
	var w, x, y, z Pred
	n, err := fmt.Sscanf(s, "%v %v %v %v", &w, &x, &y, &z)
	if err != nil {
		t.Fatal(err.Error())
	}
	if n != 4 {
		t.Fatal("incomplete parse")
	}
}

func TestParseForm(t *testing.T) {
	tests := []string{
		`key("a") says true`,
	}

	for _, s := range tests {
		var x AnyForm
		n, err := fmt.Sscanf(s, "%v", &x)
		if err != nil {
			t.Fatal(err.Error())
		}
		if n != 1 {
			t.Fatal("incomplete parse")
		}
		if x.Form.String() != s {
			t.Fatal("bad print: %v", x.Form.String())
		}
	}


}

