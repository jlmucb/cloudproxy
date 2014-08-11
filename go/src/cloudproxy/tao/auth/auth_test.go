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
	var x, y, z AnyTerm
	n, err := fmt.Sscanf(`42 "Hello World" key("foo")::Bar(3, "Hello", key("Baz")::Boo())`, "%v %v %v", &x, &y, &z)
	if err != nil {
		t.Fatal(err.Error())
	}
	if n != 3 {
		t.Fatal("incomplete parse")
	}
}

func TestParsePred(t *testing.T) {
	var x Pred
	n, err := fmt.Sscanf(`Foo( "a", 1 )::Bar( )`, "%v", &x)
	if err != nil {
		t.Fatal(err.Error())
	}
	if n != 1 {
		t.Fatal("incomplete parse")
	}
}

func TestParsePrin(t *testing.T) {
	var x Prin
	s := `My name is Key("xxxx")::Prog("foo", 1)::Args("foo", "bar").`
	n, err := fmt.Sscanf(s, "My name is %v.", &x)
	if err != nil {
		t.Fatal(err.Error())
	}
	if n != 1 {
		t.Fatal("incomplete parse")
	}
}
