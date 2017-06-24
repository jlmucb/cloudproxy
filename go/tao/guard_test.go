// Copyright (c) 2014, Google Inc.  All rights reserved.
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

package tao

import (
	"testing"

	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

func testNewTrivialLiberalGuard(t *testing.T) Guard {
	tg := LiberalGuard
	if tg.Subprincipal().String() != `.TrivialGuard("Liberal")` {
		t.Fatal("Wrong subprincipal name for trivial liberal guard")
	}

	return tg
}

func testNewTrivialConservativeGuard(t *testing.T) Guard {
	tg := ConservativeGuard
	if tg.Subprincipal().String() != `.TrivialGuard("Conservative")` {
		t.Fatal("Wrong subprincipal name for trivial conservative guard")
	}

	return tg
}

var testPrin = auth.NewKeyPrin([]byte("testkey"))

func testTrivialGuardAuthorize(t *testing.T, tg Guard, expect bool) {
	if err := tg.Authorize(testPrin, "testop", []string{}); (err == nil) != expect {
		t.Fatal("Authorize command unexpected result on trivial guard")
	}
}

/*
	FIX
func testTrivialGuardRetract(t *testing.T, tg Guard, expect bool) {
	if err := tg.Retract(testPrin, "testop", []string{}); (err == nil) != expect {
		t.Fatal("Retract command unexpected result on trivial guard")
	}
}
*/

func testTrivialGuardIsAuthorized(t *testing.T, tg Guard, expect bool) {
	b := tg.IsAuthorized(testPrin, "testop", []string{})
	if b != expect {
		t.Fatal("Got an unexpected result from IsAuthorized on a trivial guard")
	}
}

func testTrivialGuardAddRule(t *testing.T, tg Guard, expect bool) {
	if err := tg.AddRule("fake rule"); (err == nil) != expect {
		t.Fatal("AddRule command unexpected result on trivial guard")
	}
}

/*
func testTrivialGuardRetractRule(t *testing.T, tg Guard, expect bool) {
	if err := tg.RetractRule("fake rule"); (err == nil) != expect {
		t.Fatal("RetractRule command unexpected result on trivial guard")
	}
}
*/

func testTrivialGuardClear(t *testing.T, tg Guard) {
	if err := tg.Clear(); err != nil {
		t.Fatal("Clear command failed on trivial guard")
	}
}

func testTrivialGuardQuery(t *testing.T, tg Guard, expect bool) {
	if res, err := tg.Query("fake query"); err != nil || res != expect {
		t.Fatal("Query command incorrectly succeeded on trivial guard")
	}
}

func testTrivialGuardRuleCount(t *testing.T, tg Guard) {
	if tg.RuleCount() != 1 {
		t.Fatal("The rule count for a trivial guard was not exactly 1")
	}
}

func testTrivialGuardGetRule(t *testing.T, tg Guard, expect string) {
	if tg.GetRule(0) != expect {
		t.Fatal("Got an unexpected rule from GetRule(0) on a trivial guard")
	}
}

func testTrivialGuardRuleDebugString(t *testing.T, tg Guard, expect string) {
	if tg.RuleDebugString(0) != expect {
		t.Fatal("Got an unexpected rule from RuleDebugString(0) on a trivial guard")
	}
}

func testTrivialGuardDebugString(t *testing.T, tg Guard, expect string) {
	if tg.String() != expect {
		t.Fatal("Got an unexpected rule from String() on a trivial guard")
	}
}

func TestTrivialLiberalGuardAuthorize(t *testing.T) {
	testTrivialGuardAuthorize(t, testNewTrivialLiberalGuard(t), true)
}

/*
	FIX
func TestTrivialLiberalGuardRetract(t *testing.T) {
	testTrivialGuardRetract(t, testNewTrivialLiberalGuard(t), false)
}
*/

func TestTrivialLiberalGuardIsAuthorized(t *testing.T) {
	testTrivialGuardIsAuthorized(t, testNewTrivialLiberalGuard(t), true)
}

/*
	FIX
func TestTrivialLiberalGuardAddRule(t *testing.T) {
	testTrivialGuardAddRule(t, testNewTrivialLiberalGuard(t), true)
}
*/

/*
	FIX
func TestTrivialLiberalGuardRetractRule(t *testing.T) {
	testTrivialGuardRetractRule(t, testNewTrivialLiberalGuard(t), false)
}

func TestTrivialLiberalGuardClear(t *testing.T) {
	testTrivialGuardClear(t, testNewTrivialLiberalGuard(t))
}

func TestTrivialLiberalGuardQuery(t *testing.T) {
	testTrivialGuardQuery(t, testNewTrivialLiberalGuard(t), true)
}

func TestTrivialLiberalGuardRuleCount(t *testing.T) {
	testTrivialGuardRuleCount(t, testNewTrivialLiberalGuard(t))
}

func TestTrivialLiberalGuardGetRule(t *testing.T) {
	testTrivialGuardGetRule(t, testNewTrivialLiberalGuard(t), "Allow All")
}

func TestTrivialLiberalGuardRuleDebugString(t *testing.T) {
	testTrivialGuardRuleDebugString(t, testNewTrivialLiberalGuard(t), "Allow All")
}

func TestTrivialLiberalGuardDebugString(t *testing.T) {
	testTrivialGuardDebugString(t, testNewTrivialLiberalGuard(t), "Trivial Liberal Policy (a.k.a. \"allow all\")")
}

func TestTrivialConservativeGuardAuthorize(t *testing.T) {
	testTrivialGuardAuthorize(t, testNewTrivialConservativeGuard(t), false)
}

func TestTrivialConservativeGuardRetract(t *testing.T) {
	testTrivialGuardRetract(t, testNewTrivialConservativeGuard(t), true)
}

func TestTrivialConservativeGuardIsAuthorized(t *testing.T) {
	testTrivialGuardIsAuthorized(t, testNewTrivialConservativeGuard(t), false)
}

func TestTrivialConservativeGuardAddRule(t *testing.T) {
	testTrivialGuardAddRule(t, testNewTrivialConservativeGuard(t), false)
}

func TestTrivialConservativeGuardRetractRule(t *testing.T) {
	testTrivialGuardRetractRule(t, testNewTrivialConservativeGuard(t), true)
}

func TestTrivialConservativeGuardClear(t *testing.T) {
	testTrivialGuardClear(t, testNewTrivialConservativeGuard(t))
}

func TestTrivialConservativeGuardQuery(t *testing.T) {
	testTrivialGuardQuery(t, testNewTrivialConservativeGuard(t), false)
}

func TestTrivialConservativeGuardRuleCount(t *testing.T) {
	testTrivialGuardRuleCount(t, testNewTrivialConservativeGuard(t))
}

func TestTrivialConservativeGuardGetRule(t *testing.T) {
	testTrivialGuardGetRule(t, testNewTrivialConservativeGuard(t), "Deny All")
}

func TestTrivialConservativeGuardRuleDebugString(t *testing.T) {
	testTrivialGuardRuleDebugString(t, testNewTrivialConservativeGuard(t), "Deny All")
}

func TestTrivialConservativeGuardDebugString(t *testing.T) {
	testTrivialGuardDebugString(t, testNewTrivialConservativeGuard(t), "Trivial Conservative Policy (a.k.a. \"deny all\")")
}
*/
