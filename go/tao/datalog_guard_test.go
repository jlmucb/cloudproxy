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

package tao

import (
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

func makeDatalogGuard() (*DatalogGuard, *Keys, string, error) {
	tmpdir, err := ioutil.TempDir("", "test_datalog_guard")
	if err != nil {
		return nil, nil, "",
			fmt.Errorf("Couldn't get a temp directory for the datalog guard test")
	}
	keys, err := NewTemporaryKeys(Signing)
	if err != nil {
		return nil, nil, "", err
	}
	g, err := NewDatalogGuardFromConfig(keys.VerifyingKey, DatalogGuardDetails{
		SignedRulesPath: proto.String(tmpdir + "/rules"),
	})
	if err != nil {
		return nil, nil, "", err
	}

	// Add a bogus rule.
	bogusOSString := `ext.PCRs("17, 18", "000, 000")`
	var prin auth.PrinTail
	fmt.Sscanf(bogusOSString, "%s", &prin)
	pred := auth.MakePredicate("BogusTPM", prin)
	if err = g.AddRule(fmt.Sprint(pred)); err != nil {
		return nil, nil, "", err
	}
	return g, keys, tmpdir, nil
}

var subj = auth.NewKeyPrin([]byte("test1"))
var subj2 = auth.NewKeyPrin([]byte("test2"))

func TestDatalogSaveReload(t *testing.T) {
	g, keys, tmpdir, err := makeDatalogGuard()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)
	err = g.Save(keys.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	err = g.ReloadIfModified()
	if err != nil {
		t.Fatal(err)
	}
	err = g.Authorize(subj, "read", []string{"somefile"})
	if err != nil {
		t.Fatal(err)
	}
	err = g.Save(keys.SigningKey)
	if err != nil {
		t.Fatal(err)
	}
	err = g.ReloadIfModified()
	if err != nil {
		t.Fatal(err)
	}
	if g.RuleCount() != 2 {
		t.Fatal("wrong number of rules")
	}
	if g.GetRule(1) != `Authorized(key([7465737431]), "read", "somefile")` {
		t.Fatalf("wrong rule: %s", g.GetRule(0))
	}
}

func TestDatalogAuthorizeRetract(t *testing.T) {
	g, _, tmpdir, err := makeDatalogGuard()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	err = g.Authorize(subj, "read", []string{"somefile"})
	if err != nil {
		t.Fatal(err)
	}

	ok := g.IsAuthorized(subj, "read", []string{"somefile"})
	if !ok {
		t.Fatal("denied, should have been authorized")
	}

	ok = g.IsAuthorized(subj, "read", []string{"otherfile"})
	if ok {
		t.Fatal("authorized, should have been denied")
	}

	err = g.Retract(subj, "read", []string{"somefile"})
	if err != nil {
		t.Fatal(err)
	}

	ok = g.IsAuthorized(subj, "read", []string{"somefile"})
	if ok {
		t.Fatal("authorized, should have been denied")
	}
}

func TestDatalogRules(t *testing.T) {
	g, _, tmpdir, err := makeDatalogGuard()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	err = g.AddRule(fmt.Sprintf(`(forall F: IsFile(F) implies Authorized(%s, "read", F))`, subj))
	if err != nil {
		t.Fatal(err)
	}

	err = g.AddRule(fmt.Sprintf(`IsFile("somefile")`))
	if err != nil {
		t.Fatal(err)
	}

	err = g.AddRule(fmt.Sprintf(`IsFile("otherfile")`))
	if err != nil {
		t.Fatal(err)
	}

	ok := g.IsAuthorized(subj, "read", []string{"somefile"})
	if !ok {
		t.Fatal("denied, should have been authorized")
	}

	ok = g.IsAuthorized(subj, "read", []string{"otherfile"})
	if !ok {
		t.Fatal("denied, should have been authorized")
	}

	ok = g.IsAuthorized(subj, "write", []string{"somefile"})
	if ok {
		t.Fatal("authorized, should have been denied")
	}

	ok = g.IsAuthorized(subj2, "read", []string{"somefile"})
	if ok {
		t.Fatal("authorized, should have been denied")
	}
}

// datalogProg contains simple test rules for authorization.
var datalogProg = []string{
	"(forall P: MemberProgram(P) implies Authorized(P, \"Execute\"))",
	"(MemberProgram(key([70])))",
}

func TestDatalogSimpleTranslation(t *testing.T) {
	g, keys, tmpdir, err := makeDatalogGuard()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	for _, s := range datalogProg {
		if err := g.AddRule(s); err != nil {
			t.Fatal("Couldn't add rule '", s, "':", err)
		}
	}

	kprin := auth.Prin{
		Type: "key",
		Key:  auth.Bytes([]byte{0x70}),
	}
	if !g.IsAuthorized(kprin, "Execute", nil) {
		t.Fatal("Simple authorization check failed")
	}

	if err := g.Save(keys.SigningKey); err != nil {
		t.Fatal("Couldn't save the guard:", err)
	}

	ok, err := g.Query("MemberProgram(key([70]))")
	if err != nil {
		t.Fatal("Couldn't query the guard:", err)
	}
	if !ok {
		t.Fatal("A simple sanity-check query failed")
	}

	ok, err = g.Query("Authorized(key([70]), \"Execute\")")
	if err != nil {
		t.Fatal("Couldn't query the guard:", err)
	}
	if !ok {
		t.Fatal("A simple authorized query didn't succeed")
	}
}

// datalogSubprinProg contains rules that use the custom primitive subprin.
var datalogSubprinProg = []string{
	"(forall Y: forall P: forall Q: TrustedOS(P) and TrustedProgramHash(Q) and Subprin(Y, P, Q) implies Authorized(Y, \"Execute\"))",
	"(TrustedOS(key([70])))",
	"(TrustedProgramHash(ext.Hash([71])))",
}

func TestDatalogSubprin(t *testing.T) {
	g, _, tmpdir, err := makeDatalogGuard()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpdir)

	for _, s := range datalogSubprinProg {
		if err := g.AddRule(s); err != nil {
			t.Fatal("Couldn't add rule '", s, "':", err)
		}
	}

	pprin := auth.Prin{
		Type: "key",
		Key:  auth.Bytes([]byte{0x70}),
		Ext: []auth.PrinExt{
			auth.PrinExt{
				Name: "Hash",
				Arg:  []auth.Term{auth.Bytes([]byte{0x71})},
			},
		},
	}
	if !g.IsAuthorized(pprin, "Execute", nil) {
		t.Fatal("Subprin authorization check failed")
	}
}

var datalogFormLengthChecks = []struct {
	query  string
	length int
}{
	{"P(key([70]).Program([71]))", 2},
	{"not P(key([70]).Program([71]))", 2},
	{"P()", 0},
	{"P() and Q(key([70]).Program([71]))", 2},
	{"P() or Q(key([70]).Program([71]))", 2},
	{"P(key([70]).Program([71])) and Q(key([70]).Program([71]))", 2},
	{"P(key([70]).Program([71]).N([72])) and Q(key([70]).Program([71]))", 3},
	{"P() implies Q(key([70]).Program([71]))", 2},
	{"tpm([70]) speaksfor key([70]).Program([71])", 2},
	{"tpm([70]).PCRs(\"17,18\", \"a4c7,b876\") says key([72]) speaksfor key([73]).A(\"B\").C()", 3},
	{"forall X: forall Y: TPM(X) and TrustedHost(Y) implies M(key([70]))", 1},
	{"exists X: P(X)", 0},
	{"exists X: P(X, key([71]).P())", 2},
}

func TestDatalogMaxFormLength(t *testing.T) {
	for _, v := range datalogFormLengthChecks {
		var form auth.AnyForm
		if fmt.Sscanf("("+v.query+")", "%v", &form); form.Form == nil {
			t.Errorf("fmt.Sscanf(%q) failed", v.query)
		}
		l := getMaxFormLength(form.Form)
		if l != v.length {
			t.Errorf("%q had length %d, want %d", v.query, l, v.length)
		}
	}
}

var datalogTermLengthChecks = []struct {
	query  string
	length int
}{
	{"5", 0},
	{"\"a string\"", 0},
	{"[716475a8e3]", 0},
	{"ext.Program([7154])", 1},
	{"ext.P().Q().R().S().T()", 5},
	{"key([70]).Program([71])", 2},
}

func TestDatalogMaxTermLength(t *testing.T) {
	for _, v := range datalogTermLengthChecks {
		var term auth.AnyTerm
		if fmt.Sscanf(v.query, "%v", &term); term.Term == nil {
			t.Errorf("fmt.Sscanf(%q) failed", v.query)
		}
		l := getMaxTermLength(term.Term)
		if l != v.length {
			t.Errorf("%q had length %d, want %d", v.query, l, v.length)
		}
	}
}

var datalogLoops = []string{
	"(forall X: forall Y: forall P: A(X) and B(Y) and Subprin(P, X, Y) implies A(P))",
	"(A(key([70])))",
	"(B(ext.Hash([71])))",
}

var datalogLoopQueries = []struct {
	query    string
	expected bool
}{
	{"A(key([70]).Hash([71]))", true},
	{"A(key([70]))", true},
	{"A(key([70]).Hash([72]))", false},
}

func TestDatalogLoop(t *testing.T) {
	g, key, tmpdir, err := makeDatalogGuard()
	if err != nil {
		t.Fatalf("makeDatalogGuard failed: %v", err)
	}
	defer os.RemoveAll(tmpdir)
	if err = g.Save(key.SigningKey); err != nil {
		t.Fatalf("Failed to save DatalogGuard: %v", err)
	}

	for _, s := range datalogLoops {
		if err := g.AddRule(s); err != nil {
			t.Fatalf("Couldn't add rule '%s': %s", s, err)
		}
	}

	for _, q := range datalogLoopQueries {
		ok, err := g.Query(q.query)
		if err != nil {
			t.Errorf("Query(%q) failed: %v", q.query, err)
		}
		if ok != q.expected {
			t.Errorf("Query(%q) = %t; want %t", q.query, ok, q.expected)
		}
	}
}

func TestDatalogSignedSubprincipal(t *testing.T) {
	g, key, tmpdir, err := makeDatalogGuard()
	if err != nil {
		t.Fatalf("makeDatalogGuard failed: %v", err)
	}
	defer os.RemoveAll(tmpdir)
	name := g.Subprincipal().String()
	k := key.SigningKey.ToPrincipal().String()
	if name != ".DatalogGuard("+k+")" {
		t.Fatalf("Datalog guard has wrong name: %v", name)
	}
}

func TestDatalogUnsignedSubprincipal(t *testing.T) {
	g := NewTemporaryDatalogGuard()
	err := g.Authorize(subj, "read", []string{"somefile"})
	if err != nil {
		t.Fatal(err)
	}
	name := g.Subprincipal().String()
	if name != ".DatalogGuard([45d9e4c235c05e6750dd18a194512ccbc99b0e6add96b6f90321113c946ec5a0])" {
		t.Fatalf("Datalog guard has wrong name: %v", name)
	}
}
