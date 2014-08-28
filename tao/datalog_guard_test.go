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

	"github.com/jlmucb/cloudproxy/tao/auth"
)

func makeDatalogGuard(t *testing.T) (*DatalogGuard, *Signer, string) {
	tmpdir, err := ioutil.TempDir("/tmp", "test_datalog_guard")
	if err != nil {
		t.Fatal("Couldn't get a temp directory for the datalog guard test")
	}
	signer, err := GenerateSigner()
	if err != nil {
		t.Fatal(err.Error())
	}
	g, err := NewDatalogGuard(signer.GetVerifier(), DatalogGuardConfig{
		SignedRulesPath: tmpdir + "/signed_rules",
	})
	if err != nil {
		t.Fatal(err)
	}
	return g, signer, tmpdir
}

var subj = auth.NewKeyPrin([]byte("test1"))
var subj2 = auth.NewKeyPrin([]byte("test2"))

func TestDatalogSaveReload(t *testing.T) {
	g, key, tmpdir := makeDatalogGuard(t)
	defer os.RemoveAll(tmpdir)
	err := g.Save(key)
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
	err = g.Save(key)
	if err != nil {
		t.Fatal(err)
	}
	err = g.ReloadIfModified()
	if err != nil {
		t.Fatal(err)
	}
	if g.RuleCount() != 1 {
		t.Fatal("wrong number of rules")
	}
	if g.GetRule(0) != `Authorized(key([7465737431]), "read", "somefile")` {
		t.Fatalf("wrong rule: %s", g.GetRule(0))
	}
}

func TestDatalogAuthorizeRetract(t *testing.T) {
	g, _, tmpdir := makeDatalogGuard(t)
	defer os.RemoveAll(tmpdir)

	err := g.Authorize(subj, "read", []string{"somefile"})
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
	g, _, tmpdir := makeDatalogGuard(t)
	defer os.RemoveAll(tmpdir)

	err := g.AddRule(fmt.Sprintf(`(forall F: IsFile(F) implies Authorized(%s, "read", F))`, subj))
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
	if ok {
		t.Fatal("denied, should have been authorized")
	}

	ok = g.IsAuthorized(subj, "read", []string{"otherfile"})
	if ok {
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
