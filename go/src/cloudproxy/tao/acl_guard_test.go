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
	"io/ioutil"
	"os"
	"path"
	"strconv"
	"testing"

	"cloudproxy/tao/auth"
)

func testNewACLGuard(t *testing.T) (Guard, string) {
	tmpdir, err := ioutil.TempDir("/tmp", "acl_guard_test")
	if err != nil {
		t.Fatal("Couldn't get a temp directory for the new ACL guard:", err)
	}

	aclsPath := path.Join(tmpdir, "acls")
	sigPath := path.Join(tmpdir, "sig")
	config := ACLGuardConfig{
		SignedACLsPath: aclsPath,
		SignaturePath:  sigPath,
	}
	tg := NewACLGuard(config)
	return tg, tmpdir
}

func TestACLGuardSaveACLs(t *testing.T) {
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal("Couldn't generate a signer")
	}

	tg, tmpdir := testNewACLGuard(t)
	defer os.RemoveAll(tmpdir)

	p := auth.Prin{
		Type: "key",
		Key:  []byte(`Fake key`),
	}
	if err := tg.Authorize(p, "Write", []string{"filename"}); err != nil {
		t.Fatal("Couldn't authorize a simple operation:", err)
	}

	if err := tg.Save(s); err != nil {
		t.Fatal("Couldn't save the file")
	}

	aclsPath := path.Join(tmpdir, "acls")
	sigPath := path.Join(tmpdir, "sig")
	config := ACLGuardConfig{
		SignedACLsPath: aclsPath,
		SignaturePath:  sigPath,
	}

	v := s.GetVerifier()
	aclg, err := LoadACLGuard(v, config)
	if err != nil {
		t.Fatal("Couldn't load the ACLs:", err)
	}

	if aclg.RuleCount() != tg.RuleCount() {
		t.Fatal("Wrong number of rules in loaded ACLGuard")
	}

	if aclg.String() != tg.String() {
		t.Fatal("Wrong string representation of loaded ACLGuard")
	}
}

func TestACLGuardAuthorize(t *testing.T) {
	tg, tmpdir := testNewACLGuard(t)
	defer os.RemoveAll(tmpdir)

	p := auth.Prin{
		Type: "key",
		Key:  []byte(`Fake key`),
	}
	if err := tg.Authorize(p, "Write", []string{"filename"}); err != nil {
		t.Fatal("Couldn't authorize a simple operation:", err)
	}

	if !tg.IsAuthorized(p, "Write", []string{"filename"}) {
		t.Fatal("A rule that was added to the ACL was not present")
	}

	if tg.IsAuthorized(p, "Write", []string{"file"}) {
		t.Fatal("A rule was authorized even though it has the wrong file name")
	}

	if tg.IsAuthorized(p, "Read", []string{"filename"}) {
		t.Fatal("A rule was authorized even though it has the wrong op")
	}

	if tg.IsAuthorized(auth.Prin{}, "Write", []string{"filename"}) {
		t.Fatal("A rule was authorized even though it has the wrong principal")
	}

	if err := tg.Retract(p, "Write", []string{"filename"}); err != nil {
		t.Fatal("Couldn't retract an existing rule:", err)
	}

	if tg.IsAuthorized(p, "Write", []string{"filename"}) {
		t.Fatal("A rule was still authorized after it was retracted")
	}
}

func TestACLGuardDoubleAuthorize(t *testing.T) {
	tg, tmpdir := testNewACLGuard(t)
	defer os.RemoveAll(tmpdir)

	p := auth.Prin{
		Type: "key",
		Key:  []byte(`Fake key`),
	}
	if err := tg.Authorize(p, "Write", []string{"filename"}); err != nil {
		t.Fatal("Couldn't authorize a simple operation:", err)
	}

	// So nice, we authorize it twice.
	if err := tg.Authorize(p, "Write", []string{"filename"}); err != nil {
		t.Fatal("Couldn't authorize a simple operation:", err)
	}

	if !tg.IsAuthorized(p, "Write", []string{"filename"}) {
		t.Fatal("A rule that was added to the ACL was not present")
	}

	if err := tg.Retract(p, "Write", []string{"filename"}); err != nil {
		t.Fatal("Couldn't retract an existing double-added rule:", err)
	}

	if tg.IsAuthorized(p, "Write", []string{"filename"}) {
		t.Fatal("A rule was still authorized after it was retracted")
	}
}

func TestACLGuardAddRule(t *testing.T) {
	tg, tmpdir := testNewACLGuard(t)
	defer os.RemoveAll(tmpdir)

	if err := tg.AddRule("Fake rule"); err != nil {
		t.Fatal("Couldn't add a fake rule to the ACL")
	}

	ret, err := tg.Query("Fake rule")
	if err != nil {
		t.Fatal("Couldn't query a fake rule from the ACLGuard:", err)
	}

	if !ret {
		t.Fatal("ACLGuard.Query did not return true for a rule that was added by AddRule")
	}

	if err := tg.Clear(); err != nil {
		t.Fatal("Couldn't clear the ACLGuard:", err)
	}

	ret, err = tg.Query("Fake rule")
	if err != nil {
		t.Fatal("Couldn't query a fake rule after clearing the ACLGuard:", err)
	}

	if ret {
		t.Fatal("ACLGuard.Query returned true for a rule after clearing the ACLGuard")
	}
}

func TestACLGuardRetractRule(t *testing.T) {
	tg, tmpdir := testNewACLGuard(t)
	defer os.RemoveAll(tmpdir)

	if err := tg.AddRule("Fake rule"); err != nil {
		t.Fatal("Couldn't add a fake rule to the ACL")
	}

	ret, err := tg.Query("Fake rule")
	if err != nil {
		t.Fatal("Couldn't query a fake rule from the ACLGuard:", err)
	}

	if !ret {
		t.Fatal("ACLGuard.Query did not return true for a rule that was added by AddRule")
	}

	if err := tg.RetractRule("Fake rule"); err != nil {
		t.Fatal("Couldn't clear the ACLGuard:", err)
	}

	ret, err = tg.Query("Fake rule")
	if err != nil {
		t.Fatal("Couldn't query a fake rule after clearing the ACLGuard:", err)
	}

	if ret {
		t.Fatal("ACLGuard.Query returned true for a rule after retracting the rule")
	}
}

func TestACLGuardRuleCount(t *testing.T) {
	tg, tmpdir := testNewACLGuard(t)
	defer os.RemoveAll(tmpdir)

	count := 20
	for i := 0; i < count; i++ {
		if err := tg.AddRule(strconv.Itoa(i)); err != nil {
			t.Fatal("Couldn't add a rule that was a single integer as a string:", err)
		}
	}

	if tg.RuleCount() != count {
		t.Fatal("Wrong rule count after adding 20 rules")
	}

	// add the same rule again and make sure the RuleCount goes up.
	if err := tg.AddRule("0"); err != nil {
		t.Fatal("Couldn't add the same rule twice to the list:", err)
	}

	if tg.RuleCount() != count+1 {
		t.Fatal("Wrong rule count after adding a rule twice")
	}

	if err := tg.RetractRule("0"); err != nil {
		t.Fatal("Couldn't retract a rule that had been added twice:", err)
	}

	if tg.RuleCount() != count-1 {
		t.Fatal("Wrong rule count after removing a rule that had been added twice")
	}
}

func TestACLGuardGetRule(t *testing.T) {
	tg, tmpdir := testNewACLGuard(t)
	defer os.RemoveAll(tmpdir)

	count := 20
	for i := 0; i < count; i++ {
		if err := tg.AddRule(strconv.Itoa(i)); err != nil {
			t.Fatal("Couldn't add a rule that was a single integer as a string:", err)
		}
	}

	if tg.GetRule(0) != "0" {
		t.Fatal("Got the wrong rule from GetRule")
	}

	if tg.GetRule(200) != "" {
		t.Fatal("Got a non-empty rule string for a non-existent rule")
	}

	if tg.GetRule(-1) != "" {
		t.Fatal("Got a non-empty rule string for a negative rule index")
	}
}

func TestACLGuardRuleDebugString(t *testing.T) {
	tg, tmpdir := testNewACLGuard(t)
	defer os.RemoveAll(tmpdir)

	count := 20
	for i := 0; i < count; i++ {
		if err := tg.AddRule(strconv.Itoa(i)); err != nil {
			t.Fatal("Couldn't add a rule that was a single integer as a string:", err)
		}
	}

	if tg.RuleDebugString(0) != "0" {
		t.Fatal("Got the wrong rule from GetRule")
	}

	if tg.RuleDebugString(200) != "" {
		t.Fatal("Got a non-empty rule string for a non-existent rule")
	}

	if tg.RuleDebugString(-1) != "" {
		t.Fatal("Got a non-empty rule string for a negative rule index")
	}
}

func TestACLGuardString(t *testing.T) {
	tg, tmpdir := testNewACLGuard(t)
	defer os.RemoveAll(tmpdir)

	if err := tg.AddRule("0"); err != nil {
		t.Fatal("Couldn't add a rule that was a single integer as a string:", err)
	}

	s := "ACLGuard{\n0\n}"
	if tg.String() != s {
		t.Fatal("Got the wrong string representation of the ACLGuard")
	}
}
