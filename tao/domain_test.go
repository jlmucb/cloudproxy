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
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/tao/auth"
)

var testDomainPassword = []byte(`insecure dummy password`)
var authPrin = auth.Prin{
	Type: "key",
	Key:  auth.Bytes([]byte(`fake key`)),
}

func testNewACLDomain(t *testing.T) (*Domain, string) {
	tmpdir, err := ioutil.TempDir("/tmp", "acl_domain_test")
	if err != nil {
		t.Fatal("Couldn't get a temp directory for the new ACL guard:", err)
	}

	var dcfg DomainConfig
	dcfg.DomainInfo = &DomainDetails{
		Name:           proto.String("Test"),
		PolicyKeysPath: proto.String("keys"),
		GuardType:      proto.String("ACLs"),
	}
	dcfg.SetDefaults()
	dcfg.AclGuardInfo = &ACLGuardDetails{SignedAclsPath: proto.String(path.Join(tmpdir, "acls"))}
	d, err := CreateDomain(dcfg, path.Join(tmpdir, "tao.config"), testDomainPassword)
	if err != nil {
		os.RemoveAll(tmpdir)
		t.Fatal("Couldn't create a domain:", err)
	}

	return d, tmpdir
}

func TestDomainACLSaveAndLoad(t *testing.T) {
	d, tmpdir := testNewACLDomain(t)
	defer os.RemoveAll(tmpdir)

	d.Guard.Authorize(authPrin, "Execute", nil)
	if err := d.Save(); err != nil {
		t.Fatal("Couldn't save the ACL-based domain:", err)
	}

	d2, err := LoadDomain(path.Join(tmpdir, "tao.config"), testDomainPassword)
	if err != nil {
		t.Fatal("Couldn't load the ACL domain:", err)
	}

	if !d.Subprincipal().Identical(d2.Subprincipal()) {
		t.Fatal("The subprincipal of the loaded domain was not the same as the original")
	}

	if d.String() != d2.String() {
		t.Fatal("The name of the loaded ACL domain is not the same as the original")
	}

	if d.Guard.String() != d2.Guard.String() {
		t.Fatal("The string representation of the loaded guard didn't match the original")
	}
}

func testNewDatalogDomain(t *testing.T) (*Domain, string) {
	tmpdir, err := ioutil.TempDir("/tmp", "datalog_domain_test")
	if err != nil {
		t.Fatal("Couldn't get a temp directory for the new ACL guard:", err)
	}

	var dcfg DomainConfig
	dcfg.DomainInfo = &DomainDetails{
		Name:           proto.String("Test"),
		PolicyKeysPath: proto.String("keys"),
		GuardType:      proto.String("Datalog"),
	}
	dcfg.SetDefaults()
	dcfg.DatalogGuardInfo = &DatalogGuardDetails{SignedRulesPath: proto.String(path.Join(tmpdir, "policy_rules"))}
	d, err := CreateDomain(dcfg, path.Join(tmpdir, "tao.config"), testDomainPassword)
	if err != nil {
		os.RemoveAll(tmpdir)
		t.Fatal("Couldn't create a domain:", err)
	}

	return d, tmpdir
}

func TestDomainDatalogSaveAndLoad(t *testing.T) {
	d, tmpdir := testNewDatalogDomain(t)
	defer os.RemoveAll(tmpdir)

	if err := d.Guard.Authorize(authPrin, "Execute", nil); err != nil {
		t.Fatal("Couldn't authorize a simple key principal to Execute:", err)
	}
	if err := d.Save(); err != nil {
		t.Fatal("Couldn't save the original domain after authorization:", err)
	}

	d2, err := LoadDomain(path.Join(tmpdir, "tao.config"), testDomainPassword)
	if err != nil {
		t.Fatal("Couldn't load the datalog domain:", err)
	}

	if !d.Subprincipal().Identical(d2.Subprincipal()) {
		t.Fatal("The subprincipal of the loaded domain was not the same as the original")
	}

	if d.String() != d2.String() {
		t.Fatal("The string representation of the loaded datalog domain is not the same as the original")
	}

	if d.Guard.String() != d2.Guard.String() {
		t.Fatal("The string representation of the loaded datalog guard didn't match the original")
	}
}
