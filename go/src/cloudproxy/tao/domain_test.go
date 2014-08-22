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
)

var testDomainPassword = []byte(`insecure dummy password`)

func testNewDomain(t *testing.T) (*Domain, string) {
	tmpdir, err := ioutil.TempDir("/tmp", "acl_guard_test")
	if err != nil {
		t.Fatal("Couldn't get a temp directory for the new ACL guard:", err)
	}

	var dcfg DomainConfig
	dcfg.Domain.Name = "Test"
	dcfg.Domain.PolicyKeysPath = "keys"
	dcfg.Domain.GuardType = "ACLs"
	dcfg.SetDefaults()
	dcfg.ACLGuard = ACLGuardConfig{SignedACLsPath: path.Join(tmpdir, "acls")}
	d, err := CreateDomain(dcfg, path.Join(tmpdir, "tao.config"), testDomainPassword)
	if err != nil {
		os.RemoveAll(tmpdir)
		t.Fatal("Couldn't create a domain:", err)
	}

	return d, tmpdir
}

func TestDomainSaveAndLoad(t *testing.T) {
	d, tmpdir := testNewDomain(t)
	defer os.RemoveAll(tmpdir)

	d2, err := LoadDomain(path.Join(tmpdir, "tao.config"), testDomainPassword)
	if err != nil {
		t.Fatal("Couldn't load the domain:", err)
	}

	if !d.Subprincipal().Identical(d2.Subprincipal()) {
		t.Fatal("The subprincipal of the loaded domain was not the same as the original:", err)
	}

	if d.String() != d2.String() {
		t.Fatal("The name of the loaded domain is not the same as the original:", err)
	}
}
