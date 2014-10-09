//  Copyright (c) 2014, Google Inc.  All rights reserved.
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
	"bytes"
	"io/ioutil"
	"os"
	"testing"

	"github.com/jlmucb/cloudproxy/tao/auth"
)

func testNewStackedLinuxHost(t *testing.T) (*LinuxHost, string) {
	tmpdir, err := ioutil.TempDir("/tmp", "test_new_stacked_linux_host")
	if err != nil {
		t.Fatal("Couldn't get a temp directory for the new stacked linux host")
	}

	ft, err := NewFakeTao(auth.NewKeyPrin([]byte("test")), "", nil)
	if err != nil {
		t.Fatal("Couldn't create a new fake Tao:", err)
	}

	tg := LiberalGuard
	lh, err := NewStackedLinuxHost(tmpdir, &tg, ft, nil)
	if err != nil {
		os.RemoveAll(tmpdir)
		t.Fatal("Couldn't create a new stacked Linux host")
	}

	return lh, tmpdir
}

func testNewRootLinuxHost(t *testing.T) (*LinuxHost, string) {
	tmpdir, err := ioutil.TempDir("/tmp", "test_new_root_linux_host")
	if err != nil {
		t.Fatal("Couldn't get a temp directory for the new root linux host")
	}

	tg := LiberalGuard
	password := []byte("bad password")
	lh, err := NewRootLinuxHost(tmpdir, &tg, password, nil)
	if err != nil {
		os.RemoveAll(tmpdir)
		t.Fatal("Couldn't create a new stacked Linux host")
	}

	return lh, tmpdir
}

func TestNewStackedLinuxHost(t *testing.T) {
	_, td := testNewStackedLinuxHost(t)
	defer os.RemoveAll(td)
}

func TestNewRootLinuxHost(t *testing.T) {
	_, td := testNewRootLinuxHost(t)
	defer os.RemoveAll(td)
}

// Test the methods directly instead of testing them across a channel.

var testChildLH = &LinuxHostChild{
	channel:      nil,
	Cmd:          nil,
	ChildSubprin: auth.SubPrin{auth.PrinExt{Name: "TestChild"}},
}

func testLinuxHostHandleGetTaoName(t *testing.T, lh *LinuxHost) {
	if !lh.GetTaoName(testChildLH).Identical(lh.taoHost.TaoHostName().MakeSubprincipal(testChildLH.ChildSubprin)) {
		t.Fatal("Incorrect construction of Tao name")
	}
}

func testLinuxHostHandleGetRandomBytes(t *testing.T, lh *LinuxHost) {
	b, err := lh.GetRandomBytes(testChildLH, 10)
	if err != nil {
		t.Fatal("Failed to get random bytes from the Linux host:", err)
	}

	if len(b) != 10 {
		t.Fatal("Linux host returned the incorrect number of random bytes")
	}
}

func testLinuxHostHandleGetSharedSecret(t *testing.T, lh *LinuxHost) {
	b, err := lh.GetSharedSecret(testChildLH, 10, SharedSecretPolicyDefault)
	if err != nil {
		t.Fatal("Couldn't get a shared secret from the Linux host:", err)
	}

	b2, err := lh.GetSharedSecret(testChildLH, 10, SharedSecretPolicyDefault)
	if err != nil {
		t.Fatal("Couldn't get a second shared secret from the Linux host:", err)
	}

	if len(b) == 0 || !bytes.Equal(b, b2) {
		t.Fatal("Invalid or inconsistent secrets returned from HandleGetSharedSecret in the Linux host")
	}
}

func testLinuxHostHandleSealUnseal(t *testing.T, lh *LinuxHost) {
	data := []byte{1, 2, 3, 4, 5, 6, 7}
	b, err := lh.Seal(testChildLH, data, SharedSecretPolicyDefault)
	if err != nil {
		t.Fatal("Couldn't seal the data:", err)
	}

	d, policy, err := lh.Unseal(testChildLH, b)
	if err != nil {
		t.Fatal("Couldn't unseal the sealed data")
	}

	if !bytes.Equal(d, data) {
		t.Fatal("Incorrect unsealed data")
	}

	if policy != SharedSecretPolicyDefault {
		t.Fatal("Wrong policy returned by Unseal")
	}
}

func testLinuxHostHandleAttest(t *testing.T, lh *LinuxHost) {
	stmt := auth.Pred{Name: "FakePredicate"}

	a, err := lh.Attest(testChildLH, nil, nil, nil, stmt)
	if err != nil {
		t.Fatal("Couldn't create Attestation")
	}

	if a == nil {
		t.Fatal("Returned invalid Attestation from Attest")
	}

	// TODO(tmroeder): verify this attestation.
}

func testRootLinuxHostHandleGetTaoName(t *testing.T) {
	lh, td := testNewRootLinuxHost(t)
	defer os.RemoveAll(td)
	testLinuxHostHandleGetTaoName(t, lh)
}

func testRootLinuxHostHandleGetRandomBytes(t *testing.T) {
	lh, td := testNewRootLinuxHost(t)
	defer os.RemoveAll(td)
	testLinuxHostHandleGetRandomBytes(t, lh)
}

func testRootLinuxHostHandleGetSharedSecret(t *testing.T) {
	lh, td := testNewRootLinuxHost(t)
	defer os.RemoveAll(td)
	testLinuxHostHandleGetSharedSecret(t, lh)
}

func testRootLinuxHostHandleSealUnseal(t *testing.T) {
	lh, td := testNewRootLinuxHost(t)
	defer os.RemoveAll(td)
	testLinuxHostHandleSealUnseal(t, lh)
}

func testRootLinuxHostHandleAttest(t *testing.T) {
	lh, td := testNewRootLinuxHost(t)
	defer os.RemoveAll(td)
	testLinuxHostHandleAttest(t, lh)
}

func testStackedLinuxHostHandleGetTaoName(t *testing.T) {
	lh, td := testNewStackedLinuxHost(t)
	defer os.RemoveAll(td)
	testLinuxHostHandleGetTaoName(t, lh)
}

func testStackedLinuxHostHandleGetRandomBytes(t *testing.T) {
	lh, td := testNewStackedLinuxHost(t)
	defer os.RemoveAll(td)
	testLinuxHostHandleGetRandomBytes(t, lh)
}

func testStackedLinuxHostHandleGetSharedSecret(t *testing.T) {
	lh, td := testNewStackedLinuxHost(t)
	defer os.RemoveAll(td)
	testLinuxHostHandleGetSharedSecret(t, lh)
}

func testStackedLinuxHostHandleSealUnseal(t *testing.T) {
	lh, td := testNewStackedLinuxHost(t)
	defer os.RemoveAll(td)
	testLinuxHostHandleSealUnseal(t, lh)
}

func testStackedLinuxHostHandleAttest(t *testing.T) {
	lh, td := testNewStackedLinuxHost(t)
	defer os.RemoveAll(td)
	testLinuxHostHandleAttest(t, lh)
}
