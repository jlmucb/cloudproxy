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
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

func testNewStackedLinuxHost() (*LinuxHost, error) {
	tmpdir, err := ioutil.TempDir("/tmp", "test_new_stacked_linux_host")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpdir)

	ft, err := NewSoftTao("", nil)
	if err != nil {
		return nil, err
	}

	tg := LiberalGuard
	lh, err := NewStackedLinuxHost(tmpdir, &tg, ft, nil)
	if err != nil {
		return nil, err
	}

	return lh, nil
}

func testNewRootLinuxHost() (*LinuxHost, error) {
	tmpdir, err := ioutil.TempDir("/tmp", "test_new_root_linux_host")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmpdir)

	tg := LiberalGuard
	password := []byte("bad password")
	lh, err := NewRootLinuxHost(tmpdir, &tg, password, nil)
	if err != nil {
		return nil, err
	}

	return lh, nil
}

func TestNewStackedLinuxHost(t *testing.T) {
	if _, err := testNewStackedLinuxHost(); err != nil {
		t.Fatal(err)
	}
}

func TestNewRootLinuxHost(t *testing.T) {
	if _, err := testNewRootLinuxHost(); err != nil {
		t.Fatal(err)
	}
}

// Test the methods directly instead of testing them across a channel.

var testChildLH = &LinuxHostChild{
	channel:      nil,
	Cmd:          nil,
	ChildSubprin: []auth.PrinExt{auth.PrinExt{Name: "TestChild"}},
}

func DoTestLinuxHostHandleGetTaoName(lh *LinuxHost) error {
	if !lh.GetTaoName(testChildLH).Identical(lh.Host.HostName().MakeSubprincipal(testChildLH.ChildSubprin)) {
		return fmt.Errorf("Incorrect construction of Tao name")
	}

	return nil
}

func DoTestLinuxHostHandleGetRandomBytes(lh *LinuxHost) error {
	b, err := lh.GetRandomBytes(testChildLH, 10)
	if err != nil {
		return fmt.Errorf("Failed to get random bytes from the Linux host: %s", err)
	}

	if len(b) != 10 {
		return fmt.Errorf("Linux host returned the incorrect number of random bytes")
	}

	return nil
}

func DoTestLinuxHostHandleGetSharedSecret(lh *LinuxHost) error {
	b, err := lh.GetSharedSecret(testChildLH, 10, SharedSecretPolicyDefault)
	if err != nil {
		return fmt.Errorf("Couldn't get a shared secret from the Linux host: %s", err)
	}

	b2, err := lh.GetSharedSecret(testChildLH, 10, SharedSecretPolicyDefault)
	if err != nil {
		return fmt.Errorf("Couldn't get a second shared secret from the Linux host: %s", err)
	}

	if len(b) == 0 || !bytes.Equal(b, b2) {
		return fmt.Errorf("Invalid or inconsistent secrets returned from HandleGetSharedSecret in the Linux host")
	}

	return nil
}

func DoTestLinuxHostHandleSealUnseal(lh *LinuxHost) error {
	data := []byte{1, 2, 3, 4, 5, 6, 7}

	// `in` will be zeroed-out by LinuxHost.Seal(). Make a copy
	// to compare to the result of LinuxHost.Unseal().
	in := make([]byte, len(data))
	copy(in, data)

	b, err := lh.Seal(testChildLH, in, SharedSecretPolicyDefault)
	if err != nil {
		return fmt.Errorf("Couldn't seal the data: %s", err)
	}

	d, policy, err := lh.Unseal(testChildLH, b)
	if err != nil {
		return fmt.Errorf("Couldn't unseal the sealed data: %s", err)
	}

	if !bytes.Equal(d, data) {
		return fmt.Errorf("Incorrect unsealed data: %s", d)
	}

	if policy != SharedSecretPolicyDefault {
		return fmt.Errorf("Wrong policy returned by Unseal: %s", policy)
	}

	return nil
}

func DoTestLinuxHostHandleAttest(lh *LinuxHost) error {
	stmt := auth.Pred{Name: "FakePredicate"}

	a, err := lh.Attest(testChildLH, nil, nil, nil, stmt)
	if err != nil {
		return fmt.Errorf("Couldn't create Attestation")
	}

	if a == nil {
		return fmt.Errorf("Returned invalid Attestation from Attest")
	}

	// TODO(tmroeder): verify this attestation.
	return nil
}

func testRootLinuxHostHandleGetTaoName(t *testing.T) {
	lh, _ := testNewRootLinuxHost()
	if err := DoTestLinuxHostHandleGetTaoName(lh); err != nil {
		t.Error(err)
	}
}

func testRootLinuxHostHandleGetRandomBytes(t *testing.T) {
	lh, _ := testNewRootLinuxHost()
	if err := DoTestLinuxHostHandleGetRandomBytes(lh); err != nil {
		t.Error(err)
	}
}

func testRootLinuxHostHandleGetSharedSecret(t *testing.T) {
	lh, _ := testNewRootLinuxHost()
	if err := DoTestLinuxHostHandleGetSharedSecret(lh); err != nil {
		t.Error(err)
	}
}

func testRootLinuxHostHandleSealUnseal(t *testing.T) {
	lh, _ := testNewRootLinuxHost()
	if err := DoTestLinuxHostHandleSealUnseal(lh); err != nil {
		t.Error(err)
	}
}

func testRootLinuxHostHandleAttest(t *testing.T) {
	lh, _ := testNewRootLinuxHost()
	if err := DoTestLinuxHostHandleAttest(lh); err != nil {
		t.Error(err)
	}
}

func testStackedLinuxHostHandleGetTaoName(t *testing.T) {
	lh, _ := testNewStackedLinuxHost()
	if err := DoTestLinuxHostHandleGetTaoName(lh); err != nil {
		t.Error(err)
	}
}

func testStackedLinuxHostHandleGetRandomBytes(t *testing.T) {
	lh, _ := testNewStackedLinuxHost()
	if err := DoTestLinuxHostHandleGetRandomBytes(lh); err != nil {
		t.Error(err)
	}
}

func testStackedLinuxHostHandleGetSharedSecret(t *testing.T) {
	lh, _ := testNewStackedLinuxHost()
	if err := DoTestLinuxHostHandleGetSharedSecret(lh); err != nil {
		t.Error(err)
	}
}

func testStackedLinuxHostHandleSealUnseal(t *testing.T) {
	lh, _ := testNewStackedLinuxHost()
	if err := DoTestLinuxHostHandleSealUnseal(lh); err != nil {
		t.Error(err)
	}
}

func testStackedLinuxHostHandleAttest(t *testing.T) {
	lh, _ := testNewStackedLinuxHost()
	if err := DoTestLinuxHostHandleAttest(lh); err != nil {
		t.Error(err)
	}
}
