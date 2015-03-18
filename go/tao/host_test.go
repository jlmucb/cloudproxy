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
	"bytes"
	"testing"

	"github.com/jlmucb/cloudproxy/tao/auth"
)

var testChild = auth.SubPrin{auth.PrinExt{Name: "TestChild"}}

func testNewTaoRootHost(t *testing.T) Host {
	th, err := NewTaoRootHost()
	if err != nil {
		t.Fatal("Couldn't create a new RootHost:", err)
	}

	if err := th.AddedHostedProgram(testChild); err != nil {
		t.Fatal("Couldn't add a test child program:", err)
	}

	return th
}

func testNewTaoStackedHost(t *testing.T) Host {
	ft, err := NewSoftTao("", nil)
	if err != nil {
		t.Fatal("Couldn't set up a SoftTao for the StackedHost")
	}

	th, err := NewTaoStackedHost(ft)
	if err != nil {
		t.Fatal("Couldn't set up a StackedHost over a SoftTao")
	}

	return th
}

func testTaoHostRandomBytes(t *testing.T, th Host) {
	b, err := th.GetRandomBytes(testChild, 10)
	if err != nil {
		t.Fatal("Couldn't get random bytes from the Host:", err)
	}

	if len(b) != 10 {
		t.Fatal("The length of the returned random bytes is not 10")
	}
}

func testTaoHostSharedSecretFailure(t *testing.T, th Host) {
	tag := "test tag"
	_, err := th.GetSharedSecret(tag, 10)
	if err == nil {
		t.Fatal("A Host that doesn't support shared secrets created one")
	}
}

func testTaoHostAttest(t *testing.T, th Host) {
	a, err := th.Attest(testChild, nil, nil, nil, auth.Const(true))
	if err != nil {
		t.Fatal("Couldn't attest to a trival statement:", err)
	}

	if a == nil {
		t.Fatal("Incorrectly returned an empty attestation from a successful Attest")
	}
}

func testTaoHostEncryption(t *testing.T, th Host) {
	data := []byte{1, 2, 3, 4, 5, 6, 7}
	e, err := th.Encrypt(data)
	if err != nil {
		t.Fatal("Couldn't encrypt data")
	}

	d, err := th.Decrypt(e)
	if err != nil {
		t.Fatal("Couldn't decrypt encrypted data")
	}

	if !bytes.Equal(d, data) {
		t.Fatal("Decrypted data didn't match original data")
	}
}

func testTaoHostName(t *testing.T, th Host) {
	n := th.TaoHostName()
	if n.Key == nil {
		t.Fatal("TaoHostName returned an invalid Host name")
	}
}

func testTaoHostRemovedHostedProgram(t *testing.T, th Host) {
	if err := th.RemovedHostedProgram(testChild); err != nil {
		t.Fatal("Couldn't remove an existing hosted program")
	}
}

func TestTaoRootHostRandomBytes(t *testing.T) {
	testTaoHostRandomBytes(t, testNewTaoRootHost(t))
}

func TestTaoRootHostSharedSecretFailure(t *testing.T) {
	testTaoHostSharedSecretFailure(t, testNewTaoRootHost(t))
}

func TestTaoRootHostAttest(t *testing.T) {
	testTaoHostAttest(t, testNewTaoRootHost(t))
}

func TestTaoRootHostEncryption(t *testing.T) {
	testTaoHostEncryption(t, testNewTaoRootHost(t))
}

func TestTaoRootHostName(t *testing.T) {
	testTaoHostName(t, testNewTaoRootHost(t))
}

func TestTaoRootHostRemovedHostedProgram(t *testing.T) {
	testTaoHostRemovedHostedProgram(t, testNewTaoRootHost(t))
}

func TestTaoStackedHostRandomBytes(t *testing.T) {
	testTaoHostRandomBytes(t, testNewTaoStackedHost(t))
}

func TestTaoStackedHostSharedSecretFailure(t *testing.T) {
	testTaoHostSharedSecretFailure(t, testNewTaoStackedHost(t))
}

func TestTaoStackedHostAttest(t *testing.T) {
	testTaoHostAttest(t, testNewTaoStackedHost(t))
}

func TestTaoStackedHostEncryption(t *testing.T) {
	testTaoHostEncryption(t, testNewTaoStackedHost(t))
}

func TestTaoStackedHostName(t *testing.T) {
	testTaoHostName(t, testNewTaoStackedHost(t))
}

func TestTaoStackedHostRemovedHostedProgram(t *testing.T) {
	testTaoHostRemovedHostedProgram(t, testNewTaoStackedHost(t))
}
