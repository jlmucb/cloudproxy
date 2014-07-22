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
)

var testChild string = "test child"

func testNewTaoRootHost(t *testing.T) TaoHost {
	th, err := NewTaoRootHost()
	if err != nil {
		t.Fatal("Couldn't create a new TaoRootHost:", err)
	}

	if err := th.AddedHostedProgram(testChild); err != nil {
		t.Fatal("Couldn't add a test child program:", err)
	}

	return th
}

func testNewTaoStackedHost(t *testing.T) TaoHost {
	ft, err := NewFakeTao("test tao", "", nil)
	if err != nil {
		t.Fatal("Couldn't set up a FakeTao for the TaoStackedHost")
	}

	th, err := NewTaoStackedHost(ft)
	if err != nil {
		t.Fatal("Couldn't set up a TaoStackedHost over a FakeTao")
	}

	return th
}

func testTaoHostRandomBytes(t *testing.T, th TaoHost) {
	b, err := th.GetRandomBytes(testChild, 10)
	if err != nil {
		t.Fatal("Couldn't get random bytes from the TaoHost:", err)
	}

	if len(b) != 10 {
		t.Fatal("The length of the returned random bytes is not 10")
	}
}

func testTaoHostSharedSecretFailure(t *testing.T, th TaoHost) {
	tag := "test tag"
	_, err := th.GetSharedSecret(tag, 10)
	if err == nil {
		t.Fatal("A TaoHost that doesn't support shared secrets created one")
	}
}

func testTaoHostAttest(t *testing.T, th TaoHost) {
	var st Statement
	a, err := th.Attest(testChild, &st)
	if err != nil {
		t.Fatal("Couldn't attest to an empty Statement:", err)
	}

	if a == nil {
		t.Fatal("Incorrectly returned an empty attestation from a successful Attest")
	}
}

func testTaoHostEncryption(t *testing.T, th TaoHost) {
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

func testTaoHostName(t *testing.T, th TaoHost) {
	n := th.TaoHostName()
	if n == "" {
		t.Fatal("TaoHostName returned an invalid TaoHost name")
	}
}

func testTaoHostRemovedHostedProgram(t *testing.T, th TaoHost) {
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
