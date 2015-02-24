//  Copyright (c) 2015, Google Inc.  All rights reserved.
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
	"math/rand"
	"testing"
	"time"

	"github.com/jlmucb/cloudproxy/tao/auth"
)

func TestInMemoryInit(t *testing.T) {
	_, err := NewSoftTao("", nil)
	if err != nil {
		t.Fatal("Couldn't initialize a SoftTao in memory:", err)
	}
}

func TestSoftTaoRandom(t *testing.T) {
	ft, err := NewSoftTao("", nil)
	if err != nil {
		t.Fatal("Couldn't initialize a SoftTao in memory:", err)
	}

	if _, err := ft.GetRandomBytes(10); err != nil {
		t.Fatal("Couldn't get 10 random bytes:", err)
	}
}

func TestSoftTaoSeal(t *testing.T) {
	ft, err := NewSoftTao("", nil)
	if err != nil {
		t.Fatal("Couldn't initialize a SoftTao in memory:", err)
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 33)
	for i := range b {
		b[i] = byte(r.Intn(256))
	}

	_, err = ft.Seal(b, SealPolicyDefault)
	if err != nil {
		t.Fatal("Couldn't seal data in the SoftTao under the default policy:", err)
	}
}

func TestSoftTaoUnseal(t *testing.T) {
	ft, err := NewSoftTao("", nil)
	if err != nil {
		t.Fatal("Couldn't initialize a SoftTao in memory:", err)
	}

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 33)
	for i := range b {
		b[i] = byte(r.Intn(256))
	}

	s, err := ft.Seal(b, SealPolicyDefault)
	if err != nil {
		t.Fatal("Couldn't seal data in the SoftTao under the default policyL", err)
	}

	u, p, err := ft.Unseal(s)
	if string(p) != SealPolicyDefault {
		t.Fatal("Invalid policy returned by Unseal")
	}

	if len(u) != len(b) {
		t.Fatal("Invalid unsealed length")
	}

	for i, v := range u {
		if v != b[i] {
			t.Fatalf("Incorrect byte at position %d", i)
		}
	}
}

func TestSoftTaoAttest(t *testing.T) {
	ft, err := NewSoftTao("", nil)
	if err != nil {
		t.Fatal("Couldn't initialize a SoftTao in memory:", err)
	}

	self, err := ft.GetTaoName()
	if err != nil {
		t.Fatal("Couldn't get own name:", err)
	}

	stmt := auth.Speaksfor{
		Delegate:  auth.NewKeyPrin([]byte("BogusKeyBytes1")),
		Delegator: self,
	}

	a, err := ft.Attest(nil, nil, nil, stmt)
	if err != nil {
		t.Fatalf("Couldn't attest to a statement in the SoftTao:", err)
	}

	// Make sure the attestation passes basic sanity checks.
	_, err = a.Validate()
	if err != nil {
		t.Fatalf("The attestation produced by the SoftTao didn't pass validation: %s", err)
	}
}
