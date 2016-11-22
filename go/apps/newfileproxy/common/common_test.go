// Copyright (c) 2016, Google Inc. All rights reserved.
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

package common

import (
	// "crypto/ecdsa"
	// "crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	// "math/big"
	"testing"
	// "time"
)

func TestNonceSignVerify(t *testing.T) {
	privateKey, err := GenerateUserPublicKey()
	if err != nil {
		t.Fatal("Can't generate key")
	}
	keyData, err := MakeUserKeyStructute(privateKey, "TestUser", privateKey, nil)
	if err != nil {
		t.Fatal("Can't get keyData")
	}
	certificate, err := x509.ParseCertificate(keyData.Cert)
	if err != nil {
		t.Fatal("Can't parse certificate")
	}
	var nonce [32]byte
	rand.Read(nonce[:])
	s1, s2, err := SignNonce(nonce[:], privateKey)
	if err != nil {
		t.Fatal("Can't sign nonce")
	}
	if !Verify(nonce[:], s1, s2, certificate) {
		t.Fatal("Can't verify")
	} else {
		fmt.Printf("Verifies")
	}
}

func TestServices(t *testing.T) {
	fmt.Printf("TestServices succeeds")
}

