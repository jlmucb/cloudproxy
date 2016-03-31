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

package tpm2

import (
	"crypto/rsa"
	"fmt"
        "testing"
	"time"

	"github.com/jlmucb/cloudproxy/go/tpm2"
)

func TestCreateKeyHierarchy(t *testing.T) {
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if (err != nil) {
		t.Fatal("Can't open tpm")
	}
	err = tpm2.CreateTpm2KeyHierarchy(rw, []int{7}, 2048, tpm2.AlgTPM_ALG_SHA1,
			tpm2.PrimaryKeyHandle, tpm2.QuoteKeyHandle, "01020304")
	if (err != nil) {
		t.Fatal("Can't create key hierarchy")
	}
	tpm2.Flushall(rw)
	rw.Close()
}

func TestMakeEndorsementCert(t *testing.T) {
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if (err != nil) {
		t.Fatal("Can't open tpm")
	}
	err = tpm2.CreateTpm2KeyHierarchy(rw, []int{7}, 2048, tpm2.AlgTPM_ALG_SHA1,
			tpm2.PrimaryKeyHandle, tpm2.QuoteKeyHandle, "01020304")
	if (err != nil) {
		t.Fatal("Can't create key hierarchy")
	}

	var notBefore time.Time
        notBefore = time.Now()
        validFor := 365*24*time.Hour
        notAfter := notBefore.Add(validFor)

	var derPolicyCert []byte
	var policyKey *rsa.PrivateKey
	endorsementCert, err := tpm2.GenerateHWCert(rw, tpm2.Handle(tpm2.PrimaryKeyHandle), "JohnsHw",
        	notBefore, notAfter, tpm2.GetSerialNumber(), derPolicyCert, policyKey)
	if err != nil {
		t.Fatal("Can't create endorsement cert")
	}
	fmt.Printf("Endorsement cert: %x\n", endorsementCert)
	tpm2.Flushall(rw)
	rw.Close()
}

func TestSeal(t *testing.T) {
}

func TestUnseal(t *testing.T) {
}

func TestAttest(t *testing.T) {
}

func TestSignAttest(t *testing.T) {
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if (err != nil) {
		t.Fatal("Can't open tpm")
	}
	err = tpm2.CreateTpm2KeyHierarchy(rw, []int{7}, 2048, tpm2.AlgTPM_ALG_SHA1,
			tpm2.PrimaryKeyHandle, tpm2.QuoteKeyHandle, "01020304")
	if (err != nil) {
		t.Fatal("Can't create key hierarchy")
	}

	var notBefore time.Time
        notBefore = time.Now()
        validFor := 365*24*time.Hour
        notAfter := notBefore.Add(validFor)

	var derPolicyCert []byte
	var policyKey *rsa.PrivateKey
	attestCert, err := tpm2.GenerateHWCert(rw, tpm2.Handle(tpm2.QuoteKeyHandle), "JohnsHw",
        	notBefore, notAfter, tpm2.GetSerialNumber(), derPolicyCert, policyKey)
	if err != nil {
		t.Fatal("Can't create attest cert")
	}
	fmt.Printf("Attest cert: %x\n", attestCert)
	tpm2.Flushall(rw)
	rw.Close()
}

func TestSignProtocol(t *testing.T) {
}

func TestSignProtocolChannel(t *testing.T) {
}

func TestPCR1718(t *testing.T) {
}



