// Copyright (c) 2014, Google Inc. All rights reserved.
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

	"cloudproxy/tao/auth"
)

func TestTPMTao(t *testing.T) {
	// Set up a TPM Tao that seals and attests against PCRs 17 and 18 and uses
	// the AIK stored in aikblob. It communicates with the TPM directly through
	// /dev/tpm0.
	tpmtao, err := NewTPMTao("/dev/tpm0", "./aikblob", []int{17, 18})
	if err != nil {
		t.Fatal("Couldn't create a new TPM Tao:", err)
	}

	tt, ok := tpmtao.(*TPMTao)
	if !ok {
		t.Fatal("Wrong type of tao returnd from NewTPMTao")
	}

	tt.Close()
}

func TestTPMTaoSeal(t *testing.T) {
	tpmtao, err := NewTPMTao("/dev/tpm0", "./aikblob", []int{17, 18})
	if err != nil {
		t.Fatal("Couldn't create a new TPM Tao:", err)
	}
	tt, ok := tpmtao.(*TPMTao)
	if !ok {
		t.Fatal("Wrong type of tao returnd from NewTPMTao")
	}
	defer tt.Close()

	data := []byte(`test data to seal`)
	sealed, err := tpmtao.Seal(data, SealPolicyDefault)
	if err != nil {
		t.Fatal("Couldn't seal data in the TPM Tao:", err)
	}

	unsealed, policy, err := tpmtao.Unseal(sealed)
	if err != nil {
		t.Fatal("Couldn't unseal data sealed by the TPM Tao:", err)
	}

	if policy != SealPolicyDefault {
		t.Fatal("Got the wrong policy back from TPMTao.Unseal")
	}

	if !bytes.Equal(unsealed, data) {
		t.Fatal("The data returned from TPMTao.Unseal didn't match the original data")
	}

}

func TestTPMTaoAttest(t *testing.T) {
	tpmtao, err := NewTPMTao("/dev/tpm0", "./aikblob", []int{17, 18})
	if err != nil {
		t.Fatal("Couldn't create a new TPM Tao:", err)
	}
	tt, ok := tpmtao.(*TPMTao)
	if !ok {
		t.Fatal("Wrong type of tao returnd from NewTPMTao")
	}
	defer tt.Close()

	// Set up a fake key delegation.
	stmt := auth.Speaksfor{
		Delegate: auth.Prin{Type: "key", Key: []byte(`FakeKeyBytes`)},
	}

	// Let the TPMTao set up the issuer and time and expiration.
	a, err := tpmtao.Attest(nil, nil, nil, stmt)
	if err != nil {
		t.Fatal("Couldn't attest to a key delegation:", err)
	}

	says, err := a.Validate()
	if err != nil {
		t.Fatal("The attestation didn't pass validation:", err)
	}

	t.Logf("Got valid statement %s\n", says)
}
