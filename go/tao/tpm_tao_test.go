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
	"io/ioutil"
	"runtime"
	"testing"

	"github.com/jlmucb/cloudproxy/tao/auth"
)

// cleanUpTPMTao runs the finalizer for TPMTao early then unsets it so it
// doesn't run later. Normal code will only create one instance of TPMTao, so
// the finalizer will work correctly. But this test code creates multiple such
// instances, so it needs to call the finalizer early.
func cleanUpTPMTao(tt *TPMTao) {
	FinalizeTPMTao(tt)
	runtime.SetFinalizer(tt, nil)
}

func TestTPMTao(t *testing.T) {
	aikblob, err := ioutil.ReadFile("./aikblob")
	if err != nil {
		t.Skip("Skipping tests, since there's no ./aikblob file")
	}

	// Set up a TPM Tao that seals and attests against PCRs 17 and 18 and uses
	// the AIK stored in aikblob. It communicates with the TPM directly through
	// /dev/tpm0.
	tt, err := NewTPMTao("/dev/tpm0", aikblob, []int{17, 18})
	if err != nil {
		t.Skip("Couldn't create a new TPM Tao:", err)
	}
	tpmtao, ok := tt.(*TPMTao)
	if !ok {
		t.Fatal("Failed to create the right kind of Tao object from NewTPMTao")
	}
	cleanUpTPMTao(tpmtao)
}

func TestTPMTaoSeal(t *testing.T) {
	aikblob, err := ioutil.ReadFile("./aikblob")
	if err != nil {
		t.Skip("Skipping tests, since there's no ./aikblob file")
	}

	tpmtao, err := NewTPMTao("/dev/tpm0", aikblob, []int{17, 18})
	if err != nil {
		t.Skip("Couldn't create a new TPM Tao:", err)
	}
	tt, ok := tpmtao.(*TPMTao)
	if !ok {
		t.Fatal("Failed to create the right kind of Tao object from NewTPMTao")
	}
	defer cleanUpTPMTao(tt)

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

func TestTPMTaoLargeSeal(t *testing.T) {
	aikblob, err := ioutil.ReadFile("./aikblob")
	if err != nil {
		t.Skip("Skipping tests, since there's no ./aikblob file")
	}

	tpmtao, err := NewTPMTao("/dev/tpm0", aikblob, []int{17, 18})
	if err != nil {
		t.Skip("Couldn't create a new TPM Tao:", err)
	}
	tt, ok := tpmtao.(*TPMTao)
	if !ok {
		t.Fatal("Failed to create the right kind of Tao object from NewTPMTao")
	}
	defer cleanUpTPMTao(tt)

	data := make([]byte, 10000)
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
	aikblob, err := ioutil.ReadFile("./aikblob")
	if err != nil {
		t.Skip("Skipping tests, since there's no ./aikblob file")
	}

	tpmtao, err := NewTPMTao("/dev/tpm0", aikblob, []int{17, 18})
	if err != nil {
		t.Skip("Couldn't create a new TPM Tao:", err)
	}
	tt, ok := tpmtao.(*TPMTao)
	if !ok {
		t.Fatal("Failed to create the right kind of Tao object from NewTPMTao")
	}
	defer cleanUpTPMTao(tt)

	// Set up a fake key delegation.
	taoname, err := tpmtao.GetTaoName()
	if err != nil {
		t.Fatal("Couldn't get the name of the tao:", err)
	}
	stmt := auth.Speaksfor{
		Delegate:  auth.Prin{Type: "key", Key: auth.Bytes([]byte(`FakeKeyBytes`))},
		Delegator: taoname,
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
