// Copyright (c) 2014-2016, Google Inc. All rights reserved.
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
	"fmt"
	"runtime"
	"testing"

	// "github.com/jlmucb/cloudproxy/go/tpm2"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

// cleanUpTPMTao runs the finalizer for TPMTao early then unsets it so it
// doesn't run later. Normal code will only create one instance of TPM2Tao, so
// the finalizer will work correctly. But this test code creates multiple such
// instances, so it needs to call the finalizer early.
func cleanUpTPMTao(tt *tao.TPM2Tao) {
	tao.FinalizeTPM2Tao(tt)
	runtime.SetFinalizer(tt, nil)
}

func TestEncode(t *testing.T) {
	b1 := []byte{1,2,3}
	b2 := []byte{4,5,6}
	cb := tao.EncodeTwoBytes(b1, b2)
	fmt.Printf("combined: %x\n", cb)
	c1, c2 := tao.DecodeTwoBytes(cb)
	fmt.Printf("seperated: %x, %x\n", c1, c2)
}

func TestTPMTao(t *testing.T) {
	// Set up a TPM Tao that seals and attests against PCRs 17 and 18.
	tt, err := NewTPM2Tao("/dev/tpm0", "../tpm2/tmptest", []int{17, 18})
	if err != nil {
		t.Skip("Couldn't create a new TPM Tao:", err)
	}
	tpmtao, ok := tt.(*TPM2Tao)
	if !ok {
		t.Fatal("Failed to create the right kind of Tao object from NewTPM2Tao")
	}
	cleanUpTPMTao(tpmtao)
}

func RestTPMTaoSeal(t *testing.T) {

	tpmtao, err := NewTPMTao("/dev/tpm0", []int{17, 18})
	if err != nil {
		t.Skip("Couldn't create a new TPM Tao:", err)
	}
	tt, ok := tpmtao.(*TPM2Tao)
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

func RestTPMTaoLargeSeal(t *testing.T) {

	tpmtao, err := NewTPMTao("/dev/tpm0", []int{17, 18})
	if err != nil {
		t.Skip("Couldn't create a new TPM Tao:", err)
	}
	tt, ok := tpmtao.(*TPM2Tao)
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

func RestTPMTaoAttest(t *testing.T) {

	tpmtao, err := NewTPM2Tao("/dev/tpm0", "../tpm2/tmptest", []int{17, 18})
	if err != nil {
		t.Skip("Couldn't create a new TPM Tao:", err)
	}
	tt, ok := tpmtao.(*TPM2Tao)
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
