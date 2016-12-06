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
	"fmt"
	"log"
	"os"
	"runtime"
	"testing"

	"github.com/jlmucb/cloudproxy/go/tao/auth"
	"github.com/jlmucb/cloudproxy/go/tpm2"
	"github.com/jlmucb/cloudproxy/go/tpm2/tpm2_apps"
)

// cleanUpTPM2Tao runs the finalizer for TPMTao early then unsets it so it
// doesn't run later. Normal code will only create one instance of TPM2Tao, so
// the finalizer will work correctly. But this test code creates multiple such
// instances, so it needs to call the finalizer early.
func cleanUpTPM2Tao(tt *TPM2Tao) {
	FinalizeTPM2Tao(tt)
	runtime.SetFinalizer(tt, nil)
}

var test_dir string = "../tpm2/tmptest"

func startQuoteServer() {
	// Setup testing env
	us := "US"
	org := "Google"
	details := X509Details{
		Country:            &us,
		Organization:       &org,
		OrganizationalUnit: &org,
		CommonName:         &org,
	}
	os.Mkdir(test_dir, 644)
	quoteServer := tpm2_apps.NewQuoteServer("tcp", "127.0.0.1:8121")
	go quoteServer.HandleQuote("xxx", test_dir, details)
}

func tpm2Setup() {
	err := tpm2_apps.HandlePolicyKey(2048, test_dir+"policy.go.bin", "xxx", test_dir+"policy.cert.go.der")
	if err != nil {
		log.Fatal(err)
	}
	err = tpm2_apps.HandleEndorsement(2048, "endorsement_key", test_dir+"endorsement_cert",
		test_dir+"policy.cert.go.der", test_dir+"policy.go.bin", "xxx", test_dir, true)
	if err != nil {
		log.Fatal(err)
	}
}

func TestEncode(t *testing.T) {
	b1 := []byte{1, 2, 3}
	b2 := []byte{4, 5, 6}
	cb := EncodeTwoBytes(b1, b2)
	fmt.Printf("combined: %x\n", cb)
	c1, c2 := DecodeTwoBytes(cb)
	fmt.Printf("seperated: %x, %x\n", c1, c2)
}

func TestTPM2Tao(t *testing.T) {
	// Set up a TPM2 Tao that seals and attests against PCRs 17 and 18.
	tt, err := NewTPM2Tao("/dev/tpm0", test_dir, []int{17, 18})
	if err != nil {
		t.Skip("Couldn't create a new TPM2 Tao:", err)
	}
	tpmtao, ok := tt.(*TPM2Tao)
	if !ok {
		t.Fatal("Failed to create the right kind of Tao object from NewTPM2Tao")
	}
	cleanUpTPM2Tao(tpmtao)
}

func TestTPM2TaoSeal(t *testing.T) {

	tpmtao, err := NewTPM2Tao("/dev/tpm0", test_dir, []int{17, 18})
	if err != nil {
		t.Skip("Couldn't create a new TPM2 Tao:", err)
	}
	tt, ok := tpmtao.(*TPM2Tao)
	if !ok {
		t.Fatal("Failed to create the right kind of Tao object from NewTPM2Tao")
	}
	defer cleanUpTPM2Tao(tt)

	data := []byte(`test data to seal`)
	sealed, err := tpmtao.Seal(data, SealPolicyDefault)
	if err != nil {
		t.Fatal("Couldn't seal data in the TPM2 Tao:", err)
	}
	fmt.Printf("sealed: %x\n", sealed)

	// Fix this hack
	// tpmtao.(*TPM2Tao).TmpRm()

	unsealed, policy, err := tpmtao.Unseal(sealed)
	if err != nil {
		t.Fatal("Couldn't unseal data sealed by the TPM2 Tao:", err)
	}

	if policy != SealPolicyDefault {
		t.Fatal("Got the wrong policy back from TPM2Tao.Unseal")
	}

	if !bytes.Equal(unsealed, data) {
		t.Fatal("The data returned from TPM2Tao.Unseal didn't match the original data")
	}
}

func TestTPM2TaoLargeSeal(t *testing.T) {

	tpmtao, err := NewTPM2Tao("/dev/tpm0", "../tpm2//tmptest", []int{17, 18})
	if err != nil {
		t.Skip("Couldn't create a new TPM2 Tao:", err)
	}
	tt, ok := tpmtao.(*TPM2Tao)
	if !ok {
		t.Fatal("Failed to create the right kind of Tao object from NewTPM2Tao")
	}
	defer cleanUpTPM2Tao(tt)

	data := make([]byte, 10000)
	sealed, err := tpmtao.Seal(data, SealPolicyDefault)
	if err != nil {
		t.Fatal("Couldn't seal data in the TPM2 Tao:", err)
	}

	unsealed, policy, err := tpmtao.Unseal(sealed)
	if err != nil {
		t.Fatal("Couldn't unseal data sealed by the TPM2 Tao:", err)
	}

	if policy != SealPolicyDefault {
		t.Fatal("Got the wrong policy back from TPM2Tao.Unseal")
	}

	if !bytes.Equal(unsealed, data) {
		t.Fatal("The data returned from TPM2Tao.Unseal didn't match the original data")
	}
}

func TestTPM2TaoAttest(t *testing.T) {

	// Fix
	hash_alg_id := uint16(tpm2.AlgTPM_ALG_SHA1)

	tpmtao, err := NewTPM2Tao("/dev/tpm0", test_dir, []int{17, 18})
	if err != nil {
		t.Skip("Couldn't create a new TPM2 Tao:", err)
	}
	tt, ok := tpmtao.(*TPM2Tao)
	if !ok {
		t.Fatal("Failed to create the right kind of Tao object from NewTPM2Tao")
	}
	defer cleanUpTPM2Tao(tt)

	// Set up a fake key delegation.
	taoname, err := tpmtao.GetTaoName()
	if err != nil {
		t.Fatal("Couldn't get the name of the tao:", err)
	}
	stmt := auth.Speaksfor{
		Delegate:  auth.NewKeyPrin([]byte(`FakeKeyBytes`)),
		Delegator: taoname,
	}

	// Let the TPMTao set up the issuer and time and expiration.
	a, err := tpmtao.Attest(nil, nil, nil, stmt)
	if err != nil {
		t.Fatal("Couldn't attest to a key delegation:", err)
	}

	digests, err := ReadTPM2PCRs(tt.rw, []int{17, 18})
	if err != nil {
		t.Fatal("ReadPcrs failed\n")
	}
	var allDigests []byte
	for i := 0; i < len(digests); i++ {
		allDigests = append(allDigests, digests[i]...)
	}
	computedDigest, err := tpm2.ComputeHashValue(hash_alg_id, allDigests)
	if err != nil {
		t.Fatal("Can't compute combined quote digest")
	}
	fmt.Printf("Pcr combined digest: %x\n", computedDigest)

	pms, err := tpm2.UnmarshalCertifyInfo(a.Tpm2QuoteStructure)
	if err != nil {
		fmt.Printf("a.Tpm2QuoteStructure: %x\n", a.Tpm2QuoteStructure)
		t.Fatal("Can't unmarshal quote structure\n")
	}
	tpm2.PrintAttestData(pms)
	quoteHandle, err := tt.loadQuoteContext()
	if err != nil {
	}
	defer tpm2.FlushContext(tt.rw, quoteHandle)
	key, _ := tt.GetRsaTPMKey(quoteHandle)
	ok, err = tpm2.VerifyTpm2Quote(a.SerializedStatement, tt.GetPcrNums(),
		computedDigest, a.Tpm2QuoteStructure, a.Signature, key)
	if err != nil {
		t.Fatal("VerifyQuote error")
	}
	if !ok {
		t.Fatal("VerifyQuote succeeds")
	}
}

func TestTPM2TaoGetCounter(t *testing.T) {
	fmt.Printf("TestTPM2TaoGetCounter")
	tpmtao, err := NewTPM2Tao("/dev/tpm0", test_dir, []int{17, 18})
	if err != nil {
		t.Skip("Couldn't create a new TPM2 Tao:", err)
	}
	tt, ok := tpmtao.(*TPM2Tao)
	if !ok {
		t.Fatal("Failed to create the right kind of Tao object from NewTPM2Tao")
	}
	defer cleanUpTPM2Tao(tt)

	c, err := tpmtao.GetCounter("TestSealCounterLabel")
	if err != nil {
		t.Fatal("Couldn't GetCounter from TPM2 Tao:", err)
	}
	fmt.Printf("TestTPM2TaoGetCounter: %d\n", c)
}

func TestTPM2TaoRollbackSealUnseal(t *testing.T) {
	tpmtao, err := NewTPM2Tao("/dev/tpm0", test_dir, []int{17, 18})
	if err != nil {
		t.Skip("Couldn't create a new TPM2 Tao:", err)
	}
	tt, ok := tpmtao.(*TPM2Tao)
	if !ok {
		t.Fatal("Failed to create the right kind of Tao object from NewTPM2Tao")
	}
	defer cleanUpTPM2Tao(tt)

	data := make([]byte, 10000)
	sealed, err := tpmtao.RollbackProtectedSeal("TestSeal", data, SealPolicyDefault)
	if err != nil {
		t.Fatal("Couldn't RollbackProtectedSeal data in the TPM2 Tao:", err)
	}

	unsealed, policy, err := tpmtao.RollbackProtectedUnseal(sealed)
	if err != nil {
		t.Fatal("Couldn't RollbackProtectedUnseal data sealed by the TPM2 Tao:", err)
	}

	if policy != SealPolicyDefault {
		t.Fatal("Got the wrong policy back from TPM2Tao.Unseal")
	}

	if !bytes.Equal(unsealed, data) {
		t.Fatal("The data returned from TPM2Tao.Unseal didn't match the original data")
	}
}
