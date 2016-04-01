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

package tpm2

import (
	"bytes"
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"math/big"
	"testing"

	"github.com/jlmucb/cloudproxy/go/tpm2"
	"github.com/golang/protobuf/proto"
)

// Test Endian
func TestEndian(t *testing.T) {
	l := uint16(0xff12)
	v := byte(l >> 8)
	var s [2]byte
	s[0] = v
	v = byte(l & 0xff)
	s[1] = v
	if s[0] != 0xff || s[1] != 0x12 {
		t.Fatal("Endian test mismatch")
	}
}

// Test GetRandom
func TestGetRandom(t *testing.T) {
	fmt.Printf("TestGetRandom\n")

	// Open TPM
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}
	fmt.Printf("Flushall\n")
	tpm2.Flushall(rw)

	fmt.Printf("GetRandom\n")
	rand, err :=  tpm2.GetRandom(rw, 16)
	if err != nil {
		fmt.Printf("GetRandon Error ", err, "\n")
		t.Fatal("GetRandom failed\n")
	}
	fmt.Printf("rand: %x\n", rand[0:len(rand)])
	rw.Close()
}

// TestReadPcr tests a ReadPcr command.
func TestReadPcrs(t *testing.T) {
	fmt.Printf("TestReadPcrs\n")

	// Open TPM
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	defer rw.Close()
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}
	fmt.Printf("Flushall\n")
	tpm2.Flushall(rw)

	pcr := []byte{0x03, 0x80, 0x00, 0x00}
	counter, pcr_out, alg, digest, err := tpm2.ReadPcrs(rw, byte(4), pcr)
	if err != nil {
		t.Fatal("ReadPcrs failed\n")
	}
	fmt.Printf("Counter: %x, pcr: %x, alg: %x, digest: %x\n", counter,
		   pcr_out, alg, digest)
	rw.Close()
}

// TestReadClock tests a ReadClock command.
func TestReadClock(t *testing.T) {
	fmt.Printf("TestReadClock\n")

	// Open TPM
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}
	fmt.Printf("Flushall\n")
	tpm2.Flushall(rw)

	current_time, current_clock, err := tpm2.ReadClock(rw)
	if err != nil {
		t.Fatal("ReadClock failed\n")
	}
	fmt.Printf("current_time: %x , current_clock: %x\n",
		   current_time, current_clock)
	rw.Close()

}

// TestGetCapabilities tests a GetCapabilities command.
// Command: 8001000000160000017a000000018000000000000014
func TestGetCapabilities(t *testing.T) {

	// Open TPM
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}
	fmt.Printf("Flushall\n")
	tpm2.Flushall(rw)

	handles, err := tpm2.GetCapabilities(rw, tpm2.OrdTPM_CAP_HANDLES,
					     1, 0x80000000)
	if err != nil {
		t.Fatal("GetCapabilities failed\n")
	}
	fmt.Printf("Open handles:\n")
	for _, e := range handles {
		fmt.Printf("    %x\n", e)
	}
	rw.Close()
}

// Combined Key Test
func TestCombinedKeyTest(t *testing.T) {

	// Open tpm
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}

	// Flushall
	err =  tpm2.Flushall(rw)
	if err != nil {
		t.Fatal("Flushall failed\n")
	}

	// CreatePrimary
	var empty []byte
	primaryparms := tpm2.RsaParams{uint16(tpm2.AlgTPM_ALG_RSA),
		uint16(tpm2.AlgTPM_ALG_SHA1), uint32(0x00030072),
		empty, uint16(tpm2.AlgTPM_ALG_AES), uint16(128),
		uint16(tpm2.AlgTPM_ALG_CFB), uint16(tpm2.AlgTPM_ALG_NULL),
		uint16(0), uint16(1024), uint32(0x00010001), empty}
	parent_handle, public_blob, err := tpm2.CreatePrimary(rw,
		uint32(tpm2.OrdTPM_RH_OWNER), []int{0x7}, "",
		"01020304", primaryparms)
	if err != nil {
		t.Fatal("CreatePrimary fails")
	}
	fmt.Printf("CreatePrimary succeeded\n")

	// CreateKey
	keyparms := tpm2.RsaParams{uint16(tpm2.AlgTPM_ALG_RSA),
		uint16(tpm2.AlgTPM_ALG_SHA1), uint32(0x00030072), empty,
		uint16(tpm2.AlgTPM_ALG_AES), uint16(128),
		uint16(tpm2.AlgTPM_ALG_CFB), uint16(tpm2.AlgTPM_ALG_NULL),
		uint16(0), uint16(1024), uint32(0x00010001), empty}
	private_blob, public_blob, err := tpm2.CreateKey(rw,
		uint32(parent_handle), []int{7}, "01020304", "01020304",
		keyparms)
	if err != nil {
		t.Fatal("CreateKey fails")
	}
	fmt.Printf("CreateKey succeeded, handle: %x\n", uint32(parent_handle))
	fmt.Printf("Private blob: %x\n", private_blob)
	fmt.Printf("Public  blob: %x\n\n", public_blob)

	// Load
	key_handle, blob, err := tpm2.Load(rw, parent_handle, "", "01020304",
	     public_blob, private_blob)
	if err != nil {
		t.Fatal("Load fails")
	}
	fmt.Printf("Load succeeded, handle: %x\n", uint32(key_handle))
	fmt.Printf("Blob from Load     : %x\n", blob)

	// ReadPublic
	public, name, qualified_name, err := tpm2.ReadPublic(rw, key_handle)
	if err != nil {
		t.Fatal("ReadPublic fails")
	}
	fmt.Printf("ReadPublic succeeded\n")
	fmt.Printf("Public	 blob: %x\n", public)
	fmt.Printf("Name	   blob: %x\n", name)
	fmt.Printf("Qualified name blob: %x\n\n", qualified_name)

	// Flush
	err = tpm2.FlushContext(rw, key_handle)
	err = tpm2.FlushContext(rw, parent_handle)
	rw.Close()
}

// Combined Seal test
func TestCombinedSealTest(t *testing.T) {

	// Open tpm
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}

	// Flushall
	err =  tpm2.Flushall(rw)
	if err != nil {
		t.Fatal("Flushall failed\n")
	}

	// CreatePrimary
	var empty []byte
	primaryparms := tpm2.RsaParams{uint16(tpm2.AlgTPM_ALG_RSA),
		uint16(tpm2.AlgTPM_ALG_SHA1), uint32(0x00030072), empty,
		uint16(tpm2.AlgTPM_ALG_AES), uint16(128),
		uint16(tpm2.AlgTPM_ALG_CFB), uint16(tpm2.AlgTPM_ALG_NULL),
		uint16(0), uint16(1024), uint32(0x00010001), empty}
	parent_handle, public_blob, err := tpm2.CreatePrimary(rw,
		uint32(tpm2.OrdTPM_RH_OWNER), []int{0x7}, "",
		"01020304", primaryparms)
	if err != nil {
		t.Fatal("CreatePrimary fails")
	}
	fmt.Printf("CreatePrimary succeeded\n")

	nonceCaller := []byte{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0}
	var secret []byte
	sym := uint16(tpm2.AlgTPM_ALG_NULL)
	to_seal := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
	hash_alg := uint16(tpm2.AlgTPM_ALG_SHA1)

	session_handle, policy_digest, err := tpm2.StartAuthSession(rw,
		tpm2.Handle(tpm2.OrdTPM_RH_NULL),
		tpm2.Handle(tpm2.OrdTPM_RH_NULL), nonceCaller, secret,
		uint8(tpm2.OrdTPM_SE_POLICY), sym, hash_alg)
	if err != nil {
		tpm2.FlushContext(rw, parent_handle)
		t.Fatal("StartAuthSession fails")
	}
	fmt.Printf("policy digest  : %x\n", policy_digest)

	err = tpm2.PolicyPassword(rw, session_handle)
	if err != nil {
		tpm2.FlushContext(rw, parent_handle)
		tpm2.FlushContext(rw, session_handle)
		t.Fatal("PolicyPcr fails")
	}
	var tpm_digest []byte
	err = tpm2.PolicyPcr(rw, session_handle, tpm_digest, []int{7})
	if err != nil {
		tpm2.FlushContext(rw, parent_handle)
		tpm2.FlushContext(rw, session_handle)
		t.Fatal("PolicyPcr fails")
	}

	policy_digest, err = tpm2.PolicyGetDigest(rw, session_handle)
	if err != nil {
		tpm2.FlushContext(rw, parent_handle)
		tpm2.FlushContext(rw, session_handle)
		t.Fatal("PolicyGetDigest after PolicyPcr fails")
	}
	fmt.Printf("policy digest after PolicyPcr: %x\n", policy_digest)

	// CreateSealed
	keyedhashparms := tpm2.KeyedHashParams{uint16(tpm2.AlgTPM_ALG_KEYEDHASH),
		uint16(tpm2.AlgTPM_ALG_SHA1), uint32(0x00000012), empty,
		uint16(tpm2.AlgTPM_ALG_AES), uint16(128),
		uint16(tpm2.AlgTPM_ALG_CFB), uint16(tpm2.AlgTPM_ALG_NULL),
		empty}
	private_blob, public_blob, err := tpm2.CreateSealed(rw, parent_handle,
		policy_digest, "01020304",  "01020304", to_seal, []int{7},
		keyedhashparms)
	if err != nil {
		tpm2.FlushContext(rw, parent_handle)
		tpm2.FlushContext(rw, session_handle)
		t.Fatal("CreateSealed fails")
	}

	// Load
	item_handle, _, err := tpm2.Load(rw, parent_handle, "", "01020304",
		public_blob, private_blob)
	if err != nil {
		tpm2.FlushContext(rw, session_handle)
		tpm2.FlushContext(rw, item_handle)
		tpm2.FlushContext(rw, parent_handle)
		t.Fatal("Load fails")
	}
	fmt.Printf("Load succeeded\n")

	// Unseal
	unsealed, nonce, err := tpm2.Unseal(rw, item_handle, "01020304",
		session_handle, policy_digest)
	if err != nil {
		tpm2.FlushContext(rw, item_handle)
		tpm2.FlushContext(rw, parent_handle)
		t.Fatal("Unseal fails")
	}
	fmt.Printf("Unseal succeeds\n")
	fmt.Printf("unsealed           : %x\n", unsealed)
	fmt.Printf("nonce              : %x\n\n", nonce)

	// Flush
	tpm2.FlushContext(rw, item_handle)
	tpm2.FlushContext(rw, parent_handle)
	tpm2.FlushContext(rw, session_handle)
	rw.Close()
	if bytes.Compare(to_seal, unsealed) != 0 {
		t.Fatal("seal and unsealed bytes dont match")
	}
}

// Combined Quote test
func TestCombinedQuoteTest(t *testing.T) {

	// Open tpm
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}

	// Flushall
	err =  tpm2.Flushall(rw)
	if err != nil {
		t.Fatal("Flushall failed\n")
	}

	// CreatePrimary
	var empty []byte
	primaryparms := tpm2.RsaParams{uint16(tpm2.AlgTPM_ALG_RSA),
		uint16(tpm2.AlgTPM_ALG_SHA1), uint32(0x00030072),
		empty, uint16(tpm2.AlgTPM_ALG_AES), uint16(128),
		uint16(tpm2.AlgTPM_ALG_CFB), uint16(tpm2.AlgTPM_ALG_NULL),
		uint16(0), uint16(1024), uint32(0x00010001), empty}
	parent_handle, public_blob, err := tpm2.CreatePrimary(rw,
		uint32(tpm2.OrdTPM_RH_OWNER), []int{0x7}, "",
		"01020304", primaryparms)
	if err != nil {
		t.Fatal("CreatePrimary fails")
	}
	fmt.Printf("CreatePrimary succeeded\n\n")

	// Pcr event
	eventData := []byte{1,2,3}
	err =  tpm2.PcrEvent(rw, 7, eventData)
	if err != nil {
		t.Fatal("PcrEvent fails")
	}

	// CreateKey (Quote Key)
	keyparms := tpm2.RsaParams{uint16(tpm2.AlgTPM_ALG_RSA),
		uint16(tpm2.AlgTPM_ALG_SHA1), uint32(0x00050072), empty,
		uint16(tpm2.AlgTPM_ALG_NULL), uint16(0),
		uint16(tpm2.AlgTPM_ALG_ECB), uint16(tpm2.AlgTPM_ALG_RSASSA),
		uint16(tpm2.AlgTPM_ALG_SHA1),
		uint16(1024), uint32(0x00010001), empty}

	private_blob, public_blob, err := tpm2.CreateKey(rw,
		uint32(parent_handle), []int{7}, "01020304", "01020304",
		keyparms)
	if err != nil {
		t.Fatal("CreateKey fails")
	}
	fmt.Printf("CreateKey succeeded\n")
	fmt.Printf("Private blob: %x\n", private_blob)
	fmt.Printf("Public  blob: %x\n", public_blob)

	// Load
	quote_handle, blob, err := tpm2.Load(rw, parent_handle, "", "01020304",
	     public_blob, private_blob)
	if err != nil {
		t.Fatal("Load fails")
	}
	fmt.Printf("Load succeeded, handle: %x\n", uint32(quote_handle))
	fmt.Printf("Blob from Load        : %x\n\n", blob)

	// Quote
	to_quote := []byte{0x0f,0x0e,0x0d,0x0c,0x0b,0x0a,0x09,0x08,
			   0x07,0x06,0x05,0x04,0x03,0x02,0x01,0x00}
	attest, sig, err := tpm2.Quote(rw, quote_handle, "01020304", "01020304",
		to_quote, []int{7}, uint16(tpm2.AlgTPM_ALG_NULL))
	if err != nil {
		tpm2.FlushContext(rw, quote_handle)
		rw.Close()
		t.Fatal("Quote fails")
	}
	fmt.Printf("attest             : %x\n", attest)
	fmt.Printf("sig                : %x\n\n", sig)

	// get info for verify
	keyblob, name, qualified_name, err := tpm2.ReadPublic(rw, quote_handle)
	if err != nil {
		tpm2.FlushContext(rw, quote_handle)
		err = tpm2.FlushContext(rw, parent_handle)
		rw.Close()
		t.Fatal("Quote fails")
	}

	// Flush
	err = tpm2.FlushContext(rw, quote_handle)
	err = tpm2.FlushContext(rw, parent_handle)
	rw.Close()

	// Verify quote
	fmt.Printf("keyblob(%x): %x\n", len(keyblob), keyblob)
	fmt.Printf("name(%x): %x\n", len(name), name)
	fmt.Printf("qualified_name(%x): %x\n", len(qualified_name), qualified_name)
	rsaParams, err := tpm2.DecodeRsaBuf(public_blob)
	if err != nil {
		t.Fatal("DecodeRsaBuf fails %s", err)
	}
	tpm2.PrintRsaParams(rsaParams)

	var quote_key_info tpm2.QuoteKeyInfoMessage 
	att := int32(rsaParams.Attributes)
	quote_key_info.Name = name
	quote_key_info.Properties = &att
	quote_key_info.PublicKey = new(tpm2.PublicKeyMessage)
	key_type := "rsa"
	quote_key_info.PublicKey.KeyType = &key_type
	quote_key_info.PublicKey.RsaKey = new(tpm2.RsaPublicKeyMessage)
	key_name :=  "QuoteKey"
	quote_key_info.PublicKey.RsaKey.KeyName = &key_name
	sz_mod := int32(rsaParams.Mod_sz)
	quote_key_info.PublicKey.RsaKey.BitModulusSize = &sz_mod
	quote_key_info.PublicKey.RsaKey.Exponent = []byte{0,1,0,1}
	quote_key_info.PublicKey.RsaKey.Modulus =  rsaParams.Modulus
	if !tpm2.VerifyQuote(to_quote, quote_key_info,
				uint16(tpm2.AlgTPM_ALG_SHA1), attest, sig) {
		t.Fatal("VerifyQuote fails")
	}
	fmt.Printf("VerifyQuote succeeds\n")
}

// Combined Endorsement/Activate test
func TestCombinedEndorsementTest(t *testing.T) {
	hash_alg_id := uint16(tpm2.AlgTPM_ALG_SHA1)

	// Open tpm
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}
	defer rw.Close()

	// Flushall
	err =  tpm2.Flushall(rw)
	if err != nil {
		t.Fatal("Flushall failed\n")
	}

	// CreatePrimary
	var empty []byte
	primaryparms := tpm2.RsaParams{uint16(tpm2.AlgTPM_ALG_RSA),
		uint16(tpm2.AlgTPM_ALG_SHA1), uint32(0x00030072), empty,
		uint16(tpm2.AlgTPM_ALG_AES), uint16(128),
		uint16(tpm2.AlgTPM_ALG_CFB), uint16(tpm2.AlgTPM_ALG_NULL),
		uint16(0), uint16(2048), uint32(0x00010001), empty}
	parent_handle, public_blob, err := tpm2.CreatePrimary(rw,
		uint32(tpm2.OrdTPM_RH_OWNER), []int{0x7}, "", "", primaryparms)
	if err != nil {
		t.Fatal("CreatePrimary fails")
	}
	fmt.Printf("CreatePrimary succeeded\n")
	endorseParams, err := tpm2.DecodeRsaArea(public_blob)
	if err != nil {
		t.Fatal("DecodeRsaBuf fails", err)
	}

	// CreateKey
	keyparms := tpm2.RsaParams{uint16(tpm2.AlgTPM_ALG_RSA),
		uint16(tpm2.AlgTPM_ALG_SHA1), uint32(0x00030072), empty,
		uint16(tpm2.AlgTPM_ALG_AES), uint16(128),
		uint16(tpm2.AlgTPM_ALG_CFB), uint16(tpm2.AlgTPM_ALG_NULL),
		uint16(0), uint16(2048), uint32(0x00010001), empty}
	private_blob, public_blob, err := tpm2.CreateKey(rw,
		uint32(parent_handle),
		[]int{7}, "", "01020304", keyparms)
	if err != nil {
		t.Fatal("CreateKey fails")
	}
	fmt.Printf("CreateKey succeeded\n")

	// Load
	key_handle, _, err := tpm2.Load(rw, parent_handle, "", "",
	     public_blob, private_blob)
	if err != nil {
		t.Fatal("Load fails")
	}
	fmt.Printf("Load succeeded\n")

	// ReadPublic
	_, name, _, err := tpm2.ReadPublic(rw, key_handle)
	if err != nil {
		t.Fatal("ReadPublic fails")
	}
	fmt.Printf("ReadPublic succeeded\n")

	// Generate Credential
	credential := []byte{1,2,3,4,5,6,7,8,9,0xa,0xb,0xc,0xd,0xe,0xf,0x10}
	fmt.Printf("Credential: %x\n", credential)

	// Internal MakeCredential
	credBlob, encrypted_secret0, err := tpm2.InternalMakeCredential(rw,
		parent_handle, credential, name)
	if err != nil {
		tpm2.FlushContext(rw, key_handle)
		tpm2.FlushContext(rw, parent_handle)
		t.Fatal("Can't InternalMakeCredential\n")
	}

	// ActivateCredential
	recovered_credential1, err := tpm2.ActivateCredential(rw,
		key_handle, parent_handle,
		"01020304", "", credBlob, encrypted_secret0)
	if err != nil {
		tpm2.FlushContext(rw, key_handle)
		tpm2.FlushContext(rw, parent_handle)
		t.Fatal("Can't ActivateCredential\n")
	}
	if bytes.Compare(credential, recovered_credential1) != 0 {
		tpm2.FlushContext(rw, key_handle)
		tpm2.FlushContext(rw, parent_handle)
		t.Fatal("Credential and recovered credential differ\n")
	}
	fmt.Printf("InternalMake/Activate test succeeds\n\n")

	protectorPublic := new(rsa.PublicKey)
	protectorPublic.E = 0x00010001
	M := new(big.Int)
	M.SetBytes(endorseParams.Modulus)
	protectorPublic.N = M

	// MakeCredential
	encrypted_secret, encIdentity, integrityHmac, err := tpm2.MakeCredential(
		protectorPublic, hash_alg_id, credential, name)
	if err != nil {
		tpm2.FlushContext(rw, key_handle)
		tpm2.FlushContext(rw, parent_handle)
		t.Fatal("Can't MakeCredential\n")
	}

	// ActivateCredential
	recovered_credential2, err := tpm2.ActivateCredential(rw,
		key_handle, parent_handle, "01020304", "",
		append(integrityHmac, encIdentity...), encrypted_secret)
	if err != nil {
		tpm2.FlushContext(rw, key_handle)
		tpm2.FlushContext(rw, parent_handle)
		t.Fatal("Can't ActivateCredential\n")
	}
	if bytes.Compare(credential, recovered_credential2) != 0 {
		tpm2.FlushContext(rw, key_handle)
		tpm2.FlushContext(rw, parent_handle)
		t.Fatal("Credential and recovered credential differ\n")
	}
	fmt.Printf("Make/Activate test succeeds\n")

	// Flush
	tpm2.FlushContext(rw, key_handle)
}

// Combined Evict test
func TestCombinedEvictTest(t *testing.T) {
	fmt.Printf("TestCombinedEvictTest excluded\n")
	return

	// Open tpm
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}

	// Flushall
	err =  tpm2.Flushall(rw)
	if err != nil {
		t.Fatal("Flushall failed\n")
	}

	// CreatePrimary
	var empty []byte
	primaryparms := tpm2.RsaParams{uint16(tpm2.AlgTPM_ALG_RSA),
		uint16(tpm2.AlgTPM_ALG_SHA1), uint32(0x00030072), empty,
		uint16(tpm2.AlgTPM_ALG_AES), uint16(128),
		uint16(tpm2.AlgTPM_ALG_CFB), uint16(tpm2.AlgTPM_ALG_NULL),
		uint16(0), uint16(1024), uint32(0x00010001), empty}
	parent_handle, public_blob, err := tpm2.CreatePrimary(rw,
		uint32(tpm2.OrdTPM_RH_OWNER), []int{0x7}, "",
		"01020304", primaryparms)
	if err != nil {
		t.Fatal("CreatePrimary fails")
	}
	fmt.Printf("CreatePrimary succeeded\n")

	// CreateKey
	keyparms := tpm2.RsaParams{uint16(tpm2.AlgTPM_ALG_RSA),
		uint16(tpm2.AlgTPM_ALG_SHA1), uint32(0x00030072), empty,
		uint16(tpm2.AlgTPM_ALG_AES), uint16(128),
		uint16(tpm2.AlgTPM_ALG_CFB), uint16(tpm2.AlgTPM_ALG_NULL),
		uint16(0), uint16(1024), uint32(0x00010001), empty}
	private_blob, public_blob, err := tpm2.CreateKey(rw,
		uint32(parent_handle),
		[]int{7}, "01020304", "01020304", keyparms)
	if err != nil {
		t.Fatal("CreateKey fails")
	}
	fmt.Printf("CreateKey succeeded\n")

	// Load
	key_handle, _, err := tpm2.Load(rw, parent_handle, "", "01020304",
	     public_blob, private_blob)
	if err != nil {
		t.Fatal("Load fails")
	}
	fmt.Printf("Load succeeded\n")

	perm_handle := uint32(0x810003e8)

	// Evict
	err = tpm2.EvictControl(rw, tpm2.Handle(tpm2.OrdTPM_RH_OWNER),
		key_handle, tpm2.Handle(perm_handle))
	if err != nil {
		t.Fatal("EvictControl 1 fails")
	}

	// Evict
	err = tpm2.EvictControl(rw, tpm2.Handle(tpm2.OrdTPM_RH_OWNER),
		tpm2.Handle(perm_handle), tpm2.Handle(perm_handle))
	if err != nil {
		t.Fatal("EvictControl 2 fails")
	}

	// Flush
	err = tpm2.FlushContext(rw, key_handle)
	err = tpm2.FlushContext(rw, parent_handle)
	rw.Close()
}

// Combined Context test
func TestCombinedContextTest(t *testing.T) {
	fmt.Printf("TestCombinedContextTest excluded\n")
	return
	// pcr selections
	// CreatePrimary
	// SaveContext
	// FlushContext
	// LoadContext
	// FlushContext
}

// Combined Quote Protocol
func TestCombinedQuoteProtocolTest(t *testing.T) {
	// Read encoded private policy key
	proto_policy_key, _ := ioutil.ReadFile("/home/jlm/cryptobin/cloudproxy_key_file.proto")
	if proto_policy_key == nil {
		t.Fatal("Can't open private key file")
	}

	// Read der-encoded policy cert
	der_policy_cert,_ := ioutil.ReadFile("/home/jlm/cryptobin/policy_key_cert")
	if der_policy_cert == nil {
		t.Fatal("Can't open private cert file")
	}
	policyKey, err := tpm2.DeserializeRsaKey(proto_policy_key)
	if err != nil {
		t.Fatal("Can't deserialize policy key")
	}

	// Read endorsement cert file
	der_endorsement_cert, _ := ioutil.ReadFile("/home/jlm/cryptobin/endorsement_cert")
	if der_endorsement_cert == nil {
		t.Fatal("Can't open private key file")
	}
	fmt.Printf("Got endorsement cert: %x\n\n", der_endorsement_cert)

	// Open tpm
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		t.Fatal("Can't open tpm")
	}
	defer rw.Close()

	// Open endorsement and quote keys
	var empty []byte
	ek_parms := tpm2.RsaParams{uint16(tpm2.AlgTPM_ALG_RSA),
		uint16(tpm2.AlgTPM_ALG_SHA1),
		uint32(0x00030072), empty, 
		uint16(tpm2.AlgTPM_ALG_AES), uint16(128),
		uint16(tpm2.AlgTPM_ALG_CFB), uint16(tpm2.AlgTPM_ALG_NULL),
		uint16(0), uint16(1024), uint32(0x00010001), empty}
	endorsement_handle, _, err := tpm2.CreatePrimary(rw,
		// uint32(tpm2.OrdTPM_RH_ENDORSEMENT), []int{7},
		uint32(tpm2.OrdTPM_RH_OWNER), []int{7},
		"", "", ek_parms)
	if err != nil {
		t.Fatal("CreatePrimary fails")
	}
	quote_parms := tpm2.RsaParams{uint16(tpm2.AlgTPM_ALG_RSA),
		uint16(tpm2.AlgTPM_ALG_SHA1), uint32(0x00030072), empty,
		uint16(tpm2.AlgTPM_ALG_AES), uint16(128),
		uint16(tpm2.AlgTPM_ALG_CFB), uint16(tpm2.AlgTPM_ALG_NULL),
		uint16(0), uint16(1024), uint32(0x00010001), empty}
	private_blob, public_blob, err := tpm2.CreateKey(rw,
		uint32(endorsement_handle), []int{7},
		"", "01020304", quote_parms)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("Create fails")
	}
	fmt.Printf("Create Key for quote succeeded\n")

	quote_handle, quote_blob, err := tpm2.Load(rw, endorsement_handle, "",
		"", public_blob, private_blob)
	if err != nil {
		t.Fatal("Quote Load fails")
	}
	fmt.Printf("Load succeeded, blob size: %d\n\n", len(quote_blob))

	der_program_private, request_message, err := tpm2.ConstructClientRequest(rw,
		der_endorsement_cert,
		quote_handle, "", "01020304", "Test-Program-1")
	if err != nil {
		fmt.Printf("err: %s\n")
		t.Fatal("ConstructClientRequest fails")
	}
	fmt.Printf("Request        : %s\n", proto.MarshalTextString(request_message))
	fmt.Printf("Program private: %x\n", der_program_private)
	fmt.Printf("Fix me\n")
	return

	signing_instructions_message := new(tpm2.SigningInstructionsMessage)
	response_message, err := tpm2.ConstructServerResponse(policyKey,
		der_policy_cert,
		*signing_instructions_message, *request_message)
	if err != nil {
		fmt.Printf("err: %s\n", err)
		t.Fatal("ConstructServerResponse fails")
	}

	der_program_cert, err := tpm2.ClientDecodeServerResponse(rw,
		endorsement_handle,
		quote_handle, "01020304", *response_message)
	if err != nil {
		t.Fatal("ClientDecodeServerResponse fails")
	}

	// Save Program cert
	fmt.Printf("Program cert: %x\n", der_program_cert)

	// Close handles
	tpm2.FlushContext(rw, endorsement_handle)
	tpm2.FlushContext(rw, quote_handle)
	rw.Close()
}

