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

package tpm

import (
	"fmt"
	"testing"
)

// Test GetRandom
func TestGetRandom(t *testing.T) {
	fmt.Printf("TestGetRandom\n")

	// Open TPM
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return 
	}

	rand, err :=  GetRandom(rw, 16)
	if err != nil {
		fmt.Printf("Error: %s\n", err)
		t.Fatal("GetRandom failed\n")
	}
	fmt.Printf("rand: %x\n", rand)
}

// TestReadPcr tests a ReadPcr command.
func TestReadPcrs(t *testing.T) {
	fmt.Printf("TestReadPcrs\n")

	// Open TPM
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return 
	}

	pcr := []byte{0x03, 0x80, 0x00, 0x00}
	counter, pcr_out, alg, digest, err := ReadPcrs(rw, byte(4), pcr)
	if err != nil {
		t.Fatal("ConstructReadPcrs failed\n")
	}
	fmt.Printf("Counter: %x, pcr: %x, alg: %x, digest: %x\n", counter, pcr_out, alg, digest)
}

// TestReadClock tests a ReadClock command.
func TestReadClock(t *testing.T) {
}

// TestGetCapabilities tests a GetCapabilities command.
// Command: 8001000000160000017a000000018000000000000014
func TestGetCapabilities(t *testing.T) {
}

func TestLoadKey(t *testing.T) {
}

// TestCreatePrimary tests a CreatePrimary command.
func TestCreatePrimary(t *testing.T) {
	fmt.Printf("TestCreatePrimary\n")

	// Open TPM
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return 
	}

	var empty []byte
	parms := RsaParams{uint16(algTPM_ALG_RSA), uint16(algTPM_ALG_SHA1),
		uint32(0x00030072), empty, uint16(algTPM_ALG_AES), uint16(128),
		uint16(algTPM_ALG_CFB), uint16(algTPM_ALG_NULL), uint16(0),
		uint16(1024), uint32(0x00010001), empty}
	handle, blob, err := CreatePrimary(rw, uint32(ordTPM_RH_OWNER), []int{7},
						 "", "01020304", parms)
	if err != nil {
		t.Fatal("ConstructCreatePrimary fails")
	}
        fmt.Printf("Handle : %x\nblob: %x", handle, blob)
	_ = FlushContext(rw, handle)
}

// TestPolicyPassword tests a PolicyPassword command.
func TestPolicyPassword(t *testing.T) {
}

// TestPolicyGetDigest tests a PolicyGetDigest command.
func TestPolicyGetDigest(t *testing.T) {
}

// TestStartAuthSession tests a StartAuthSession command.
func TestStartAuthSession(t *testing.T) {
}

// CreateKey
func TestCreateKey(t *testing.T) {
	fmt.Printf("TestCreateKey\n")

	// Open TPM
	rw, err := OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}

	var empty []byte
	parms := RsaParams{uint16(algTPM_ALG_RSA), uint16(algTPM_ALG_SHA1),
		uint32(0x00030072), empty, uint16(algTPM_ALG_AES), uint16(128),
		uint16(algTPM_ALG_CFB), uint16(algTPM_ALG_NULL), uint16(0),
		uint16(1024), uint32(0x00010001), empty}
	private_blob, public_blob, err := CreateKey(rw, uint32(ordTPM_RH_OWNER), []int{7},
						    "", "01020304", parms)
	if err != nil {
		t.Fatal("ConstructCreatePrimary fails")
	}
	fmt.Printf("\nPrivate blob: %x\n", private_blob)
	fmt.Printf("\nPublic  blob: %x\n", public_blob)
}

// TestUnseal tests a Unseal command.
func TestUnseal(t *testing.T) {
}

// TestQuote tests a Quote command.
func TestQuote(t *testing.T) {
}

func TestActivateCredential(t *testing.T) {
}

// TestEvictControl tests a EvictControl command.
func TestEvictControl(t *testing.T) {
}

// Combined Key Test
func TestCombinedKeyTest(t *testing.T) {
	// Open tpm
	rw, err := OpenTPM("dev/tpm0")
        if err != nil {
                return
        }

	var empty []byte
	parms := RsaParams{uint16(algTPM_ALG_RSA), uint16(algTPM_ALG_SHA1),
                uint32(0x00030072), empty, uint16(algTPM_ALG_AES), uint16(128),
                uint16(algTPM_ALG_CFB), uint16(algTPM_ALG_NULL), uint16(0),
                uint16(1024), uint32(0x00010001), empty}
	// CreatePrimary
	parent_handle, public_blob, err := CreatePrimary(rw,
		uint32(ordTPM_RH_OWNER), []int{0x7}, "", "01020304", parms)
        if err != nil {
                t.Fatal("CreatePrimary fails")
        }
	// CreateKey
	 private_blob, public_blob, err := CreateKey(rw, uint32(ordTPM_RH_OWNER),
		[]int{7}, "", "01020304", parms)
        if err != nil {
                t.Fatal("CreateKey fails")
        }
        fmt.Printf("\nPrivate blob: %x\n", private_blob)
        fmt.Printf("\nPublic  blob: %x\n", public_blob)
	// Load
	key_handle, blob, err := Load(rw, parent_handle, "", "01020304",
             public_blob, private_blob)
        if err != nil {
                t.Fatal("Load fails")
        }
        fmt.Printf("\nBlob from Load     : %x\n", blob)
	// ReadPublic
	public, name, qualified_name, err := ReadPublic(rw, key_handle)
        if err != nil {
                t.Fatal("ReadPublic fails")
        }
        fmt.Printf("\nPublic         blob: %x\n", public)
        fmt.Printf("\nName           blob: %x\n", name)
        fmt.Printf("\nQualified name blob: %x\n", qualified_name)
	// Flush
	err = FlushContext(rw, key_handle)
	err = FlushContext(rw, parent_handle)
}

// Combined Seal test
func TestCombinedSealTest(t *testing.T) {
	// Init pcr's
	// CreatePrimary
	// StartAuthSession
	// PolicyGetDigest
	// PolicyPassword
	// PolicyPcr
	// PolicyGetDigest
	// CreateSealed
	// Load
	// Unseal
	// Flush
}

// Combined Quote test
func TestCombinedQuoteTest(t *testing.T) {
	// CreatePrimary
	// PCR_Event
	// CreateKey
	// Quote
	// Verify quote
	// Flush
}

// Combined Evict test
func TestCombinedEvictTest(t *testing.T) {
	// CreatePrimary
	// CreateKey
	// Load
	// Evict
	// Evict
	// Flush
}

// Combined Endorsementtest
func TestCombinedEndorsementTest(t *testing.T) {
	// Set pcr's
	// CreatePrimary
	// ReadPublic
	// CreateKey
	// Load
	// Construct credential
	// MakeCredential
	// ActivateCredential
	// Flush
}

// Combined Context test
func TestCombinedContextTest(t *testing.T) {
	// pcr selections
	//CreatePrimary
	// SaveContext
	// FlushContext
	// LoadContext
	// FlushContext

}

// Combined Quote Protocol
func TestCombinedQuoteProtocolTest(t *testing.T) {
	// pcr selections
}


