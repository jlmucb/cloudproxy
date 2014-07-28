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
	"crypto/rand"
	"os"
	"testing"
)

func TestEncoding(t *testing.T) {
	ch := CommandHeader{tagRQUCommand, 0, ordOIAP}
	var c uint32 = 137
	in := []interface{}{c}

	b, err := PackWithHeader(ch, in)
	if err != nil {
		t.Fatal("Couldn't pack the bytes:", err)
	}

	var hdr CommandHeader
	var size uint32
	out := []interface{}{&hdr, &size}
	if err := SimpleUnpack(b, out); err != nil {
		t.Fatal("Couldn't unpack the packed bytes")
	}

	if size != 137 {
		t.Fatal("Got the wrong size back")
	}
}

func TestReadPCR(t *testing.T) {
	// Try to read PCR 18. For this to work, you have to have access to
	// /dev/tpm0, and there has to be a TPM driver to answer requests.
	f, err := os.OpenFile("/dev/tpm0", os.O_RDWR, 0600)
	defer f.Close()
	if err != nil {
		t.Fatal("Can't open /dev/tpm0 for read/write:", err)
	}

	res, err := ReadPCR(f, 18)
	if err != nil {
		t.Fatal("Couldn't read PCR 18 from the TPM:", err)
	}

	t.Logf("Got PCR 18 value % x\n", res)
}

func TestPCRMask(t *testing.T) {
	var mask PCRMask
	if err := mask.SetPCR(-1); err == nil {
		t.Fatal("Incorrectly allowed non-existent PCR -1 to be set")
	}

	if err := mask.SetPCR(24); err == nil {
		t.Fatal("Incorrectly allowed non-existent PCR 24 to be set")
	}

	if err := mask.SetPCR(0); err != nil {
		t.Fatal("Couldn't set PCR 0 in the mask:", err)
	}

	set, err := mask.IsPCRSet(0)
	if err != nil {
		t.Fatal("Couldn't check to see if PCR 0 was set:", err)
	}

	if !set {
		t.Fatal("Incorrectly said PCR wasn't set when it should have been")
	}

	if err := mask.SetPCR(18); err != nil {
		t.Fatal("Couldn't set PCR 18 in the mask:", err)
	}

	set, err = mask.IsPCRSet(18)
	if err != nil {
		t.Fatal("Couldn't check to see if PCR 18 was set:", err)
	}

	if !set {
		t.Fatal("Incorrectly said PCR wasn't set when it should have been")
	}
}

func TestFetchPCRValues(t *testing.T) {
	// Try to get 16 bytes of randomness from the TPM.
	f, err := os.OpenFile("/dev/tpm0", os.O_RDWR, 0600)
	defer f.Close()
	if err != nil {
		t.Fatal("Can't open /dev/tpm0 for read/write:", err)
	}

	var mask PCRMask
	if err := mask.SetPCR(17); err != nil {
		t.Fatal("Couldn't set PCR 17:", err)
	}

	if err := mask.SetPCR(18); err != nil {
		t.Fatal("Couldn't set PCR 18:", err)
	}

	pcrs, err := FetchPCRValues(f, mask)
	if err != nil {
		t.Fatal("Couldn't get PCRs 17 and 18:", err)
	}

	comp, err := CreatePCRComposite(mask, pcrs)
	if err != nil {
		t.Fatal("Couldn't create PCR composite")
	}

	if len(comp) != int(DigestSize) {
		t.Fatal("Invalid PCR composite")
	}
}

func TestGetRandom(t *testing.T) {
	// Try to get 16 bytes of randomness from the TPM.
	f, err := os.OpenFile("/dev/tpm0", os.O_RDWR, 0600)
	defer f.Close()
	if err != nil {
		t.Fatal("Can't open /dev/tpm0 for read/write:", err)
	}

	b, err := GetRandom(f, 16)
	if err != nil {
		t.Fatal("Couldn't get 16 bytes of randomness from the TPM:", err)
	}

	t.Logf("Got random bytes % x\n", b)
}

func TestOIAP(t *testing.T) {
	f, err := os.OpenFile("/dev/tpm0", os.O_RDWR, 0600)
	defer f.Close()
	if err != nil {
		t.Fatal("Can't open /dev/tpm0 for read/write:", err)
	}

	// Get auth info from OIAP.
	resp, err := OIAP(f)
	if err != nil {
		t.Fatal("Couldn't run OIAP:", err)
	}

	t.Logf("From OIAP, got AuthHandle %d and NonceEven % x\n", resp.AuthHandle, resp.NonceEven)
}

func TestOSAP(t *testing.T) {
	f, err := os.OpenFile("/dev/tpm0", os.O_RDWR, 0600)
	defer f.Close()
	if err != nil {
		t.Fatal("Can't open /dev/tpm0 for read/write:", err)
	}

	// Try to run OSAP for the SRK.
	osap := OSAPCommand{
		EntityType:  etSRK,
		EntityValue: khSRK,
	}

	if _, err := rand.Read(osap.OddOSAP[:]); err != nil {
		t.Fatal("Couldn't get a random odd OSAP nonce")
	}

	resp, err := OSAP(f, osap)
	if err != nil {
		t.Fatal("Couldn't run OSAP:", err)
	}

	t.Logf("From OSAP, go AuthHandle %d and NonceEven % x and EvenOSAP % x\n", resp.AuthHandle, resp.NonceEven, resp.EvenOSAP)
}
