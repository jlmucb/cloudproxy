// Copyright (c) 2014, Google, Inc. All rights reserved.
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
//

package main

import (
	"flag"
	"fmt"

	// "github.com/jlmucb/cloudproxy/src/tpm2/tpm20"
)

// This program creates a key hierarchy consisting of the
// endorsement key, sealing key and quoting key for cloudproxy
// and makes their handles permanent.
func main() {
	keySize := flag.Int("modulus size",  2048,
		"Modulus size for keys")
	hashAlg := flag.String("hash algorithm",  "sha1",
		"hash algorithm used")
	endorsementHandle := flag.Uint("endorsement handle", 0x810003e8,
		"permenant endorsement handle")
	sealHandle := flag.Uint("seal handle", 0x810003e9,
		"permenant seal handle")
	quoteHandle := flag.Uint("quote handle", 0x810003ea,
		"permenant quote handle")
	flag.Parse()

	fmt.Printf("Endorsement handle: %x, Seal handle: %x, quote handle: %x\n",
		*endorsementHandle, *sealHandle, *quoteHandle)
	fmt.Printf("modulus size: %d,  hash algorithm: %s\n",
		*keySize, *hashAlg)

/*
	var hash_alg_id uint16
	if *hashAlg == "sha1" {
		hash_alg_id := uint16(tpm.algTPM_ALG_SHA1)
	} else if  *hashAlg == "sha256" {
		hash_alg_id := uint16(tpm.algTPM_ALG_SHA256)
	} else {
		fmt.Printf("Unsupported Hash algoritm\n")
		return
	}

	// Open tpm
	rw, err := tpm.OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}

	// Flushall
	err =  tpm.Flushall(rw)
	if err != nil {
		fmt.Printf("Flushall failed\n")
		return
	}

	// CreatePrimary
	var empty []byte
	primaryparms := tpm.RsaParams{uint16(algTPM_ALG_RSA), uint16(algTPM_ALG_SHA1),
		uint32(0x00030072), empty, uint16(algTPM_ALG_AES), uint16(128),
		uint16(algTPM_ALG_CFB), uint16(algTPM_ALG_NULL), uint16(0),
		uint16(2048), uint32(0x00010001), empty}
	parent_handle, public_blob, err := CreatePrimary(rw,
		uint32(ordTPM_RH_OWNER), []int{0x7}, "", "", primaryparms)
	if err != nil {
		fmt.Printf("CreatePrimary fails")
		return
	}
	fmt.Printf("CreatePrimary succeeded\n")
	endorseParams, err := tpmDecodeRsaArea(public_blob)
	if err != nil {
		t.Fatal("DecodeRsaBuf fails", err)
	}

	// CreateKey
	keyparms := tpmRsaParams{uint16(algTPM_ALG_RSA), uint16(algTPM_ALG_SHA1),
		uint32(0x00030072), empty, uint16(algTPM_ALG_AES), uint16(128),
		uint16(algTPM_ALG_CFB), uint16(algTPM_ALG_NULL), uint16(0),
		uint16(2048), uint32(0x00010001), empty}
	private_blob, public_blob, err := CreateKey(rw, uint32(parent_handle),
		[]int{7}, "", "01020304", keyparms)
	if err != nil {
		t.Fatal("CreateKey fails")
	}
	fmt.Printf("CreateKey succeeded\n")

	// Load
	key_handle, _, err := tpm.Load(rw, parent_handle, "", "",
	     public_blob, private_blob)
	if err != nil {
		t.Fatal("Load fails")
	}
	fmt.Printf("Load succeeded\n")

	// ReadPublic
	_, name, _, err := tpm.ReadPublic(rw, key_handle)
	if err != nil {
		fmt.Printf("ReadPublic fails")
	}
	fmt.Printf("ReadPublic succeeded\n")
 */
	return
}
