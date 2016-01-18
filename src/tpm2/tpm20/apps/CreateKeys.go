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

	"github.com/jlmucb/cloudproxy/src/tpm2/tpm20"
)

// This program creates a key hierarchy consisting of a
// primary key and quoting key for cloudproxy
// and makes their handles permanent.
func main() {
	keySize := flag.Int("modulus size",  2048,
		"Modulus size for keys")
	hashAlg := flag.String("hash algorithm",  "sha1",
		"hash algorithm used")
	primaryHandle := flag.Uint("primary handle", 0x810003e8,
		"permenant primary handle")
	quoteHandle := flag.Uint("quote handle", 0x810003e9,
		"permenant quote handle")
	flag.Parse()

	fmt.Printf("Primary handle: %x, quote handle: %x\n",
		*primaryHandle, *quoteHandle)
	fmt.Printf("modulus size: %d,  hash algorithm: %s\n",
		*keySize, *hashAlg)

	modSize := uint16(*keySize)
	var hash_alg_id uint16
	if *hashAlg == "sha1" {
		hash_alg_id = uint16(tpm.AlgTPM_ALG_SHA1)
	} else if  *hashAlg == "sha256" {
		hash_alg_id = uint16(tpm.AlgTPM_ALG_SHA256)
	} else {
		fmt.Printf("Unsupported Hash algoritm\n")
		return
	}
	fmt.Printf("hash: %x\n", hash_alg_id)

	// Open tpm
	rw, err := tpm.OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}
	defer rw.Close()

	// Flushall
	err =  tpm.Flushall(rw)
	if err != nil {
		fmt.Printf("Flushall failed\n")
		return
	}
	fmt.Printf("rw: %x\n", rw)

	// Remove old permanent handles
	err = tpm.EvictControl(rw, tpm.Handle(tpm.OrdTPM_RH_OWNER), tpm.Handle(*primaryHandle),
			tpm.Handle(*primaryHandle))
	if err != nil {
		fmt.Printf("Evict existing permanant primary handle failed\n")
	}
	err = tpm.EvictControl(rw, tpm.Handle(tpm.OrdTPM_RH_OWNER), tpm.Handle(*quoteHandle),
		tpm.Handle(*quoteHandle))
	if err != nil {
		fmt.Printf("Evict existing permanant quote handle failed\n")
	}

	// CreatePrimary
	var empty []byte
	primaryparms := tpm.RsaParams{uint16(tpm.AlgTPM_ALG_RSA), uint16(tpm.AlgTPM_ALG_SHA1),
		uint32(0x00030072), empty, uint16(tpm.AlgTPM_ALG_AES), uint16(128),
		uint16(tpm.AlgTPM_ALG_CFB), uint16(tpm.AlgTPM_ALG_NULL),
		uint16(0), modSize, uint32(0x00010001), empty}
	tmpPrimaryHandle, public_blob, err := tpm.CreatePrimary(rw,
		uint32(tpm.OrdTPM_RH_OWNER), []int{0x7}, "", "01020304", primaryparms)
	if err != nil {
		fmt.Printf("CreatePrimary fails\n")
		return
	}
	fmt.Printf("CreatePrimary succeeded\n")

	// CreateKey (Quote Key)
	keyparms := tpm.RsaParams{uint16(tpm.AlgTPM_ALG_RSA), uint16(tpm.AlgTPM_ALG_SHA1),
		uint32(0x00050072), empty, uint16(tpm.AlgTPM_ALG_NULL), uint16(0),
		uint16(tpm.AlgTPM_ALG_ECB), uint16(tpm.AlgTPM_ALG_RSASSA),
		uint16(tpm.AlgTPM_ALG_SHA1),
		uint16(1024), uint32(0x00010001), empty}
	private_blob, public_blob, err := tpm.CreateKey(rw,
		uint32(tmpPrimaryHandle), []int{7}, "01020304", "01020304", keyparms)
	if err != nil {
		fmt.Printf("CreateKey (Quote) fails ", err, "\n")
		return
	}
	fmt.Printf("CreateKey (Quote) succeeded\n")

	// Load
	tmpQuoteHandle, _, err := tpm.Load(rw, tmpPrimaryHandle, "", "01020304",
	     public_blob, private_blob)
	if err != nil {
		fmt.Printf("Load fails ", err, "\n")
		return
	}
	fmt.Printf("Load succeeded %d\n", tmpQuoteHandle)

	// Install new handles
	err = tpm.EvictControl(rw, tpm.Handle(tpm.OrdTPM_RH_OWNER), tmpPrimaryHandle,
			tpm.Handle(*primaryHandle))
	if err != nil {
		tpm.FlushContext(rw, tmpPrimaryHandle)
		tpm.FlushContext(rw, tmpQuoteHandle)
		fmt.Printf("Install new primary handle failed\n")
		return
	}
	fmt.Printf("Install new primary handle succeeded\n")
	err = tpm.EvictControl(rw, tpm.Handle(tpm.OrdTPM_RH_OWNER), tmpQuoteHandle,
			tpm.Handle(*quoteHandle))
	if err != nil {
		tpm.FlushContext(rw, tmpQuoteHandle)
		fmt.Printf("Install new quote handle failed\n")
		return
	}
	fmt.Printf("Install new quote handle succeeded\n")
	return
}