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

	//"github.com/jlmucb/cloudproxy/src/tpm2/tpm20"
)

// This program runs the cloudproxy protocol.
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

}
