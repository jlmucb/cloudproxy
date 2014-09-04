// Copyright (c) 2014, Google Inc.  All rights reserved.
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

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpm"
)

var pcr = flag.Int("pcr", 17, "The PCR to return")
var tpmFile = flag.String("tpm", "/dev/tpm0", "The TPM device to query")

func main() {
	flag.Parse()

	f, err := os.OpenFile("/dev/tpm0", os.O_RDWR, 0600)
	defer f.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Can't open %s for read/write: %s\n", *tpmFile, err)
		return
	}

	res, err := tpm.ReadPCR(f, uint32(*pcr))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't read PCR %d from TPM %s: %s\n", *pcr, *tpmFile, err)
		return
	}

	fmt.Printf("%x", res)
	return
}
