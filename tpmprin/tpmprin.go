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
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/go-tpm/tpm"
	"github.com/jlmucb/cloudproxy/tao/auth"
)

var aikFile = flag.String("aikblob", "aikblob", "A file containing a TPM AIK")

func main() {
	flag.Parse()
	aikblob, err := ioutil.ReadFile(*aikFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't read the aik file %s: %s\n", *aikFile, err)
		return
	}

	v, err := tpm.UnmarshalRSAPublicKey(aikblob)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't unmarshal the AIK: %s\n", err)
		return
	}

	aik, err := x509.MarshalPKIXPublicKey(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Couldn't marshal the AIK into PKIX: %s\n", err)
		return
	}

	name := auth.Prin{
		Type: "tpm",
		Key:  auth.Bytes(aik),
	}
	fmt.Printf("%v", name)
}
