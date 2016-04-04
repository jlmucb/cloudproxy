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
	"io/ioutil"
	"time"

	"github.com/jlmucb/cloudproxy/go/tpm2"
)

// This program makes the endorsement certificate given the Policy key.
func main() {
	keySize := flag.Int("modulus size",  2048, "Modulus size for keys")
	keyName := flag.String("Endorsement key name",
		"JohnsHw", "endorsement key name")
	endorsementCertFile := flag.String("Endorsement save file",
		"endorsement.cert.der", "endorsement save file")
	policyCertFile := flag.String("Policy cert file",
		"policy.cert.go.der", "cert file")
	policyKeyFile:= flag.String("Policy key file",  "policy.go.bin",
		"policy save file")
	policyKeyPassword := flag.String("Policy key password",  "xxzzy",
		"policy key password")
	flag.Parse()
	fmt.Printf("Policy key password: %s\n", *policyKeyPassword)

	// TODO
	pcrs := []int{7}

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
		fmt.Printf("Flushall failed\n")
		return
	}

	var notBefore time.Time
	notBefore = time.Now()
	validFor := 365*24*time.Hour
	notAfter := notBefore.Add(validFor)

	serializePolicyKey, err := ioutil.ReadFile(*policyKeyFile)
	if err != nil {
		fmt.Printf("Can't get serialized policy key\n")
		return
	}
	derPolicyCert, err := ioutil.ReadFile(*policyCertFile)
	if err != nil {
		fmt.Printf("Can't get policy cert %s\n", *policyCertFile)
		return
	}

	policyKey, err := tpm2.DeserializeRsaKey(serializePolicyKey)
	if err != nil {
		fmt.Printf("Can't get deserialize policy key\n")
		return
	}

	ekHandle, _, err := tpm2.CreateEndorsement(rw, uint16(*keySize), pcrs)
	if err != nil {
		fmt.Printf("Can't CreateEndorsement\n")
		return
	}
	defer tpm2.FlushContext(rw, ekHandle)
	endorsementCert, err := tpm2.GenerateHWCert(rw, ekHandle,
		*keyName, notBefore, notAfter, tpm2.GetSerialNumber(),
		derPolicyCert, policyKey)
	if err != nil {
		fmt.Printf("Can't create endorsement cert\n")
	}
	fmt.Printf("Endorsement cert: %x\n", endorsementCert)
	ioutil.WriteFile(*endorsementCertFile, endorsementCert, 0644)
	fmt.Printf("Endorsement cert created")
}
