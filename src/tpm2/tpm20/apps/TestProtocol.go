// Copyright (c) 2015, Google, Inc. All rights reserved.
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
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"flag"
	"fmt"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/src/tpm2/tpm20"
)

// This program runs the cloudproxy protocol.
func main() {
	keySize := flag.Int("modulus size",  2048,
		"Modulus size for keys")
	hashAlg := flag.String("hash algorithm",  "sha1",
		"hash algorithm used")
	permEndorsementHandle := flag.Uint("endorsement handle", 0x810003e8,
		"permenant endorsement handle")
	permQuoteHandle := flag.Uint("quote handle", 0x810003e9,
		"permenant quote handle")
	fileNameEndorsementCert := flag.String("Endorsement cert file",
		"../tmptest/endorsement_cert", "endorsement cert")
	fileNamePolicyCert := flag.String("Policy cert",
		"../tmptest/policy_key_cert", "policy_key_cert")
	fileNamePolicyKey := flag.String("Policy key",
		"../tmptest/cloudproxy_key_file", "policy_key_cert")
	fileNameSigningInstructions := flag.String("Signing instructions",
		"../tmptest/signing_instructions", "signing instructions")
	quoteOwnerPassword := flag.String("Quote owner password", "01020304",
		"quote owner password")
	programName := flag.String("Application program name", "TestProgram",
		"program name")
	flag.Parse()

	fmt.Printf("Endorsement handle: %x, quote handle: %x\n",
		*permEndorsementHandle, *permQuoteHandle)
	fmt.Printf("Endorsement cert file: %s, Policy cert file: %s, Policy key file: %s\n",
		*fileNameEndorsementCert, *fileNamePolicyCert, *fileNamePolicyKey)
	fmt.Printf("Program name: %s, Signing Instructions file: %s\n",
		*programName, *fileNameSigningInstructions)
	fmt.Printf("modulus size: %d,  hash algorithm: %s\n",
		*keySize, *hashAlg)

	// Read Endorsement key info
	derEndorsementCert := tpm.RetrieveFile(*fileNameEndorsementCert)
	if derEndorsementCert == nil {
		fmt.Printf("Can't read endorsement cert\n")
		return
	}
	// Get endorsement public from cert
	endorsement_cert, err := x509.ParseCertificate(derEndorsementCert)
	if err != nil {
		fmt.Printf("Endorsement ParseCertificate fails\n")
		return
	}
	fmt.Printf("Endorsement cert: %x\n", derEndorsementCert)

	// Open tpm
	rw, err := tpm.OpenTPM("/dev/tpm0")
	if err != nil {
		fmt.Printf("OpenTPM failed %s\n", err)
		return
	}
	defer rw.Close()

	// Use the permanent keys.
	protectorHandle := tpm.Handle(*permEndorsementHandle)
	quoteHandle := tpm.Handle(*permQuoteHandle)

	// ReadPublic
	protectorPublicBlob, name, _, err := tpm.ReadPublic(rw, protectorHandle)
	if err != nil {
		fmt.Printf("Can't read protector public\n")
		return
	}
	fmt.Printf("ReadPublic protector succeeded\n")
	fmt.Printf("Public         blob: %x\n", protectorPublicBlob)
	fmt.Printf("Name	   blob: %x\n", name)
	rsaParams, err := tpm.DecodeRsaBuf(protectorPublicBlob)
	if err != nil {
		fmt.Printf("Can't interpret protector public")
		return
	}
	tpm.PrintRsaParams(rsaParams)

	var protectorPublic *rsa.PublicKey
	switch k :=  endorsement_cert.PublicKey.(type) {
	case  *rsa.PublicKey:
		protectorPublic = k
	case  *rsa.PrivateKey:
		protectorPublic = &k.PublicKey
	default:
		fmt.Printf("endorsement cert is not an rsa key\n")
		return
	}
	fmt.Printf("Public key from ReadPublic: %x\n", protectorPublic);

	// Does endorsement cert have the right key?
	if bytes.Compare(protectorPublic.N.Bytes(), rsaParams.Modulus) != 0 {
		fmt.Printf("Endorsement key does not match endorsement cert\n")
		return
	}

	// Read Policy cert
	derPolicyCert := tpm.RetrieveFile(*fileNamePolicyCert)
	if derPolicyCert == nil {
		fmt.Printf("Can't read policy cert\n")
		return
	}

	// Read Policy key
	derPolicyKey := tpm.RetrieveFile(*fileNamePolicyKey)
	if derPolicyKey == nil {
		fmt.Printf("Can't read policy key\n")
		return
	}

	// Parse policy key
/*
	policyPrivateKey, err := x509.ParsePKCS1PrivateKey(derPolicyKey)
	if err != nil {
		fmt.Printf("Can't parse key\n")
		return
	}
	fmt.Printf("Key: %x\n", policyPrivateKey)
 */

	// Read signing instructions
	signingInstructionsIn := tpm.RetrieveFile(*fileNameSigningInstructions)
	if derPolicyKey == nil {
		fmt.Printf("Can't read signing instructions\n")
		return
	}
	signing_instructions_message := new(tpm.SigningInstructionsMessage)
	err = proto.Unmarshal(signingInstructionsIn,
		signing_instructions_message)
	if  err != nil {
		fmt.Printf("Can't unmarshal signing instructions\n", err)
		return
	}
	fmt.Printf("Got signing instructions\n")

	// Protocol
	fmt.Printf("Program name is %s\n",  *programName)
	prog_name := *programName
	clientPrivateKey, request, err := tpm.ConstructClientRequest(rw,
		derEndorsementCert, quoteHandle, "", *quoteOwnerPassword,
		prog_name)
	if err != nil {
		fmt.Printf("ConstructClientRequest failed\n")
		return
	}
	fmt.Printf("Client private key: %x\n", clientPrivateKey)
	fmt.Printf("Request: %s\n", request.String())
/*
	response, err := tpm.ConstructServerResponse(policyPrivateKey,
		*signing_instructions_message, *request)
	if err != nil {
		fmt.Printf("ConstructServerResponse failed\n")
		return
	}
	cert, err := tpm.ClientDecodeServerResponse(rw, protectorHandle,
                quoteHandle, *quoteOwnerPassword, *response)
	if err != nil {
		fmt.Printf("ClientDecodeServerResponse failed\n")
		return
	}

	// Save cert so we can interpret it.
	fmt.Printf("Client cert: %x\n", cert)
 */

	fmt.Printf("Cloudproxy protocol succeeds\n")
	return
}
