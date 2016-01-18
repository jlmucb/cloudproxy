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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/src/tpm2/tpm20"
)

// This program runs the cloudproxy protocol.
func main() {
	filePolicyKeyFileName := flag.String("Policy key file",
		"../tmptest/cloudproxy_key_file.proto", "Policy Key file")
	filePolicyCertFileName := flag.String("Policy cert",
		"../tmptest/policy_key_cert.t", "policy_key_cert")
	domainName := flag.String("Domain name", "test-policy-domain",
		"domain name")
	fileEndorsementCertInFileName := flag.String("Input endorsement cert",
		"../tmptest/endorsement_cert", "endorsement_cert")
	fileEndorsementCertOutFileName := flag.String("Output endorsement cert",
		"../tmptest/endorsement_cert.t", "endorsement_cert.t")
	flag.Parse()

	fmt.Printf("Policy key file: %s, policy cert: %s\n",
		*filePolicyKeyFileName, *filePolicyCertFileName)
	fmt.Printf("Endorsement input file: %s, endorsement output file: %s\n",
		*fileEndorsementCertInFileName, *fileEndorsementCertOutFileName)

	// Read Policy key
	protoPolicyKey := tpm.RetrieveFile(*filePolicyKeyFileName)
	if protoPolicyKey == nil {
		fmt.Printf("Can't read policy key file\n")
		return
	}

	// Parse policy key
	keyMsg := new(tpm.RsaPrivateKeyMessage)
	err := proto.Unmarshal(protoPolicyKey, keyMsg)
	if err != nil {
		fmt.Printf("Can't unmarshal policy key\n")
		return
	}
	policyPrivateKey, err := tpm.UnmarshalRsaPrivateFromProto(keyMsg)
	if err != nil {
		fmt.Printf("Can't decode policy key\n")
		return
	}
	fmt.Printf("Key: %x\n", policyPrivateKey)

	// Sign cert.
	var notBefore time.Time
	notBefore = time.Now()
	validFor := 365*24*time.Hour
	notAfter := notBefore.Add(validFor)
	selfSignTemplate := x509.Certificate{
		SerialNumber:tpm. GetSerialNumber(),
		Subject: pkix.Name {
			Organization: []string{"CloudProxyAuthority"},
			CommonName:   *domainName,
			},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA: true,
	}
	policy_pub := &policyPrivateKey.PublicKey
	der_policy_cert, err := x509.CreateCertificate(rand.Reader, &selfSignTemplate, &selfSignTemplate,
		policy_pub, policyPrivateKey)
	if err != nil {
		fmt.Printf("Can't CreateCertificate ", err, "\n")
	}
	policy_cert, err := x509.ParseCertificate(der_policy_cert)
	if err != nil {
		fmt.Printf("Can't parse policy certificate ", err, "\n")
	}
	fmt.Printf("Program cert bin: %x\n", policy_cert)
	ioutil.WriteFile(*filePolicyCertFileName, der_policy_cert, 0644)

	// Save policy cert.
	fmt.Printf("Policy cert: %x\n\n", der_policy_cert)
	ioutil.WriteFile(*filePolicyCertFileName, der_policy_cert, 0644)

	// Get endorsement and check it
	der_endorsement_cert := tpm.RetrieveFile(*fileEndorsementCertInFileName)
	if der_endorsement_cert == nil {
		fmt.Printf("Can't read Endorsement Cert File\n")
		return
	}
	old_endorse_cert, err := x509.ParseCertificate(der_endorsement_cert)
	if err != nil {
		fmt.Printf("Can't parse endorsement certificate ", err, "\n")
		return
	}
	signeeTemplate := x509.Certificate{
		SerialNumber:tpm. GetSerialNumber(),
		Subject: old_endorse_cert.Subject,
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	// This seems to get the signer public key

	var endorsementPublic *rsa.PublicKey
	switch k :=  old_endorse_cert.PublicKey.(type) {
	case  *rsa.PublicKey:
		endorsementPublic = k
	case  *rsa.PrivateKey:
		endorsementPublic = &k.PublicKey
	default:
		fmt.Printf("endorsement cert is not an rsa key\n")
		return
	}

	new_der_endorsement_cert, err := x509.CreateCertificate(rand.Reader,
		&signeeTemplate, policy_cert, endorsementPublic, policyPrivateKey)
	if err != nil {
		fmt.Printf("Can't CreateCertificate ", err, "\n")
	}
	fmt.Printf("New endorsement cert: %x\n\n", new_der_endorsement_cert)

	// Save endorsement cert.
	fmt.Printf("Policy cert: %x\n\n", der_policy_cert)
	ioutil.WriteFile(*fileEndorsementCertOutFileName, new_der_endorsement_cert, 0644)

	ok, err := tpm.VerifyDerCert(new_der_endorsement_cert, der_policy_cert)
	if ok {
		fmt.Printf("Endorsement cert verifies\n")
	} else {
		fmt.Printf("Endorsement cert does not verify ", err, "\n")
	}

	fmt.Printf("Resign succeeds\n")
	return
}
