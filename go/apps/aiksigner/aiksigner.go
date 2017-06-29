// Copyright (c) 2016, Google Inc. All rights reserved.
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
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"github.com/google/go-tpm/tpm"
	"github.com/jlmucb/cloudproxy/go/tao"
	"io/ioutil"
	"log"
	"math/big"
	"time"
)

var aikPath = flag.String("aik_path", "./aikblob", "The path to the AIK blob")
var policyKeyPath = flag.String("policy_key_path", "./policy_keys", "The path to policy key directory")
var pass = flag.String("password", "xxx", "The password protecting the policy keys")
var keyName = flag.String("key_name", "tpm1.2", "The Tao name of the key being certified")
var certFile = flag.String("output_file", "./aik_cert", "The file where the AIK cert is written to")

func main() {
	flag.Parse()
	aikblob, err := ioutil.ReadFile(*aikPath)
	if err != nil {
		log.Fatalln("Error reading AIK blob: ", err)
	}
	aik, err := tpm.UnmarshalRSAPublicKey(aikblob)
	if err != nil {
		log.Fatalln("Error unmarshalling AIK blob: ", err)
	}

	// Sign certificate.
	notBefore := time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	us := "US"
	issuerName := "Google"
	localhost := "localhost"
	x509SubjectName := &pkix.Name{
		Organization:       []string{*keyName},
		OrganizationalUnit: []string{*keyName},
		CommonName:         localhost,
		Country:            []string{us},
	}
	x509IssuerName := &pkix.Name{
		Organization:       []string{issuerName},
		OrganizationalUnit: []string{issuerName},
		CommonName:         localhost,
		Country:            []string{us},
	}

	// issuerName := tao.NewX509Name(&details)
	var sn big.Int
	certificateTemplate := x509.Certificate{
		SerialNumber: &sn,
		Issuer:       *x509IssuerName,
		Subject:      *x509SubjectName,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage: x509.KeyUsageCertSign |
			x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature,
	}

	policyKey, err := tao.NewOnDiskPBEKeys(tao.Signing, []byte(*pass), *policyKeyPath, x509IssuerName)
	if err != nil {
		log.Fatalln("Error loading policy key: ", err)
	}
	if policyKey.Cert == nil {
		log.Fatalln("Missing cert in policy key ")
	}

	cert, err := x509.CreateCertificate(rand.Reader, &certificateTemplate,
		policyKey.Cert, aik, policyKey.SigningKey)
	if err != nil {
		log.Fatalln("Can't create AIK certificate: ", err)
	}
	if err := ioutil.WriteFile(*certFile, cert, 0644); err != nil {
		log.Fatalln("Error writing AIK certificate: ", err)
	}
}
