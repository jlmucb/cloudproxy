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

package resourcemanager;

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"testing"
	"time"
)

func TestTimeEncode(t *testing.T) {
	now := time.Now()
	s, err := EncodeTime(now)
	if err != nil {
		t.Fatal("EncodeTime fails\n")
	}
	fmt.Printf("Encoded time: %s\n", s)
	tt, err := DecodeTime(s)
	if err != nil {
		t.Fatal("DecodeTime fails\n")
	}
	if !now.Equal(*tt) {
		t.Fatal("TestTimeEncode not equal\n")
	}
	fmt.Printf("TestTimeEncode succeeds")
}

func TestTableFunctions(t *testing.T) {

	// Generate Certificates and keys for test.
	notBefore := time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	serialNumber := new(big.Int).SetInt64(1)

	policyKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("TestTableFunctions: ecdsa.GenerateKey fails\n")
	}
	var policyPriv interface{}
        var policyPub interface{}
        policyPriv = policyKey
        policyPub = policyKey.Public()
	policyCert, err := CreateKeyCertificate(*serialNumber, "Google", "Google",
				"US", policyPriv, nil, "", "TestPolicyCert", "US",
				policyPub, notBefore, notAfter,
				x509.KeyUsageCertSign | x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature)
	if err != nil {
		t.Fatal("TestTableFunctions: CreateKeyCertificate fails\n")
	}
	policyCertificate, err := x509.ParseCertificate(policyCert)
	if err != nil {
		t.Fatal("TestTableFunctions: ParseCertificate fails\n")
	}
	fmt.Printf("\nPolicyCert: %x\n", policyCert)

	programKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("TestTableFunctions: ecdsa.GenerateKey fails\n")
	}
        var programPub interface{}
	programPub = programKey.Public()
	programCert, err := CreateKeyCertificate(*serialNumber, "Google", "Google",
				"US", policyPriv, policyCertificate, "", "TestProgramCert", "US",
				programPub, notBefore, notAfter,
				x509.KeyUsageCertSign | x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature)
	if err != nil {
		t.Fatal("TestTableFunctions: CreateKeyCertificate fails\n")
	}
	fmt.Printf("\nProgramCert: %x\n", programCert)

	userKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("TestTableFunctions: ecdsa.GenerateKey fails\n")
	}
        var userPub interface{}
	userPub = userKey.Public()
	userCert, err := CreateKeyCertificate(*serialNumber, "Google", "Google",
				"US", policyKey, policyCertificate, "", "TestPolicyCert", "US",
				userPub, notBefore, notAfter,
				x509.KeyUsageCertSign | x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature)
	if err != nil {
		t.Fatal("TestTableFunctions: CreateKeyCertificate fails\n")
	}
	fmt.Printf("\nUserCert: %x\n", userCert)

/*
	a := new(PrincipalInfo)
	b := new(ResourceInfo)
	c := new(ResourceMasterInfo)

	PrintPrincipalList(pl []CombinedPrincipal)
 */
}

func TestResourceInfo(t *testing.T) {
	return
}
