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

package resourcemanager

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/jlmucb/cloudproxy/go/apps/newfileproxy/common"
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

func StringIntoPointer(s1 string) *string {
	return &s1
}

func IntIntoPointer(i1 int) *int32 {
	i := int32(i1)
	return &i
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
	policyCert, err := common.CreateKeyCertificate(*serialNumber, "Google", "Google",
		"US", policyPriv, nil, "", "TestPolicyCert", "US",
		policyPub, notBefore, notAfter,
		x509.KeyUsageCertSign|x509.KeyUsageKeyAgreement|x509.KeyUsageDigitalSignature)
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
	programCert, err := common.CreateKeyCertificate(*serialNumber, "Google", "Google",
		"US", policyPriv, policyCertificate, "", "TestProgramCert", "US",
		programPub, notBefore, notAfter,
		x509.KeyUsageCertSign|x509.KeyUsageKeyAgreement|x509.KeyUsageDigitalSignature)
	if err != nil {
		t.Fatal("TestTableFunctions: CreateKeyCertificate fails\n")
	}
	fmt.Printf("\nProgramCert: %x\n", programCert)

	user1Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("TestTableFunctions: ecdsa.GenerateKey fails\n")
	}
	var user1Pub interface{}
	user1Pub = user1Key.Public()
	user1Cert, err := common.CreateKeyCertificate(*serialNumber, "Google", "Google",
		"US", policyKey, policyCertificate, "", "TestUserCert1", "US",
		user1Pub, notBefore, notAfter,
		x509.KeyUsageCertSign|x509.KeyUsageKeyAgreement|x509.KeyUsageDigitalSignature)
	if err != nil {
		t.Fatal("TestTableFunctions: CreateKeyCertificate fails\n")
	}
	fmt.Printf("\nUserCert 1: %x\n", user1Cert)

	user2Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal("TestTableFunctions: ecdsa.GenerateKey fails\n")
	}
	var user2Pub interface{}
	user2Pub = user2Key.Public()
	user2Cert, err := common.CreateKeyCertificate(*serialNumber, "Google", "Google",
		"US", policyKey, policyCertificate, "", "TestUserCert2", "US",
		user2Pub, notBefore, notAfter,
		x509.KeyUsageCertSign|x509.KeyUsageKeyAgreement|x509.KeyUsageDigitalSignature)
	if err != nil {
		t.Fatal("TestTableFunctions: CreateKeyCertificate fails\n")
	}
	fmt.Printf("\nUserCert 2: %x\n", user2Cert)

	programPrincipal := new(PrincipalInfo)
	user1Principal := new(PrincipalInfo)
	user2Principal := new(PrincipalInfo)

	programPrincipal.Name = StringIntoPointer("TestProgramCert")
	programPrincipal.Cert = programCert
	user1Principal.Name = StringIntoPointer("TestUser1Cert")
	user1Principal.Cert = user1Cert
	user2Principal.Name = StringIntoPointer("TestUser2Cert")
	user2Principal.Cert = user2Cert

	resourceMaster := new(ResourceMasterInfo)
	resourceMaster.ServiceName = StringIntoPointer("TestService")
	resourceMaster.PolicyCert = policyCert
	resourceMaster.BaseDirectoryName = StringIntoPointer("./tmptest")

	cp1 := MakeCombinedPrincipal(programPrincipal, user1Principal)
	cp2 := MakeCombinedPrincipal(programPrincipal, user2Principal)
	if cp1 == nil || cp2 == nil {
		t.Fatal("Can't make combined principal")
	}

	str_time1, err := EncodeTime(time.Now())
	if err != nil {
		t.Fatal("Can't EncodeTime")
	}
	str_time2, err := EncodeTime(time.Now())
	if err != nil {
		t.Fatal("Can't EncodeTime")
	}

	// Resource 1
	res1 := new(ResourceInfo)
	res1.Name = StringIntoPointer("TestFile1")
	res1.Type = IntIntoPointer(int(ResourceType_FILE))
	res1.DateCreated = &str_time1
	res1.DateModified = &str_time1
	res1.Size = IntIntoPointer(0)
	res1.Keys = nil
	err = res1.AddOwner(*cp1)
	if err != nil {
		t.Fatal("AddOwner fails")
	}
	err = res1.AddReader(*cp2)
	if err != nil {
		t.Fatal("AddReader fails")
	}
	err = res1.AddWriter(*cp2)
	if err != nil {
		t.Fatal("AddWriter fails")
	}

	err = resourceMaster.InsertResource(res1)
	if err != nil {
		t.Fatal("InsertResource fails")
	}

	// Resource 2
	res2 := new(ResourceInfo)
	res2.Name = StringIntoPointer("TestFile2")
	res2.Type = IntIntoPointer(int(ResourceType_FILE))
	res2.DateCreated = &str_time1
	res2.DateModified = &str_time2
	res2.Size = IntIntoPointer(0)
	res2.Keys = nil
	err = res2.AddOwner(*cp2)
	if err != nil {
		t.Fatal("AddOwner fails")
	}
	err = res2.AddReader(*cp1)
	if err != nil {
		t.Fatal("AddReader fails")
	}
	err = res2.AddWriter(*cp1)
	if err != nil {
		t.Fatal("AddWriter fails")
	}
	err = res2.AddReader(*cp2)
	if err != nil {
		t.Fatal("AddReader fails")
	}
	err = res2.AddWriter(*cp2)
	if err != nil {
		t.Fatal("AddReader fails")
	}

	err = resourceMaster.InsertResource(res2)
	if err != nil {
		t.Fatal("InsertResource fails")
	}

	fmt.Printf("\nReaders list: \n")
	PrintPrincipalList(res2.Readers)

	n := FindCombinedPrincipalPosition(*cp2, res2.Readers)
	if n < 0 {
		t.Fatal("FindCombinedPrincipalPosition fails")
	}
	x := resourceMaster.FindResource("TestFile1")
	if x == nil {
		t.Fatal("resourceMaster.FindResource TestFile1 fails")
	}
	fmt.Printf("\n")
	x.PrintResource(*resourceMaster.BaseDirectoryName, true)

	fmt.Printf("\n")
	y := resourceMaster.FindResource("TestFile2")
	if y == nil {
		t.Fatal("resourceMaster.FindResource TestFile2 fails")
	}

	fileContents1 := []byte{1, 3, 5}
	fileContents2 := []byte{2, 4, 6}
	err = res1.Write(*resourceMaster.BaseDirectoryName, fileContents1)
	if err != nil {
		t.Fatal("res1.Write fails")
	}
	err = res2.Write(*resourceMaster.BaseDirectoryName, fileContents2)
	if err != nil {
		t.Fatal("res2.Write fails")
	}
	out1, err := res1.Read(*resourceMaster.BaseDirectoryName)
	if err != nil {
		t.Fatal("res1.Read fails")
	}
	fmt.Printf("out1: %x\n", out1)
	out2, err := res2.Read(*resourceMaster.BaseDirectoryName)
	if err != nil {
		t.Fatal("res2.Read fails")
	}
	fmt.Printf("out2: %x\n", out2)
	fmt.Printf("\n")
	if !res1.IsOwner(*cp1) {
		t.Fatal("res1.IsOwnwer fails")
	}
	if res1.IsOwner(*cp2) {
		t.Fatal("res1.IsOwnwer succeeds")
	}
	// TODO(jlm): consider removing
	fmt.Printf("\n")
	res1.PrintResource(*resourceMaster.BaseDirectoryName, true)
	fmt.Printf("\n")
	res2.PrintResource(*resourceMaster.BaseDirectoryName, true)
}

func TestResourceInfo(t *testing.T) {
	return
}
