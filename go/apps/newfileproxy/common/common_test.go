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

package common

import (
	// "crypto/ecdsa"
	// "crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"math/big"
	"strconv"
	"testing"
	"time"

	"github.com/jlmucb/cloudproxy/go/apps/newfileproxy/resourcemanager"
)

func TestNonceSignVerify(t *testing.T) {
	privateKey, err := GenerateUserPublicKey()
	if err != nil {
		t.Fatal("Can't generate key")
	}
	keyData, err := MakeUserKeyStructure(privateKey, "TestUser", privateKey, nil)
	if err != nil {
		t.Fatal("Can't get keyData")
	}
	certificate, err := x509.ParseCertificate(keyData.Cert)
	if err != nil {
		t.Fatal("Can't parse certificate")
	}
	var nonce [32]byte
	rand.Read(nonce[:])
	s1, s2, err := SignNonce(nonce[:], privateKey)
	if err != nil {
		t.Fatal("Can't sign nonce")
	}
	if !VerifyNonceSignature(nonce[:], s1, s2, certificate) {
		t.Fatal("Can't verify")
	} else {
		fmt.Printf("Verifies")
	}
}

func TestAuthorization(t *testing.T) {
	serverData := new(ServerData)
	serverData.InitServerData()
	connectionData := new(ServerConnectionData)
	if serverData == nil {
		t.Fatal("TestAuthorization: bad serverData init\n")
	}
	if connectionData == nil {
		t.Fatal("TestAuthorization: bad connectionData init\n")
	}

	// Make up 6 principals
	var p[6] *resourcemanager.PrincipalInfo
	for i := 0; i < 6; i++ {
		userName := "TestUser" + strconv.Itoa(i)
		key, err := GenerateUserPublicKey()
		if err != nil {
			t.Fatal("TestAuthorization: Can't generate public key\n")
		}
		keyData, err:= MakeUserKeyStructure(key, userName, key, nil)
		if err != nil {
			t.Fatal("TestAuthorization: Can't make key structure\n")
		}
		keyData.Certificate, err = x509.ParseCertificate(keyData.Cert)
		if err != nil {
			t.Fatal("TestAuthorization: parse certificate\n")
		}
		p[i] = new(resourcemanager.PrincipalInfo)
		p[i].Name = &userName
		p[i].Cert = keyData.Cert
	}

	// Add three resources
	var r[3] *resourcemanager.ResourceInfo
	for i := 0; i < 3; i++ {
		r[i] = new(resourcemanager.ResourceInfo)
		resourceName := "Resource" + strconv.Itoa(i)
		r[i].Name = &resourceName
		rType := int32(resourcemanager.ResourceType_FILE)
		r[i].Type = &rType
	}

	// Principals 0, 1, 2 are verified; 3, 4, 5 aren't.
	for i := 0; i < 3; i++ {
		connectionData.Principals = append(connectionData.Principals, p[i])
	}

	cp := resourcemanager.MakeCombinedPrincipalFromOne(p[0])
	r[0].Owners = append(r[0].Owners, cp)
	cp = resourcemanager.MakeCombinedPrincipalFromOne(p[5])
	r[1].Owners = append(r[1].Owners, cp)
	cp = resourcemanager.MakeCombinedPrincipalFromTwo(p[0], p[1])
	r[2].Owners = append(r[2].Owners, cp)

	// Test owner authorization
	serviceType := ServiceType(ServiceType_ADDOWNER)
	if (!IsAuthorized(serviceType, serverData, connectionData, r[0])) {
		t.Fatal("TestAuthorization: access to Resource0 doesn't pass but should\n")
	}
	if (IsAuthorized(serviceType, serverData, connectionData, r[1])) {
		t.Fatal("TestAuthorization: access to Resource1 passes but shouldn't\n")
	}
	if (!IsAuthorized(serviceType, serverData, connectionData, r[2])) {
		t.Fatal("TestAuthorization: access to Resource0 doesn't pass but should\n")
	}
}

func TestSignature(t *testing.T) {
	serialNumber := new(big.Int).SetInt64(1)
	userName := "RootKey"
	notBefore := time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	rootKey, err :=  GenerateUserPublicKey()
	if err != nil {
		t.Fatal("TestSignature: Generate root key fails\n");
	}
	signerPriv := interface{}(rootKey)
	subjectPub := interface{}(rootKey.Public())
	rootCert, err := CreateKeyCertificate(*serialNumber, userName, "", "US",
		signerPriv, nil, "", userName, "US", subjectPub,
		notBefore, notAfter, true, x509.KeyUsageCertSign)
	if err != nil {
		t.Fatal("TestSignature: CreateKeyCertificate fails: ", err);
	}
	_ = ioutil.WriteFile("./tmptest/rootCert", rootCert, 0666)
	signerCertificate, err := x509.ParseCertificate(rootCert)
	if err != nil {
		t.Fatal("TestSignature: Can't parse root certificate\n");
	}
	fmt.Printf("Root cert : %x\n", signerCertificate)
	ok, _, err := VerifyCertificateChain(signerCertificate, nil, signerCertificate)
	if !ok {
		t.Fatal("TestSignature: root certificate fails verify: ", err);
	}

	serialNumber.SetInt64(2)
	subjectKey, err :=  GenerateUserPublicKey()
	if err != nil {
		t.Fatal("TestSignature: Generate subject key fails\n");
	}
	subjectPub = interface{}(subjectKey.Public())
	subjectUserName := "SubjectUser"
	subjectCert, err := CreateKeyCertificate(*serialNumber, "Google", "", "US",
		signerPriv, signerCertificate, "", subjectUserName, "US", subjectPub,
		notBefore, notAfter, false,
		x509.KeyUsageCertSign|x509.KeyUsageKeyAgreement|x509.KeyUsageDigitalSignature)
	if err != nil {
		t.Fatal("TestSignature: CreateKeyCertificate fails\n");
	}
	subjectCertificate, err := x509.ParseCertificate(subjectCert)
	if err != nil {
		t.Fatal("TestSignature: Can't parse subject certificate\n");
	}
	ok, _, err = VerifyCertificateChain(signerCertificate, nil, subjectCertificate)
	if !ok {
		t.Fatal("TestSignature: subject certificate fails verify: ", err);
	}
	fmt.Printf("TestSignature succeeds")
}

func TestServices(t *testing.T) {
	fmt.Printf("TestServices succeeds")
}

