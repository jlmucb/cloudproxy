// Copyright (c) 2016, Google, Inc. All rights reserved.
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
// File: utility.go

package common;

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"log"
	"math/big"
	"time"

	"github.com/golang/protobuf/proto"
)



func GenerateUserPublicKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func MakeUserKeyStructute(key *ecdsa.PrivateKey, userName string, signerPriv interface{},
		signerCertificate *x509.Certificate) (*KeyData, error) {
	keyData := new(KeyData)
	notBefore := time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)
	serialNumber := new(big.Int).SetInt64(1)
	var subjectPub interface{}
	subjectPub = key.Public()
 	cert, err := CreateKeyCertificate(*serialNumber, "Google", "", "US",
			  signerPriv, signerCertificate, "", userName, "US", subjectPub,
			  notBefore, notAfter,
			  x509.KeyUsageCertSign|x509.KeyUsageKeyAgreement|x509.KeyUsageDigitalSignature)
	if err != nil {
		return nil, err
	}
	keyData.Cert = cert
	keyData.Key = key
	return keyData, nil
}

func SerializeUserKey(key *KeyData) ([]byte, error) {
	keyMessage := new(UserKeyDataMessage)
	keyMessage.Cert = key.Cert
	blob, err := x509.MarshalECPrivateKey(key.Key)
	if err != nil {
		return nil, err
	}
	keyMessage.DerKey = blob
	return proto.Marshal(keyMessage)
}

func ParseUserKey(in []byte) (*KeyData, error) {
	key := new(KeyData)
	keyMessage := new(UserKeyDataMessage)
	err := proto.Unmarshal(in, keyMessage)
	if err != nil {
		return nil, err
	}
	key.Cert = keyMessage.Cert
	key.Key, err = x509.ParseECPrivateKey(keyMessage.DerKey)
	if err != nil {
		return nil, err
	}
	return key, nil
}

// policyKey.SigningKey.GetSigner())
// KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageKeyAgreement | x509.KeyUsageDigitalSignature,

func CreateKeyCertificate(serialNumber big.Int,
			  issuerCommonName string,
			  issuerOrgName string,
			  issuerCountry string,
			  issuerKey interface{},
			  parentCert *x509.Certificate,
			  subjectOrgName string,
			  subjectCommonName string,
			  subjectCountry string,
			  subjectKey interface{},
			  notBefore time.Time,
			  notAfter time.Time,
			  keyUsage x509.KeyUsage) ([]byte, error)  {

	x509SubjectName := &pkix.Name{
		Organization:       []string{subjectOrgName},
		CommonName:         subjectCommonName,
		Country:            []string{subjectCountry},
	}

	x509IssuerName := &pkix.Name{
		Organization:       []string{issuerOrgName},
		CommonName:         issuerCommonName,
		Country:            []string{issuerCountry},
	}

	certificateTemplate := x509.Certificate {
		SerialNumber: &serialNumber,
		Issuer:       *x509IssuerName,
		Subject:      *x509SubjectName,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     keyUsage,
	}

	if parentCert == nil {
		parentCert = &certificateTemplate
	}

	cert, err := x509.CreateCertificate(rand.Reader, &certificateTemplate,
				parentCert, subjectKey, issuerKey)
	if err != nil {
		log.Printf("Can't create certificate. Error: %v\n", err)
		return nil, err
	}
	return cert, err
}

