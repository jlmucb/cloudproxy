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
// File: utility.go

package resourcemanager;

import (
	// "crypto/aes"
	// "crypto/cipher"
	// "crypto/hmac"
	"crypto/rand"
	// "crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	// "errors"
	// "fmt"
	"log"
	"math/big"
	"time"

	// "github.com/jlmucb/cloudproxy/go/tao"
	// "github.com/jlmucb/cloudproxy/go/tao/auth"
	// "github.com/jlmucb/cloudproxy/go/util"
)

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

