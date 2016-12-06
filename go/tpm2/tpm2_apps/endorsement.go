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

package tpm2_apps

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tpm2"
)

func HandleEndorsement(keySize int, keyName, endorsementCertFile, policyCertFile,
	policyKeyFile, policyKeyPassword, policyKeyDir string, policyKeyIsEcdsa bool) error {
	// TODO(jlm): Should this be the pcr's measured by the tpm (17, 18) or should it be empty?
	// In any case, {7} is wrong.
	pcrs := []int{17, 18}

	// Open tpm
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		return fmt.Errorf("OpenTPM failed: %s", err)
	}
	defer rw.Close()

	// Flushall
	err = tpm2.Flushall(rw)
	if err != nil {
		return fmt.Errorf("Flushall failed: %s", err)
	}

	// TODO(jlm): Currently a year.  This should be specified in a flag witht the
	//	default being a year.
	var notBefore time.Time
	notBefore = time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	ekHandle, _, err := tpm2.CreateEndorsement(rw, uint16(keySize), pcrs)
	if err != nil {
		fmt.Errorf("Can't CreateEndorsement: %s", err)
	}
	defer tpm2.FlushContext(rw, ekHandle)

	var endorsementCert []byte
	if policyKeyIsEcdsa {
		// Load keys from policyKeyDir if keys are present there.
		policyKey, err := tao.NewOnDiskPBEKeys(tao.Signing, []byte(policyKeyPassword), policyKeyDir, nil)
		if err != nil {
			return fmt.Errorf("Error in getting policy cert: %s", err)
		}
		if policyKey.Cert == nil {
			return fmt.Errorf("Missing cert in policy key: %s", err)
		}
		hwPublic, err := tpm2.GetRsaKeyFromHandle(rw, ekHandle)
		if err != nil {
			return fmt.Errorf("Can't get endorsement public key: %s", err)
		}
		// TODO(sidtelang): move this to tpm2/support.go
		serialNumber := tpm2.GetSerialNumber()
		fmt.Printf("Serial: %x\n", serialNumber)
		fmt.Printf("notBefore: %s, notAfter: %s\n", notBefore, notAfter)
		signTemplate := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization: []string{keyName},
				CommonName:   keyName,
			},
			NotBefore:             notBefore,
			NotAfter:              notAfter,
			KeyUsage:              x509.KeyUsageCertSign,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
			// IsCA: false,
			IsCA: true,
		}
		endorsementCert, err = x509.CreateCertificate(rand.Reader, &signTemplate, policyKey.Cert,
			hwPublic, policyKey.SigningKey.GetSigner())
		if err != nil {
			return fmt.Errorf("Can't create endorsement certificate: %s", err)
		}
	} else {
		serializePolicyKey, err := ioutil.ReadFile(policyKeyFile)
		if err != nil {
			return fmt.Errorf("Can't get serialized policy key: %s", err)
		}
		derPolicyCert, err := ioutil.ReadFile(policyCertFile)
		if err != nil {
			return fmt.Errorf("Can't get policy cert: %s", err)
		}

		policyKey, err := tpm2.DeserializeRsaKey(serializePolicyKey)
		if err != nil {
			return fmt.Errorf("Can't get deserialize policy key: %s", err)
		}
		endorsementCert, err = tpm2.GenerateHWCert(rw, ekHandle,
			keyName, notBefore, notAfter, tpm2.GetSerialNumber(),
			derPolicyCert, policyKey)
		if err != nil {
			return fmt.Errorf("Can't create endorsement cert: %s", err)
		}
	}
	fmt.Printf("Endorsement cert: %x\n", endorsementCert)
	ioutil.WriteFile(endorsementCertFile, endorsementCert, 0644)
	fmt.Printf("Endorsement cert created")
	return nil
}
