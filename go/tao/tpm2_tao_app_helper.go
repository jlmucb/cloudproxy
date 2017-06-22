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

package tao

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"time"

	"github.com/jlmucb/cloudproxy/go/tpm2"
	"github.com/jlmucb/cloudproxy/go/util"
)

func HandleEndorsement(keySize int, keyName, endorsementCertFile, policyCertFile,
	policyKeyFile, policyKeyPassword, policyKeyDir string, policyKeyIsEcdsa bool) error {
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
		return fmt.Errorf("Can't CreateEndorsement: %s", err)
	}
	defer tpm2.FlushContext(rw, ekHandle)

	var endorsementCert []byte
	if policyKeyIsEcdsa {
		// Load keys from policyKeyDir if keys are present there.
		policyKey, err := NewOnDiskPBEKeys(Signing, []byte(policyKeyPassword), policyKeyDir, nil)
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
			hwPublic, policyKey.SigningKey.GetSignerPrivateKey())
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

func HandlePolicyKey(keySize int, policyKeyFile, policyKeyPassword, policyCertFile string) error {
	// Open tpm
	rw, err := tpm2.OpenTPM("/dev/tpm0")
	if err != nil {
		return fmt.Errorf("OpenTPM failed %s", err)
	}
	defer rw.Close()

	// Flushall
	err = tpm2.Flushall(rw)
	if err != nil {
		return fmt.Errorf("Flushall failed: %s", err)
	}
	var notBefore time.Time
	notBefore = time.Now()
	validFor := 365 * 24 * time.Hour
	notAfter := notBefore.Add(validFor)

	policyKey, err := rsa.GenerateKey(rand.Reader, keySize)
	if err != nil {
		return fmt.Errorf("Can't generate policy key: %s", err)
	}
	fmt.Printf("policyKey: %x\n", policyKey)

	derPolicyCert, err := tpm2.GenerateSelfSignedCertFromKey(policyKey,
		"Cloudproxy Authority", "Application Policy Key",
		tpm2.GetSerialNumber(), notBefore, notAfter)
	fmt.Printf("policyKey: %x\n", policyKey)
	ioutil.WriteFile(policyCertFile, derPolicyCert, 0644)
	if err != nil {
		return fmt.Errorf("Can't write policy cert: %s", err)
	}

	// Marshal policy key
	serializedPolicyKey, err := tpm2.SerializeRsaPrivateKey(policyKey)
	if err != nil {
		return fmt.Errorf("Cant serialize rsa key: %s", err)
	}

	ioutil.WriteFile(policyKeyFile, serializedPolicyKey, 0644)
	if err != nil {
		return fmt.Errorf("Policy Key generation failed: %s", err)
	}
	fmt.Printf("Policy Key generation succeeded, password: %s\n",
		policyKeyPassword)

	return nil
}

// TODO: probably receive a kill channel to kill this function..
func HandleQuote(network, addr, pass, path string, details X509Details) error {
	ln, err := net.Listen(network, addr)
	if err != nil {
		log.Fatalln("Quote server: could not listen at port:", err)
	}

	// Generate/Load policy key
	policyKey, err := NewOnDiskPBEKeys(Signing, []byte(pass), path,
		NewX509Name(&details))
	if err != nil {
		return fmt.Errorf("Error loading policy key: %s", err)
	}
	if policyKey.Cert == nil || policyKey.Cert.Raw == nil {
		log.Fatalln("Quote server: cert missing in policy key.")
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			return fmt.Errorf("Quote server: could not accept connection: %s", err)
		}
		ms := util.NewMessageStream(conn)
		var request tpm2.AttestCertRequest
		if err := ms.ReadMessage(&request); err != nil {
			log.Printf("Quote server: Couldn't read request from channel: %s\n", err)
			continue
		}
		// FIX
		response, err := tpm2.ProcessQuoteDomainRequest(request,
			(policyKey.SigningKey.GetSignerPrivateKey()).(*ecdsa.PrivateKey), policyKey.Cert.Raw)
		if err != nil {
			continue
		}
		if _, err := ms.WriteMessage(response); err != nil {
			log.Printf("Quote server: Error sending response on the channel: %s\n ", err)
		}
	}
}
