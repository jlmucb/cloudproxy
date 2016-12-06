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
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/jlmucb/cloudproxy/go/tpm2"
)

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
