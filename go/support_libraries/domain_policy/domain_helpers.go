// Copyright (c) 2014, Google, Inc..  All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//     http://www.apache.org/licenses/LICENSE-2.0
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// File: domain_helpers.go

package domain_policy

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
)

func GetPublicDerFromEcdsaKey(ecKey *ecdsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(ecKey)
}

func GetEcdsaKeyFromDer(der []byte) (interface{}, error) {
	return x509.ParsePKIXPublicKey(der)
}

func SerializeRSAKeyToInternalName(rsaKey *rsa.PublicKey) ([]byte, error) {
	return nil, nil
}

func SerializeEcdsaKeyToInternalName(ecKey *ecdsa.PublicKey) ([]byte, error) {
	// JLM
	return x509.MarshalPKIXPublicKey(ecKey)
}

func GetKeyHash(s []byte) ([32]byte) {
	return sha256.Sum256(s)
}

