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
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
)

func GetPublicDerFromEcdsaKey(key ecdsa.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(key)
}

func GetEcdsaKeyFromDer(der []byte) (interface{}, error) {
	return x509.ParsePKIXPublicKey(der)
}

func SerializeKeyToInternalName(ec_key *ecdsa.PublicKey) ([]byte, error) {
	m := &tao.ECDSA_SHA_VerifyingKeyV1{
                Curve:    tao.NamedEllipticCurve_PRIME256_V1.Enum(),
		EcPublic: elliptic.Marshal(ec_key.Curve, ec_key.X, ec_key.Y),
	}
	b, _ := proto.Marshal(m)

	s := &tao.CryptoKey{
		Version:   tao.CryptoVersion_CRYPTO_VERSION_1.Enum(),
		Purpose:   tao.CryptoKey_VERIFYING.Enum(),
		Algorithm: tao.CryptoKey_ECDSA_SHA.Enum(),
		Key:       b,
        }

	return proto.Marshal(s)
}

func GetKeyHash(s []byte) ([32]byte) {
	return sha256.Sum256(s)
}

