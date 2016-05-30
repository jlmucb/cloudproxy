// Copyright (c) 2014, Google, Inc.,  All rights reserved.
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
// File: authdebug.go

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"flag"
	"fmt"
	// "io/ioutil"
	//"log"
	//"os"
	//"path"

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
	//"github.com/jlmucb/cloudproxy/go/util"
)

var fileName = flag.String("/Domains/extendtest", "/Domains/extendtest", "file name")

func marshalECDSASHAVerifyingKeyV1(k *ecdsa.PublicKey) *tao.ECDSA_SHA_VerifyingKeyV1 {
	return &tao.ECDSA_SHA_VerifyingKeyV1{
		Curve:    tao.NamedEllipticCurve_PRIME256_V1.Enum(),
		EcPublic: elliptic.Marshal(k.Curve, k.X, k.Y),
	}
}

func marshalPublicKeyProto(k *ecdsa.PublicKey) *tao.CryptoKey {
	m := marshalECDSASHAVerifyingKeyV1(k)
	b, _ := proto.Marshal(m)
	return &tao.CryptoKey{
		Version:   tao.CryptoVersion_CRYPTO_VERSION_1.Enum(),
		Purpose:   tao.CryptoKey_VERIFYING.Enum(),
		Algorithm: tao.CryptoKey_ECDSA_SHA.Enum(),
		Key:       b,
	}
}

func main() {
	ecpK, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
	}
	ecPK := ecpK.Public()
	if ecPK == nil {
	}
	eckp := ecPK.(*ecdsa.PublicKey)
	fmt.Printf("Curve: %x, X: %x, Y: %x\n",
		eckp.Curve, eckp.X, eckp.Y)
	ck := marshalPublicKeyProto(eckp)
	if ecPK == nil {
	}
	fmt.Printf("ck: %x\n", ck)
	data, _ := proto.Marshal(ck)
	fmt.Printf("data: %x\n", data)
	kprin := auth.NewKeyPrin(data)
	fmt.Printf("kprin: %x\n", kprin)
}
