// Copyright (c) 2014, Google Inc. All rights reserved.
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

package tpm

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"math/big"
	"os"
	"testing"
)

func TestAttributes(t *testing.T) {
	sealedObj := uint32(FlagFixedTPM | FlagFixedParent)
	if  sealedObj != 0x12 {
		t.Fatal("sealed object flags wrong\n")
	}
	storageObj := uint32(FlagRestricted | FlagDecrypt | FlagUserWithAuth |
		FlagSensitiveDataOrigin | FlagFixedTPM | FlagFixedParent)
	if  storageObj != 0x30072 {
		t.Fatal("storage object flags wrong\n")
	}
	signObj := uint32(FlagRestricted | FlagSign | FlagUserWithAuth |
		FlagSensitiveDataOrigin | FlagFixedTPM | FlagFixedParent)
	if  signObj != 0x50072 {
		t.Fatal("storage object flags wrong\n")
	}
}

func TestSetShortPcrs(t *testing.T) {
	pcr_nums := []int{7,8}
	pcr, err := SetShortPcrs(pcr_nums)
	if err != nil {
		t.Fatal("Test SetShortPcrs fails\n")
	}
	test_pcr := []byte{0x03,0x80,0x01,0x00}
	if !bytes.Equal(test_pcr, pcr) {
		t.Fatal("Wrong pcr value\n")
	}
}

func TestSetHandle(t *testing.T) {
	hand := SetHandle(Handle(ordTPM_RH_OWNER))
	if hand == nil {
		t.Fatal("Test SetHandle fails\n")
	}
	test_out := []byte{0x40, 0, 0, 1}
	if !bytes.Equal(test_out, hand)  {
		t.Fatal("Test SetHandle bad output\n")
	}
}

func TestSetPasswordData(t *testing.T) {
	pw1 := SetPasswordData("01020304")
	test1 := []byte{0,4,1,2,3,4}
	if pw1 == nil || !bytes.Equal(test1, pw1) {
		t.Fatal("Test Password 1 fails\n")
	}
	pw2 := SetPasswordData("0102030405")
	test2 := []byte{0,5,1,2,3,4,5}
	if pw2 == nil || !bytes.Equal(test2, pw2) {
		t.Fatal("Test Password 2 fails\n")
	}
}

func TestCreatePasswordAuthArea(t *testing.T) {
	pw_auth1 := CreatePasswordAuthArea("01020304", Handle(ordTPM_RS_PW))
	fmt.Printf("TestCreatePasswordAuthArea: %x\n", pw_auth1)
	test1 := []byte{0,0xd,0x40,0,0,9,0,0,1,0,4,1,2,3,4}
	if test1 == nil || !bytes.Equal(test1, pw_auth1) {
		t.Fatal("Test PasswordAuthArea 1 fails\n")
	}

	pw_auth2 := CreatePasswordAuthArea("", Handle(ordTPM_RS_PW))
	test2 := []byte{0,0x9,0x40,0,0,9,0,0,1,0,0}
	if test2 == nil || !bytes.Equal(test1, pw_auth1) {
		t.Fatal("Test PasswordAuthArea 2 fails\n")
	}
	fmt.Printf("TestCreatePasswordAuthArea: %x\n", pw_auth2)
}

func TestCreateSensitiveArea(t *testing.T) {
	a1 := []byte{1,2,3,4}
	var a2 []byte
	s := CreateSensitiveArea(a1, a2)
	if s == nil {
		t.Fatal("CreateSensitiveArea fails")
	}
	test := []byte{0, 8, 0, 4, 1, 2, 3, 4,0,0}
	if !bytes.Equal(test, s) {
		t.Fatal("CreateSensitiveArea fails")
	}
	fmt.Printf("Sensitive area: %x\n", s)
}

func TestCreateRsaParams(t *testing.T) {
	var empty []byte
	parms := RsaParams{uint16(AlgTPM_ALG_RSA), uint16(AlgTPM_ALG_SHA1),
		uint32(0x00030072), empty, uint16(AlgTPM_ALG_AES), uint16(128),
		uint16(AlgTPM_ALG_CFB), uint16(AlgTPM_ALG_NULL), uint16(0),
		uint16(1024), uint32(0x00010001), empty}

	s := CreateRsaParams(parms)
	if s == nil {
		t.Fatal("CreateRsaParams fails")
	}
	fmt.Printf("RsaParams area: %x\n", s)
/*
	test := []byte{0,6,0,0x80,0,0x43, 0, 0x10, 4,0,0,1,0,1,0,0}
	if !bytes.Equal(test, s) {
		t.Fatal("CreateRsaParams fails")
	}
*/
}

func TestCreateLongPcr(t *testing.T) {
	s :=  CreateLongPcr(uint32(1), []int{7})
	test := []byte{0, 0, 0, 1, 0, 4, 3, 0x80, 0, 0}
	if !bytes.Equal(test, s) {
		t.Fatal("CreateRsaParams fails")
	}
}

func TestKDFa(t *testing.T) {
	key := []byte{0,1,2,3,4,5,6,7,8,9,10,11,12,23,14,15}
	out, err := KDFA(uint16(AlgTPM_ALG_SHA1), key, "IDENTITY", nil, nil, 256)
	if err != nil {
		t.Fatal("KDFa fails")
	}
	fmt.Printf("KDFA: %x\n", out)
}

func TestReadRsaBlob(t *testing.T) {
}

func TestRetrieveFile(t *testing.T) {
	fileName := "./tmptest/cert.der"
	out := RetrieveFile(fileName)
	if out == nil {
		t.Fatal("Can't retrieve file\n")
	}
	fmt.Printf("Cert (%d): %x\n", len(out), out)
	fileInfo, err := os.Stat(fileName)
	if err != nil {
		t.Fatal("Can't stat file\n")
	}
	if len(out) != int(fileInfo.Size()) {
		t.Fatal("Bad file retrieve\n")
	}
}

func TestCertificateParse(t *testing.T) {
	out := RetrieveFile("./tmptest/endorsement_cert")
	if out == nil {
		t.Fatal("Can't retrieve file\n")
	}
	fmt.Printf("Cert (%d): %x\n", len(out), out)

	cert, err := x509.ParseCertificate(out)
	if cert == nil || err !=nil {
		fmt.Printf("Error: %s\n", err)
		t.Fatal("Can't parse retrieved cert\n")
	}
}

func TestPad(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if  err != nil || private == nil {
		t.Fatal("Can't gen private key %s\n", err)
	}
	public := &private.PublicKey
	var a [9]byte
	copy(a[0:8], "IDENTITY")

	seed := []byte{1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16}
	encrypted_secret, err := rsa.EncryptOAEP(sha1.New(), rand.Reader,
                        public, seed, a[0:9])
	if  err != nil {
		t.Fatal("Can't encrypt ", err)
	}
	fmt.Printf("encrypted_secret: %x\n", encrypted_secret)
	decrypted_secret, err := rsa.DecryptOAEP(sha1.New(), rand.Reader,
                        private, encrypted_secret, a[0:9])
	if  err != nil {
		t.Fatal("Can't decrypt ", err)
	}
	fmt.Printf("decrypted_secret: %x\n", decrypted_secret)
	var N *big.Int
	var D *big.Int
	var x *big.Int
	var z *big.Int
	N = public.N
	D = private.D
	x = new(big.Int)
	z = new(big.Int)
	x.SetBytes(encrypted_secret)
	z = z.Exp(x, D, N)
	decrypted_pad := z.Bytes()
	fmt.Printf("decrypted_pad   : %x\n", decrypted_pad)
}

