//  Copyright (c) 2014, Google Inc.  All rights reserved.
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
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"golang.org/x/crypto/pbkdf2"
)

func TestGenerateKeys(t *testing.T) {
	var keyName string
	var keyEpoch int32
	var keyPurpose string
	var keyStatus string

	// "aes128-raw"
	keyName = "keyName1"
	keyEpoch = 1
	keyPurpose = "crypting"
	keyStatus = "active"
	cryptoKey1 := GenerateCryptoKey("aes128-raw", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey1 == nil {
		t.Fatal("Can't generate aes128-raw key\n")
	}
	fmt.Printf("Testing aes128-raw generation\n")
	PrintCryptoKey(cryptoKey1)
	fmt.Printf("\n")
	m1 := MarshalCryptoKey(*cryptoKey1)
	if m1 == nil {
		t.Fatal("Can't MarshalCryptoKey aes128-raw key\n")
	}
	cryptoKey1_d, err := UnmarshalCryptoKey(m1)
	if err != nil {
		t.Fatal("Can't UnmarshalCryptoKey aes128-raw key\n")
	}
	PrintCryptoKey(cryptoKey1_d)
	fmt.Printf("\n")
	crypter, err := aes.NewCipher(cryptoKey1_d.KeyComponents[0])
	if err != nil {
		t.Fatal("Can't create aes128 encrypter\n")
	}
	plain := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	fmt.Printf("aes key size %d, key: %x, plain size %d, BlockSize: %d\n", len(cryptoKey1_d.KeyComponents[0]),
		cryptoKey1_d.KeyComponents[0], len(plain), crypter.BlockSize())
	encrypted := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	decrypted := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	crypter.Encrypt(encrypted, plain)
	crypter.Decrypt(decrypted, encrypted)
	if !bytes.Equal(plain, decrypted) {
		t.Fatal("aes128-raw plain and decrypted dont match\n")
	} else {
		fmt.Printf("Encryption works, encrypted: %x\n", encrypted)
	}
	fmt.Printf("\n")

	// "aes256-raw"
	keyName = "keyName2"
	keyEpoch = 2
	keyPurpose = "crypting"
	keyStatus = "active"
	cryptoKey2 := GenerateCryptoKey("aes256-raw", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey2 == nil {
		t.Fatal("Can't generate aes256-raw key\n")
	}
	fmt.Printf("Testing aes256-raw generation\n")
	PrintCryptoKey(cryptoKey2)
	fmt.Printf("\n")
	m2 := MarshalCryptoKey(*cryptoKey2)
	if m2 == nil {
		t.Fatal("Can't MarshalCryptoKey aes256-raw key\n")
	}
	cryptoKey2_d, err := UnmarshalCryptoKey(m2)
	if err != nil {
		t.Fatal("Can't UnmarshalCryptoKey aes256-raw key\n")
	}
	PrintCryptoKey(cryptoKey2_d)
	fmt.Printf("\n")
	crypter2, err := aes.NewCipher(cryptoKey2_d.KeyComponents[0])
	if err != nil {
		t.Fatal("Can't create aes256 encrypter\n")
	}
	plain2 := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	fmt.Printf("aes key size %d, key: %x, plain size %d, BlockSize: %d\n", len(cryptoKey2_d.KeyComponents[0]),
		cryptoKey2_d.KeyComponents[0], len(plain2), crypter2.BlockSize())
	encrypted2 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	decrypted2 := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	crypter2.Encrypt(encrypted2, plain2)
	crypter2.Decrypt(decrypted2, encrypted2)
	if !bytes.Equal(plain2, decrypted2) {
		t.Fatal("aes256-raw plain and decrypted dont match\n")
	} else {
		fmt.Printf("Encryption works, encrypted: %x\n", encrypted2)
	}
	fmt.Printf("\n")

	// "aes128-ctr"
	keyName = "keyName3"
	keyEpoch = 3
	keyPurpose = "crypting"
	keyStatus = "active"
	cryptoKey3 := GenerateCryptoKey("aes128-ctr", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey1 == nil {
		t.Fatal("Can't generate aes128-ctr key\n")
	}
	fmt.Printf("Testing aes128-ctr generation\n")
	PrintCryptoKey(cryptoKey3)
	fmt.Printf("\n")

	// "aes256-ctr"
	keyName = "keyName4"
	keyEpoch = 4
	keyPurpose = "crypting"
	keyStatus = "active"
	cryptoKey4 := GenerateCryptoKey("aes256-ctr", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey1 == nil {
		t.Fatal("Can't generate aes256-ctr key\n")
	}
	fmt.Printf("Testing aes256-ctr generation\n")
	PrintCryptoKey(cryptoKey4)
	fmt.Printf("\n")

	// "aes128-ctr-hmacsha256"
	keyName = "keyName5"
	keyEpoch = 2
	keyPurpose = "crypting"
	keyStatus = "active"
	cryptoKey5 := GenerateCryptoKey("aes128-ctr-hmacsha256", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey5 == nil {
		t.Fatal("Can't generate aes128-ctr-hmacsha256 key\n")
	}
	fmt.Printf("Testing aes128-ctr-hmacsha256 generation\n")
	PrintCryptoKey(cryptoKey5)
	fmt.Printf("\n")

	// "aes256-sha384-ctr"
	keyName = "keyName6"
	keyEpoch = 2
	cryptoKey6 := GenerateCryptoKey("aes256-ctr-hmacsha384", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey6 == nil {
		t.Fatal("Can't generate aes256-ctr-hmacsha384 key\n")
	}
	fmt.Printf("Testing aes256-ctr-hmacsha384 generation\n")
	PrintCryptoKey(cryptoKey6)
	fmt.Printf("\n")

	// "aes256-sha512-ctr"
	keyName = "keyName6.2"
	cryptoKey6 = GenerateCryptoKey("aes256-ctr-hmacsha512", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey6 == nil {
		t.Fatal("Can't generate aes256-ctr-hmacsha512 key\n")
	}
	fmt.Printf("Testing aes256-ctr-hmacsha512 generation\n")
	PrintCryptoKey(cryptoKey6)
	fmt.Printf("\n")

	// "hmacsha256"
	keyName = "keyName7"
	keyEpoch = 2
	keyPurpose = "crypting"
	keyStatus = "active"
	cryptoKey7 := GenerateCryptoKey("hmacsha256", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey7 == nil {
		t.Fatal("Can't hmacsha256 key\n")
	}
	fmt.Printf("Testing hmacsha256 generation\n")
	PrintCryptoKey(cryptoKey7)
	fmt.Printf("\n")

	// "hmacsha384"
	keyName = "keyName8"
	keyEpoch = 2
	keyPurpose = "crypting"
	keyStatus = "active"
	cryptoKey8 := GenerateCryptoKey("hmacsha384", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey1 == nil {
		t.Fatal("Can't generate hmacsha384 key\n")
	}
	fmt.Printf("Testing hmacsha384 generation\n")
	PrintCryptoKey(cryptoKey8)
	fmt.Printf("\n")

	// "hmacsha512"
	keyName = "keyName9"
	keyEpoch = 2
	keyPurpose = "crypting"
	keyStatus = "active"
	cryptoKey9 := GenerateCryptoKey("hmacsha512", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey1 == nil {
		t.Fatal("Can't generate hmacsha512 key\n")
	}
	fmt.Printf("Testing hmacsha512 generation\n")
	PrintCryptoKey(cryptoKey9)
	fmt.Printf("\n")

	// "rsa1024"
	keyName = "keyName10"
	keyEpoch = 2
	keyPurpose = "signing"
	keyStatus = "primary"
	cryptoKey10 := GenerateCryptoKey("rsa1024", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey1 == nil {
		t.Fatal("Can't generate rsa1024 key\n")
	}
	fmt.Printf("Testing rsa1024 generation\n")
	PrintCryptoKey(cryptoKey10)
	fmt.Printf("\n")
	m10 := MarshalCryptoKey(*cryptoKey10)
	if m10 == nil {
		t.Fatal("Can't MarshalCryptoKey rsa1024 key\n")
	}
	cryptoKey10_d, err := UnmarshalCryptoKey(m10)
	if err != nil {
		t.Fatal("Can't UnmarshalCryptoKey rsa1024 key\n")
	}
	PrintCryptoKey(cryptoKey10_d)
	fmt.Printf("\n")

	// "rsa2048"
	keyName = "keyName11"
	keyEpoch = 2
	keyPurpose = "signing"
	keyStatus = "primary"
	cryptoKey11 := GenerateCryptoKey("rsa2048", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey11 == nil {
		t.Fatal("Can't generate rsa2048 key\n")
	}
	fmt.Printf("Testing rsa2048 generation\n")
	PrintCryptoKey(cryptoKey11)
	fmt.Printf("\n")

	// "rsa3072"
	keyName = "keyName12"
	keyEpoch = 2
	keyPurpose = "signing"
	keyStatus = "primary"
	cryptoKey12 := GenerateCryptoKey("rsa3072", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey12 == nil {
		t.Fatal("Can't generate rsa3072 key\n")
	}
	fmt.Printf("Testing rsa3072 generation\n")
	PrintCryptoKey(cryptoKey12)
	fmt.Printf("\n")

	// "ecdsap256"
	keyName = "keyName13"
	keyEpoch = 2
	keyPurpose = "signing"
	keyStatus = "primary"
	cryptoKey13 := GenerateCryptoKey("ecdsap256", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey13 == nil {
		t.Fatal("Can't generate ecdsap256 key\n")
	}
	fmt.Printf("Testing ecdsap256 generation\n")
	PrintCryptoKey(cryptoKey13)
	fmt.Printf("\n")

	// "ecdsap384"
	keyName = "keyName14"
	keyEpoch = 2
	keyPurpose = "signing"
	keyStatus = "primary"
	cryptoKey14 := GenerateCryptoKey("ecdsap384", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey14 == nil {
		t.Fatal("Can't generate ecdsap384 key\n")
	}
	fmt.Printf("Testing ecdsap384 generation\n")
	PrintCryptoKey(cryptoKey14)
	fmt.Printf("\n")

	// "ecdsap521"
	keyName = "keyName15"
	keyEpoch = 2
	keyPurpose = "signing"
	keyStatus = "primary"
	cryptoKey15 := GenerateCryptoKey("ecdsap521", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey15 == nil {
		t.Fatal("Can't generate ecdsap521 key\n")
	}
	fmt.Printf("Testing ecdsap521 generation\n")
	PrintCryptoKey(cryptoKey15)
	fmt.Printf("\n")
}

func TestKeyTranslate(t *testing.T) {

	// Private keys --- RSA
	keyType := "rsa1024"
	keyName := "Rsatestkey"
	keyEpoch := int32(1)
	keyPurpose := "signing"
	keyStatus := "active"
	ck := GenerateCryptoKey(keyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if ck == nil {
		t.Fatal("Can't generate rsa key\n")
	}
	s := SignerFromCryptoKey(*ck)
	if s == nil {
		t.Fatal("Can't get signer from key\n")
	}
	ckNew, err := CryptoKeyFromSigner(s)
	if err != nil {
		t.Fatal("Can't get key from signer\n")
	}
	PrintCryptoKey(ckNew)
	sNew := SignerFromCryptoKey(*ck)
	if sNew == nil {
		t.Fatal("Can't get signer recovered key\n")
	}
	keyType = "ecdsap256"
	keyName = "Ecdsatestkey"
	ck = GenerateCryptoKey(keyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if ck == nil {
		t.Fatal("Can't generate rsa key\n")
	}
	s = SignerFromCryptoKey(*ck)
	if s == nil {
		t.Fatal("Can't get signer from key\n")
	}
	ckNew, err = CryptoKeyFromSigner(s)
	if err != nil {
		t.Fatal("Can't get key from signer\n")
	}
	PrintCryptoKey(ckNew)
	sNew = SignerFromCryptoKey(*ck)
	if sNew == nil {
		t.Fatal("Can't get signer recovered key\n")
	}

	// verifier
	v := s.GetVerifierFromSigner()
	if v == nil {
		t.Fatal("Can't get verifier\n")
	}
	ckNew, err = CryptoKeyFromVerifier(v)
	if err != nil {
		t.Fatal("Cannot get CryptoKeyFromVerifier\n")
	}
	v = VerifierFromCryptoKey(*ckNew)
	PrintCryptoKey(ckNew)

	// aes128-ctr-hmac256
	keyType = "aes128-ctr-hmacsha256"
	keyName = "aes128Crypter"
	keyEpoch = 2
	keyPurpose = "crypting"
	keyStatus = "primary"
	ck = GenerateCryptoKey(keyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if ck == nil {
		t.Fatal("Can't generate aes key\n")
	}
	c := CrypterFromCryptoKey(*ck)
	if c == nil {
		t.Fatal("Can't generate aes key\n")
	}
	ckNew, err = CryptoKeyFromCrypter(c)
	if err != nil {
		t.Fatal("Can't generate aes key from crypter\n")
	}
	PrintCryptoKey(ckNew)
	c = CrypterFromCryptoKey(*ckNew)
	if c == nil {
		t.Fatal("Can't recover crypter from key\n")
	}

	// aes256-ctr-hmac384
	keyType = "aes256-ctr-hmacsha384"
	keyName = "aes256Crypter384"
	keyStatus = "primary"
	ck = GenerateCryptoKey(keyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if ck == nil {
		t.Fatal("Can't generate aes key\n")
	}
	c = CrypterFromCryptoKey(*ck)
	if c == nil {
		t.Fatal("Can't get crypter from key\n")
	}
	ckNew, err = CryptoKeyFromCrypter(c)
	if c == nil {
		t.Fatal("Can't recover crypter from key\n")
	}
	PrintCryptoKey(ckNew)

	// aes256-ctr-hmac512
	keyType = "aes256-ctr-hmacsha512"
	keyName = "aes256Crypter"
	ck = GenerateCryptoKey(keyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if ck == nil {
		t.Fatal("Can't generate aes key\n")
	}
	c = CrypterFromCryptoKey(*ck)
	if c == nil {
		t.Fatal("Can't get crypter from key\n")
	}
	ckNew, err = CryptoKeyFromCrypter(c)
	if c == nil {
		t.Fatal("Can't recover crypter from key\n")
	}
	PrintCryptoKey(ckNew)

	// hdkf-sha256
	keyType = "hdkf-sha256"
	keyName = "sha256Deriver"
	keyPurpose = "deriving"
	ck = GenerateCryptoKey(keyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if ck == nil {
		t.Fatal("Can't generate deriver key\n")
	}
	d := DeriverFromCryptoKey(*ck)
	if d == nil {
		t.Fatal("Can't get deriver from key\n")
	}
	ckNew, err = CryptoKeyFromDeriver(d)
	if err != nil {
		t.Fatal("Can't get key from deriver\n")
	}
	PrintCryptoKey(ckNew)
	d = DeriverFromCryptoKey(*ckNew)
	if d == nil {
		t.Fatal("Can't get deriver from recovered key\n")
	}

	// aes256-ctr-hmac384
	keyType = "aes256-ctr-hmacsha384"
	keyName = "aes256Crypter"
	keyStatus = "primary"
	ck = GenerateCryptoKey(keyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if ck == nil {
		t.Fatal("Can't generate aes key\n")
	}
	c = CrypterFromCryptoKey(*ck)
	if c == nil {
		t.Fatal("Can't generate rsa key\n")
	}
	ckNew, err = CryptoKeyFromCrypter(c)
	PrintCryptoKey(ckNew)
}

func TestCerts(t *testing.T) {

	// ecdsap256
	keyName := "keyName1"
	keyEpoch := int32(1)
	keyPurpose := "signing"
	keyStatus := "active"
	sk := GenerateCryptoKey("ecdsap256", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if sk == nil {
		t.Fatal("Can't generate signing key\n")
	}
	PrintCryptoKey(sk)
	fmt.Printf("\n")

	s := SignerFromCryptoKey(*sk)
	if s == nil {
		t.Fatal("Can't get signer from key\n")
	}

	details := &X509Details{
		CommonName:   proto.String("test"),
		Country:      proto.String("US"),
		State:        proto.String("WA"),
		Organization: proto.String("Google"),
	}
	der, err := s.CreateSelfSignedDER(int(x509.ECDSA), int(x509.ECDSAWithSHA256),
		int64(10), NewX509Name(details))
	if err != nil {
		t.Fatal("CreateSelfSignedDER failed, ", err, "\n")
	}
	fmt.Printf("Der: %x\n", der)
	cert, err := s.CreateSelfSignedX509(int(x509.ECDSA), int(x509.ECDSAWithSHA256),
		int64(10), NewX509Name(details))
	if err != nil {
		t.Fatal("CreateSelfSignedX509 failed, ", err, "\n")
	}
	fmt.Printf("Cert: %x\n", cert)

	// ecdsap384
	keyName = "keyName2"
	sk = GenerateCryptoKey("ecdsap384", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if sk == nil {
		t.Fatal("Can't generate signing key\n")
	}
	PrintCryptoKey(sk)
	fmt.Printf("\n")

	s = SignerFromCryptoKey(*sk)
	if s == nil {
		t.Fatal("Can't get signer from key\n")
	}

	der, err = s.CreateSelfSignedDER(int(x509.ECDSA), int(x509.ECDSAWithSHA256),
		int64(10), NewX509Name(details))
	if err != nil {
		t.Fatal("CreateSelfSignedDER failed, ", err, "\n")
	}
	fmt.Printf("Der: %x\n", der)
	cert, err = s.CreateSelfSignedX509(int(x509.ECDSA), int(x509.ECDSAWithSHA256),
		int64(10), NewX509Name(details))
	if err != nil {
		t.Fatal("CreateSelfSignedX509 failed, ", err, "\n")
	}
	fmt.Printf("Cert: %x\n", cert)

	// ecdsap521
	keyName = "keyName3"
	sk = GenerateCryptoKey("ecdsap521", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if sk == nil {
		t.Fatal("Can't generate signing key\n")
	}
	PrintCryptoKey(sk)
	fmt.Printf("\n")

	s = SignerFromCryptoKey(*sk)
	if s == nil {
		t.Fatal("Can't get signer from key\n")
	}

	der, err = s.CreateSelfSignedDER(int(x509.ECDSA), int(x509.ECDSAWithSHA256),
		int64(10), NewX509Name(details))
	if err != nil {
		t.Fatal("CreateSelfSignedDER failed, ", err, "\n")
	}
	fmt.Printf("Der: %x\n", der)
	cert, err = s.CreateSelfSignedX509(int(x509.ECDSA), int(x509.ECDSAWithSHA256),
		int64(10), NewX509Name(details))
	if err != nil {
		t.Fatal("CreateSelfSignedX509 failed, ", err, "\n")
	}
	fmt.Printf("Cert: %x\n", cert)

	// RSA
	sk = GenerateCryptoKey("rsa2048", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if sk == nil {
		t.Fatal("Can't generate signing key\n")
	}
	PrintCryptoKey(sk)
	fmt.Printf("\n")
	s = SignerFromCryptoKey(*sk)
	if s == nil {
		t.Fatal("Can't get signer from signing key\n")
	}

	/*
		FIX TEST
		der, err = s.CreateSelfSignedDER(int(x509.RSA), int(x509.SHA256WithRSA),
			int64(10), NewX509Name(details))
		if err != nil {
			t.Fatal("CreateSelfSignedDER failed, ", err, "\n")
		}
		fmt.Printf("Der: %x\n", der)
		cert, err = s.CreateSelfSignedX509(int(x509.RSA), int(x509.SHA256WithRSA),
			int64(10), NewX509Name(details))
		if err != nil {
			t.Fatal("CreateSelfSignedX509 failed, ", err, "\n")
		}
	*/

	// (s *Signer) CreateCRL(cert *x509.Certificate, revokedCerts []pkix.RevokedCertificate, now, expiry time.Time) ([]byte, error)
	// (s *Signer) CreateSignedX509(caCert *x509.Certificate, certSerial int, subjectKey *Verifier,
}

func TestCanonicalBytes(t *testing.T) {

	// ecdsa256
	keyName := "keyName1"
	keyEpoch := int32(1)
	keyPurpose := "signing"
	keyStatus := "active"
	signingKey := GenerateCryptoKey("ecdsap256", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if signingKey == nil {
		t.Fatal("Can't generate signing key\n")
	}
	PrintCryptoKey(signingKey)
	fmt.Printf("\n")

	s := SignerFromCryptoKey(*signingKey)
	if s == nil {
		t.Fatal("Can't get signer from key\n")
	}

	cb, err := s.CanonicalKeyBytesFromSigner()
	if err != nil {
		t.Fatal("CanonicalKeyBytesFromSigner fails\n")
	}
	fmt.Printf("Canonical bytes: %x\n", cb)

	// ecdsa384
	signingKey = GenerateCryptoKey("ecdsap384", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if signingKey == nil {
		t.Fatal("Can't generate signing key\n")
	}
	PrintCryptoKey(signingKey)
	fmt.Printf("\n")

	s = SignerFromCryptoKey(*signingKey)
	if s == nil {
		t.Fatal("Can't get signer from key\n")
	}

	cb, err = s.CanonicalKeyBytesFromSigner()
	if err != nil {
		t.Fatal("CanonicalKeyBytesFromSigner fails\n")
	}
	fmt.Printf("Canonical bytes: %x\n", cb)

	// ecdsa521
	signingKey = GenerateCryptoKey("ecdsap521", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if signingKey == nil {
		t.Fatal("Can't generate signing key\n")
	}
	PrintCryptoKey(signingKey)
	fmt.Printf("\n")

	s = SignerFromCryptoKey(*signingKey)
	if s == nil {
		t.Fatal("Can't get signer from key\n")
	}

	cb, err = s.CanonicalKeyBytesFromSigner()
	if err != nil {
		t.Fatal("CanonicalKeyBytesFromSigner fails\n")
	}
	fmt.Printf("Canonical bytes: %x\n", cb)

	// rsa
	keyName = "keyName1"
	signingKey = GenerateCryptoKey("rsa2048", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if signingKey == nil {
		t.Fatal("Can't generate signing key\n")
	}
	PrintCryptoKey(signingKey)
	fmt.Printf("\n")

	s = SignerFromCryptoKey(*signingKey)
	if s == nil {
		t.Fatal("Can't get signer from key\n")
	}

	cb, err = s.CanonicalKeyBytesFromSigner()
	if err != nil {
		t.Fatal("CanonicalKeyBytesFromSigner fails\n")
	}
	fmt.Printf("Canonical bytes: %x\n", cb)
}

func TestNewCrypter(t *testing.T) {

	keyName := "keyName1"
	keyEpoch := int32(1)
	keyPurpose := "crypting"
	keyStatus := "active"
	cryptingKey := GenerateCryptoKey("aes128-ctr-hmacsha256", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptingKey == nil {
		t.Fatal("Can't generate crypting key\n")
	}
	PrintCryptoKey(cryptingKey)
	fmt.Printf("\n")
	c := CrypterFromCryptoKey(*cryptingKey)
	if c == nil {
		t.Fatal("CrypterFromCryptoKey fails\n")
	}
	plain := []byte{0, 1, 2, 3, 4, 5, 6, 7}
	crypted, err := c.Encrypt(plain)
	if err != nil {
		t.Fatal("Crypter failed to encrypt\n")
	}
	fmt.Printf("Encrypted: %x\n", crypted)
	decrypted, err := c.Decrypt(crypted)
	if err != nil {
		t.Fatal("Crypter failed to decrypt\n")
	}
	fmt.Printf("Decrypted: %x\n", decrypted)
	if !bytes.Equal(plain, decrypted) {
		t.Fatal("plain an decrypted bytes don't match\n")
	}
}

func TestDeriveSecret(t *testing.T) {

	ver := CryptoVersion_CRYPTO_VERSION_2
	keyName := "keyName1"
	keyType := "hdkf-sha256"
	keyEpoch := int32(1)
	keyPurpose := "deriving"
	keyStatus := "active"
	ch := &CryptoHeader{
		Version:    &ver,
		KeyName:    &keyName,
		KeyEpoch:   &keyEpoch,
		KeyType:    &keyType,
		KeyPurpose: &keyPurpose,
		KeyStatus:  &keyStatus,
	}
	// derivingKey := GenerateCryptoKey("hdfk-sha256", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	// derivingKey.KeyComponents = append(derivingKey.KeyComponents, buf)
	// if derivingKey == nil {
	// t.Fatal("Can't generate deriving key\n")
	// }
	// PrintCryptoKey(derivingKey)
	// d := DeriverFromCryptoKey(*derivingKey)
	// if d == nil {
	// t.Fatal("DeriveFromCryptoKey fails\n")
	// }
	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	d := &Deriver{
		Header: ch,
		Secret: buf,
	}
	fmt.Printf("\n")

	salt := []byte{1, 2, 3, 4}
	context := []byte{1, 2}
	material := make([]byte, 32)
	material[0] = 1
	err = d.Derive(salt, context, material)
	if err != nil {
	}
	fmt.Printf("Derived: %x\n", material)
}

func TestSignAndVerify(t *testing.T) {

	var keyName string
	var keyEpoch int32
	var keyPurpose string
	var keyStatus string

	// Rsa Tests
	fmt.Printf("\n")
	keyName = "TestRsa2048SignandVerify"
	keyEpoch = 2
	keyPurpose = "signing"
	keyStatus = "primary"
	cryptoKey1 := GenerateCryptoKey("rsa2048", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey1 == nil {
		t.Fatal("Can't generate rsa2048 key\n")
	}
	PrintCryptoKey(cryptoKey1)

	// save
	privateKey, err := PrivateKeyFromCryptoKey(*cryptoKey1)
	if err != nil {
		t.Fatal("PrivateKeyFromCryptoKey fails, ", err, "\n")
	}

	mesg := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}
	hash := crypto.SHA256
	blk := hash.New()
	blk.Write(mesg)
	hashed := blk.Sum(nil)
	fmt.Printf("Hashed: %x\n", hashed)

	sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey.(*rsa.PrivateKey), crypto.SHA256, hashed[:])
	if err != nil {
		t.Fatal("privateKey signing fails\n")
	}
	fmt.Printf("Signature: %x\n", sig)

	publicKey := privateKey.(*rsa.PrivateKey).PublicKey
	if err != nil {
		t.Fatal("PrivateKeyFromCryptoKey fails, ", err, "\n")
	}
	err = rsa.VerifyPKCS1v15(&publicKey, crypto.SHA256, hashed, sig)
	if err != nil {
		t.Fatal("Verify fails, ", err, "\n")
	} else {
		fmt.Printf("Rsa Verify succeeds\n")
	}

	s := SignerFromCryptoKey(*cryptoKey1)
	if s == nil {
		t.Fatal("SignerFromCryptoKey fails, ", err, "\n")
	}
	sig1, err := s.Sign(hashed, "Signing context")
	if err != nil {
		t.Fatal("Signer Sign failed, ", err, "\n")
	}
	fmt.Printf("Signer sign: %x\n", sig1)

	v := s.GetVerifierFromSigner()
	if v == nil {
		t.Fatal("Can't get verifier from signer\n")
	}
	verified, err := v.Verify(hashed, "Signing context", sig1)
	if verified {
		fmt.Printf("Pkcs verified succeeds\n")
	} else {
		t.Fatal("Pkcs verified failed, ", err, "\n")
	}

	// ecdsa test
	fmt.Printf("\n")
	keyName = "TestEcdsaP256SignandVerify"
	keyEpoch = 2
	keyPurpose = "signing"
	keyStatus = "primary"
	cryptoKey2 := GenerateCryptoKey("ecdsap256", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey2 == nil {
		t.Fatal("Can't generate ecdsap256key\n")
	}
	PrintCryptoKey(cryptoKey2)

	// save
	privateKey, err = PrivateKeyFromCryptoKey(*cryptoKey2)
	if err != nil {
		t.Fatal("PrivateKeyFromCryptoKey fails, ", err, "\n")
	}

	hash = crypto.SHA256
	blk = hash.New()
	blk.Write(mesg)
	hashed = blk.Sum(nil)
	fmt.Printf("Hashed: %x\n", hashed)

	s = SignerFromCryptoKey(*cryptoKey2)
	if s == nil {
		t.Fatal("SignerFromCryptoKey fails, ", err, "\n")
	}

	sig2, err := s.Sign(hashed, "Signing context")
	if err != nil {
		t.Fatal("Signer Sign failed, ", err, "\n")
	}
	fmt.Printf("Signer sign: %x\n", sig2)

	v = s.GetVerifierFromSigner()
	if v == nil {
		t.Fatal("Can't get verifier from signer\n")
	}
	verified, err = v.Verify(hashed, "Signing context", sig2)
	if verified {
		fmt.Printf("Ecdsa verified succeeds\n")
	} else {
		t.Fatal("Ecdsa verified failed, ", err, "\n")
	}
}

func TestEncryptAndDecrypt(t *testing.T) {

	var keyName string
	var keyEpoch int32
	var keyPurpose string
	var keyStatus string

	fmt.Printf("\n")
	keyName = "TestAes128-ctr-hmac256-key"
	keyEpoch = 2
	keyPurpose = "signing"
	keyStatus = "primary"
	cryptoKey1 := GenerateCryptoKey("aes128-ctr-hmacsha256", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey1 == nil {
		t.Fatal("Can't generate aes128-ctr-hmacsha256 key\n")
	}
	PrintCryptoKey(cryptoKey1)

	c := CrypterFromCryptoKey(*cryptoKey1)
	if c == nil {
		t.Fatal("Can't get crypter from cryptokey\n")
	}
	plain := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}
	ciphertext, err := c.Encrypt(plain)
	if err != nil {
		t.Fatal("Can't encrypt, ", err, "\n")
	}
	fmt.Printf("Ciphertext: %x\n", ciphertext)
	decrypted, err := c.Decrypt(ciphertext)
	if err != nil {
		t.Fatal("Can't decrypt, ", err, "\n")
	}
	fmt.Printf("Decrypted: %x\n", decrypted)
	if !bytes.Equal(plain, decrypted) {
		t.Fatal("plain and decrypted don't match")
	}

	// Aes 256-hmacsha384
	fmt.Printf("\n")
	keyName = "TestAes256-ctr-hmac384-key"
	keyEpoch = 2
	cryptoKey2 := GenerateCryptoKey("aes256-ctr-hmacsha384", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey2 == nil {
		t.Fatal("Can't generate aes256-ctr-hmacsha384 key\n")
	}
	PrintCryptoKey(cryptoKey2)

	c = CrypterFromCryptoKey(*cryptoKey2)
	if c == nil {
		t.Fatal("Can't get crypter from cryptokey\n")
	}
	ciphertext, err = c.Encrypt(plain)
	if err != nil {
		t.Fatal("Can't encrypt, ", err, "\n")
	}
	fmt.Printf("Ciphertext: %x\n", ciphertext)
	decrypted, err = c.Decrypt(ciphertext)
	if err != nil {
		t.Fatal("Can't decrypt, ", err, "\n")
	}
	fmt.Printf("Decrypted: %x\n", decrypted)
	if !bytes.Equal(plain, decrypted) {
		t.Fatal("plain and decrypted don't match")
	}

	// Aes 256-hmacsha512
	fmt.Printf("\n")
	keyName = "TestAes256-ctr-hmac512-key"
	cryptoKey3 := GenerateCryptoKey("aes256-ctr-hmacsha512", &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if cryptoKey3 == nil {
		t.Fatal("Can't generate aes256-ctr-hmacsha512 key\n")
	}
	PrintCryptoKey(cryptoKey3)

	c = CrypterFromCryptoKey(*cryptoKey3)
	if c == nil {
		t.Fatal("Can't get crypter from cryptokey\n")
	}
	ciphertext, err = c.Encrypt(plain)
	if err != nil {
		t.Fatal("Can't encrypt, ", err, "\n")
	}
	fmt.Printf("Ciphertext: %x\n", ciphertext)
	decrypted, err = c.Decrypt(ciphertext)
	if err != nil {
		t.Fatal("Can't decrypt, ", err, "\n")
	}
	fmt.Printf("Decrypted: %x\n", decrypted)
	if !bytes.Equal(plain, decrypted) {
		t.Fatal("plain and decrypted don't match")
	}
}

func TestPdkfGeneration(t *testing.T) {
	salt := []byte{0,1,2,3,4,5,6,7}
	iterations := 1000
	password := []byte("Stupid password")
	key1 := pbkdf2.Key(password, salt, iterations, 16, sha256.New)
	key2 := pbkdf2.Key(password, salt, iterations, 32, sha256.New)
	key3 := pbkdf2.Key(password, salt, iterations, 32, sha512.New384)
	key4 := pbkdf2.Key(password, salt, iterations, 32, sha512.New)
	key5 := pbkdf2.Key(password, salt, iterations, 48, sha512.New384)
	key6 := pbkdf2.Key(password, salt, iterations, 64, sha512.New)
	fmt.Printf("key 1 (16, sha256): %x\n", key1)
	fmt.Printf("key 2 (32, sha256): %x\n", key2)
	fmt.Printf("key 3 (32, sha384): %x\n", key3)
	fmt.Printf("key 4 (32, sha512): %x\n", key4)
	fmt.Printf("key 5 (48, sha384): %x\n", key5)
	fmt.Printf("key 6 (64, sha512): %x\n", key6)

	keyType := "hdkf-sha256"
	keyName := "sha256Deriver"
	keyPurpose := "deriving"
	keyEpoch := int32(1)
	keyStatus := "primary"
	context := []byte("I am a context")
	ck := GenerateCryptoKey(keyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if ck == nil {
		t.Fatal("Can't generate deriver key\n")
	}
	d := DeriverFromCryptoKey(*ck)
	if d == nil {
		t.Fatal("Can't get deriver from key\n")
	}
	var material []byte
	material = password
	err := d.Derive(salt, context, material)
	if err != nil {
		t.Fatal("Can't get derive from material\n")
	}
	fmt.Printf("Derived (sha256): %x\n", material)

	keyType = "hdkf-sha384"
	ck = GenerateCryptoKey(keyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if ck == nil {
		t.Fatal("Can't generate deriver key\n")
	}
	d = DeriverFromCryptoKey(*ck)
	if d == nil {
		t.Fatal("Can't get deriver from key\n")
	}
	err = d.Derive(salt, context, material)
	if err != nil {
		t.Fatal("Can't get derive from material\n")
	}
	fmt.Printf("Derived (sha384): %x\n", material)

	keyType = "hdkf-sha512"
	ck = GenerateCryptoKey(keyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if ck == nil {
		t.Fatal("Can't generate deriver key\n")
	}
	d = DeriverFromCryptoKey(*ck)
	if d == nil {
		t.Fatal("Can't get deriver from key\n")
	}
	err = d.Derive(salt, context, material)
	if err != nil {
		t.Fatal("Can't get derive from material\n")
	}
	fmt.Printf("Derived (sha512): %x\n", material)
}
