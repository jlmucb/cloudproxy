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
	"crypto/rand"
	"testing"
)

func TestGenerateKeys(t *testing.T) {
	if _, err := GenerateSigner(); err != nil {
		t.Fatal(err.Error())
	}
}

func TestSignerPEMSerialization(t *testing.T) {
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err.Error())
	}

	b, err := MarshalSignerPEM(s)
	if err != nil {
		t.Fatal(err.Error())
	}

	if _, err := ParseSignerPEM(b); err != nil {
		t.Fatal(err.Error())
	}
}

func TestSelfSignedX509(t *testing.T) {
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err.Error())
	}

	d := `
		commonname: "test",
		country: "US",
		state: "WA",
		organization: "Google",
	`

	_, err = s.CreateSelfSignedX509(d)
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestSignerMarshalProto(t *testing.T) {
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err.Error())
	}

	c, err := MarshalSignerProto(s)
	if err != nil {
		t.Fatal(err.Error())
	}

	if _, err := UnmarshalSignerProto(c); err != nil {
		t.Fatal(err.Error())
	}
}

func TestCreateHeader(t *testing.T) {
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err.Error())
	}

	if _, err := s.CreateHeader(); err != nil {
		t.Fatal(err.Error())
	}
}

func TestPublicSignerMarshalProto(t *testing.T) {
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err.Error())
	}

	ck, err := MarshalPublicSignerProto(s)
	if err != nil {
		t.Fatal(err.Error())
	}

	if _, err := UnmarshalVerifierProto(ck); err != nil {
		t.Fatal(err.Error())
	}
}

func TestVerifierFromX509(t *testing.T) {
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err.Error())
	}

	d := `
		commonname: "test",
		country: "US",
		state: "WA",
		organization: "Google",
	`

	x, err := s.CreateSelfSignedX509(d)
	if err != nil {
		t.Fatal(err.Error())
	}

	if _, err := FromX509(x); err != nil {
		t.Fatal(err.Error())
	}
}

func TestFromPrincipalName(t *testing.T) {
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err.Error())
	}

	name, err := s.ToPrincipalName()
	if err != nil {
		t.Fatal(err.Error())
	}

	v, err := FromPrincipalName(name)
	if err != nil {
		t.Fatal(err.Error())
	}

	name2, err := v.ToPrincipalName()
	if err != nil {
		t.Fatal(err.Error())
	}

	if name != name2 {
		t.Fatal("Verifier Principal name doesn't match the Signer name it was derived from")
	}
}

func TestSignAndVerify(t *testing.T) {
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err.Error())
	}

	name, err := s.ToPrincipalName()
	if err != nil {
		t.Fatal(err.Error())
	}

	v, err := FromPrincipalName(name)
	if err != nil {
		t.Fatal(err.Error())
	}

	data := []byte(`Test data to sign`)
	context := "Context string"
	sig, err := s.Sign(data, context)
	if err != nil {
		t.Fatal(err.Error())
	}

	if verifies, err := v.Verify(data, context, sig); err != nil || !verifies {
		if err != nil {
			t.Fatal(err.Error())
		} else {
			t.Fatal("The signature failed verification")
		}
	}
}

func TestNewCrypter(t *testing.T) {
	if _, err := GenerateCrypter(); err != nil {
		t.Fatal(err.Error())
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
	c, err := GenerateCrypter()
	if err != nil {
		t.Fatal(err.Error())
	}

	data := []byte("Test data to encrypt")
	crypted, err := c.Encrypt(data)
	if err != nil {
		t.Fatal(err.Error())
	}

	data2, err := c.Decrypt(crypted)
	if err != nil {
		t.Fatal(err.Error())
	}

	if len(data) != len(data2) {
		t.Fatal("The decrypted data was not the same length as the original data")
	}

	for i := range data {
		if data[i] != data2[i] {
			t.Fatal("The decrypted data was not the same as the original data")
		}
	}
}

func TestMarshalCrypterProto(t *testing.T) {
	c, err := GenerateCrypter()
	if err != nil {
		t.Fatal(err.Error())
	}

	ck, err := MarshalCrypterProto(c)
	if err != nil {
		t.Fatal(err.Error())
	}

	c2, err := UnmarshalCrypterProto(ck)
	if err != nil {
		t.Fatal(err.Error())
	}

	// Try encrypting with one and decrypting with the other.
	data := []byte("Test data to encrypt")
	crypted, err := c.Encrypt(data)
	if err != nil {
		t.Fatal(err.Error())
	}

	data2, err := c2.Decrypt(crypted)
	if err != nil {
		t.Fatal(err.Error())
	}

	if len(data) != len(data2) {
		t.Fatal("The decrypted data was not the same length as the original data")
	}

	for i := range data {
		if data[i] != data2[i] {
			t.Fatal("The decrypted data was not the same as the original data")
		}
	}
}

func TestNewDeriver(t *testing.T) {
	if _, err := GenerateDeriver(); err != nil {
		t.Fatal(err.Error())
	}
}

func TestDeriveSecret(t *testing.T) {
	d, err := GenerateDeriver()
	if err != nil {
		t.Fatal(err.Error())
	}

	salt := make([]byte, 20)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err.Error())
	}

	context := []byte("Test context")

	// Derive an AES-256 key.
	material := make([]byte, 32)
	if err := d.Derive(salt, context, material); err != nil {
		t.Fatal(err.Error())
	}

	material2 := make([]byte, 32)
	if err := d.Derive(salt, context, material2); err != nil {
		t.Fatal(err.Error())
	}

	if len(material) != len(material2) {
		t.Fatal("The Deriver generated two different lengths of keys")
	}

	for i := range material {
		if material[i] != material2[i] {
			t.Fatal("The Deriver is not deterministic")
		}
	}
}

func TestMarshalDeriver(t *testing.T) {
	d, err := GenerateDeriver()
	if err != nil {
		t.Fatal(err.Error())
	}

	ck, err := MarshalDeriverProto(d)
	if err != nil {
		t.Fatal(err.Error())
	}

	d2, err := UnmarshalDeriverProto(ck)
	if err != nil {
		t.Fatal(err.Error())
	}

	// Make sure both derivers derive the same keys given the same input.
	salt := make([]byte, 20)
	if _, err := rand.Read(salt); err != nil {
		t.Fatal(err.Error())
	}

	context := []byte("Test context")

	// Derive an AES-256 key.
	material := make([]byte, 32)
	if err := d.Derive(salt, context, material); err != nil {
		t.Fatal(err.Error())
	}

	material2 := make([]byte, 32)
	if err := d2.Derive(salt, context, material2); err != nil {
		t.Fatal(err.Error())
	}

	if len(material) != len(material2) {
		t.Fatal("The Deriver generated two different lengths of keys")
	}

	for i := range material {
		if material[i] != material2[i] {
			t.Fatal("The Deriver is not deterministic")
		}
	}
}
