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
	// "crypto/rand"
	// "io/ioutil"
	// "os"
	"testing"

	// "github.com/golang/protobuf/proto"
)

func TestGenerateKeys(t *testing.T) {
/*
 *	FIX
	if _, err := GenerateSigner(); err != nil {
		t.Fatal(err.Error())
	}
 */
}

func TestSignerDERSerialization(t *testing.T) {
/*
 *	FIX
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err.Error())
	}

	b, err := MarshalSignerDER(s)
	if err != nil {
		t.Fatal(err.Error())
	}

	if _, err := UnmarshalSignerDER(b); err != nil {
		t.Fatal(err.Error())
	}
 */
}

func TestSelfSignedX509(t *testing.T) {
/*
 *	FIX
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err.Error())
	}

	details := &X509Details{
		CommonName:   proto.String("test"),
		Country:      proto.String("US"),
		State:        proto.String("WA"),
		Organization: proto.String("Google"),
	}

	_, err = s.CreateSelfSignedX509(NewX509Name(details))
	if err != nil {
		t.Fatal(err.Error())
	}
 */
}

func TestSignerMarshalProto(t *testing.T) {
/*
 *	FIX
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
 */
}

func TestCreateHeader(t *testing.T) {
/*
 *	FIX
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err.Error())
	}

	if _, err := s.CreateHeader(); err != nil {
		t.Fatal(err.Error())
	}
/*
}

func TestPublicSignerMarshalProto(t *testing.T) {
/*
 *	FIX
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err.Error())
	}

	ck := MarshalPublicSignerProto(s)

	if _, err := UnmarshalVerifierProto(ck); err != nil {
		t.Fatal(err.Error())
	}
 */
}

func TestVerifierFromX509(t *testing.T) {
/*
 *	FIX
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err.Error())
	}

	details := &X509Details{
		CommonName:   proto.String("test"),
		Country:      proto.String("US"),
		State:        proto.String("WA"),
		Organization: proto.String("Google"),
	}

	x, err := s.CreateSelfSignedX509(NewX509Name(details))
	if err != nil {
		t.Fatal(err.Error())
	}

	if _, err := FromX509(x); err != nil {
		t.Fatal(err.Error())
	}
*/
}

func TestSignAndVerify(t *testing.T) {
/*
 *	FIX
	s, err := GenerateSigner()
	if err != nil {
		t.Fatal(err.Error())
	}

	v := s.GetVerifier()

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
*/
}

func TestNewCrypter(t *testing.T) {
	if _, err := GenerateCrypter(); err != nil {
		t.Fatal(err.Error())
	}
}

func TestEncryptAndDecrypt(t *testing.T) {
/*
 *	FIX
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
 */
}

func TestMarshalCrypterProto(t *testing.T) {
/*
 *	FIX
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
*/
}

func TestNewDeriver(t *testing.T) {
	if _, err := GenerateDeriver(); err != nil {
		t.Fatal(err.Error())
	}
}

func TestDeriveSecret(t *testing.T) {
/*
 *	FIX
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
*/
}

func TestMarshalDeriver(t *testing.T) {
/*
 *	FIX
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
*/
}

func TestNewTemporaryKeys(t *testing.T) {
/*
 *	FIX
	k, err := NewTemporaryKeys(Signing | Crypting | Deriving)
	if err != nil {
		t.Fatal("Couldn't initialize temporary keys:", err)
	}

	if k.SigningKey == nil || k.CryptingKey == nil || k.DerivingKey == nil {
		t.Fatal("Couldn't generate the right keys")
	}
 */
}

func TestNewOnDiskPBEKeys(t *testing.T) {
/*
 *	FIX
	tempDir, err := ioutil.TempDir("", "TestNewOnDiskPBEKeys")
	if err != nil {
		t.Fatal("Couldn't create a temporary directory:", err)
	}
	defer os.RemoveAll(tempDir)

	password := []byte(`don't use this password`)
	k, err := NewOnDiskPBEKeys(Signing|Crypting|Deriving, password, tempDir, nil)
	if err != nil {
		t.Fatal("Couldn't create on-disk PBE keys:", err)
	}

	if k.SigningKey == nil || k.CryptingKey == nil || k.DerivingKey == nil {
		t.Fatal("Couldn't generate the right keys")
	}

	_, err = NewOnDiskPBEKeys(Signing|Crypting|Deriving, password, tempDir, nil)
	if err != nil {
		t.Fatal("Couldn't recover the serialized keys:", err)
	}
 */
}

func TestNewOnDiskPBESigner(t *testing.T) {
/*
 *	FIX
	tempDir, err := ioutil.TempDir("", "TestNewOnDiskPBESigner")
	if err != nil {
		t.Fatal("Couldn't create a temporary directory:", err)
	}
	defer os.RemoveAll(tempDir)

	password := []byte(`don't use this password`)
	k, err := NewOnDiskPBEKeys(Signing, password, tempDir, nil)
	if err != nil {
		t.Fatal("Couldn't create on-disk PBE keys:", err)
	}

	if k.SigningKey == nil || k.CryptingKey != nil || k.DerivingKey != nil {
		t.Fatal("Couldn't generate the right keys")
	}

	_, err = NewOnDiskPBEKeys(Signing, password, tempDir, nil)
	if err != nil {
		t.Fatal("Couldn't recover the serialized keys:", err)
	}
*/
}

func TestTaoDelegatedKeys(t *testing.T) {
/*
 *	FIX
	ft, err := NewSoftTao("", nil)
	if err != nil {
		t.Fatal("Couldn't initialize a SoftTao:", err)
	}

	_, err = NewTemporaryTaoDelegatedKeys(Signing|Crypting|Deriving, ft)
	if err != nil {
		t.Fatal("Couldn't initialize a temporary hosted keyset:", err)
	}
 */
}

func TestNewOnDiskTaoSealedKeys(t *testing.T) {
/*
 *	FIX
	tempDir, err := ioutil.TempDir("", "TestInitHosted")
	if err != nil {
		t.Fatal(err.Error())
	}
	defer os.RemoveAll(tempDir)

	ft, err := NewSoftTao("", nil)
	if err != nil {
		t.Fatal("Couldn't initialize a SoftTao:", err)
	}

	_, err = NewOnDiskTaoSealedKeys(Signing|Crypting|Deriving, ft, tempDir, SealPolicyDefault)
	if err != nil {
		t.Fatal("Couldn't initialize a hosted keyset:", err)
	}

	_, err = NewOnDiskTaoSealedKeys(Signing|Crypting|Deriving, ft, tempDir, SealPolicyDefault)
	if err != nil {
		t.Fatal("Couldn't read back a sealed, hosted keyset:", err)
	}
*/
}

// Test generating a new set of keys and saving/loading them to/from the disk unsealed.
func TestUnsealedDelegatedKeysSaveLoad(t *testing.T) {
/*
 *	FIX
	tempDir, err := ioutil.TempDir("", "TestInitHosted")
	if err != nil {
		t.Fatal(err.Error())
	}
	defer os.RemoveAll(tempDir)

	ft, err := NewSoftTao("", nil)
	if err != nil {
		t.Error("Couldn't initialize a SoftTao:", err)
		return
	}

	k, err := NewTemporaryTaoDelegatedKeys(Signing|Crypting|Deriving, ft)
	if err != nil {
		t.Error("failed to generate keys:", err)
		return
	}

	if err = SaveKeyset(k, tempDir); err != nil {
		t.Error("failed to save keys:", err)
		return
	}

	if _, err = LoadKeys(Signing|Crypting|Deriving, nil, tempDir, SealPolicyDefault); err != nil {
		t.Error("failed to load keys:", err)
	}
*/
}

// Test generating a new set of keys and saving/loading them to/from the disk
// unsealed without a delegation.
func TestUnsealedUndelegatedKeysSaveLoad(t *testing.T) {
/*
 *	FIX
	tempDir, err := ioutil.TempDir("", "TestInitHosted")
	if err != nil {
		t.Fatal(err.Error())
	}
	defer os.RemoveAll(tempDir)

	k, err := NewTemporaryTaoDelegatedKeys(Signing|Crypting|Deriving, nil)
	if err != nil {
		t.Error("failed to generate keys:", err)
		return
	}

	if err = SaveKeyset(k, tempDir); err != nil {
		t.Error("failed to save keys:", err)
		return
	}

	if _, err = LoadKeys(Signing|Crypting|Deriving, nil, tempDir, SealPolicyDefault); err != nil {
		t.Error("failed to load keys:", err)
	}
*/
}

func TestCorruptedCiphertext(t *testing.T) {
/*
 *	FIX
	c, err := GenerateCrypter()
	if err != nil {
		t.Fatal(err.Error())
	}

	data := []byte("Test data to encrypt")
	crypted, err := c.Encrypt(data)
	if err != nil {
		t.Fatal(err.Error())
	}

	var ed EncryptedData
	if err := proto.Unmarshal(crypted, &ed); err != nil {
		t.Fatal("Could not unmarshal the encrypted data")
	}

	// Read random data for the ciphertext.
	if _, err := rand.Read(ed.Ciphertext); err != nil {
		t.Fatal("Could not read random data into the ciphertext")
	}

	crypted2, err := proto.Marshal(&ed)
	if err != nil {
		t.Fatal("Could not marshal the corrupted ciphertext")
	}

	if _, err := c.Decrypt(crypted2); err == nil {
		t.Fatal("Incorrectly succeeded at decrypting corrupted ciphertext")
	}

	// Corrupt each bit individually and make sure the test fails for any
	// single bit flip. The range is over the first ciphertext, but this is
	// identical to the range of the unmarshalled ciphertext in this loop.
	for i := range ed.Ciphertext {
		var ed2 EncryptedData
		if err := proto.Unmarshal(crypted, &ed2); err != nil {
			t.Fatal("Could not unmarshal the encrypted data a second time")
		}

		// Corrupt a single bit in the ciphertext.
		ed2.Ciphertext[i] ^= ed2.Ciphertext[i]

		crypted3, err := proto.Marshal(&ed2)
		if err != nil {
			t.Fatal("Could not marshal a second corrupted ciphertext")
		}

		if _, err := c.Decrypt(crypted3); err == nil {
			t.Fatal("Incorrectly succeeded at decrypting a second corrupted ciphertext")
		}
	}
*/
}
