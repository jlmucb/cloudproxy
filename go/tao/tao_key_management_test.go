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
	//"crypto/aes"
	//"crypto/rand"
	//"crypto/sha256"
	"crypto/x509"
	"io/ioutil"
	"os"
	"testing"

	"github.com/golang/protobuf/proto"
)

// -------------------------------------------------------------

// Temporary
const (
	Basic128BitCipherSuite = "sign:ecdsap256,crypt:aes128-ctr-hmacsha256,derive:hdkf-sha256"
	Basic256BitCipherSuite = "sign:ecdsap384,crypt:aes256-ctr-hmacsha384,derive:hdkf-sha256"
)

var TaoCryptoSuite string

// -------------------------------------------------------------

func TestNewTemporaryKeys(t *testing.T) {
	TaoCryptoSuite = "sign:ecdsap256,crypt:aes128-ctr-hmacsha256,derive:hdkf-sha256"
	k, err := NewTemporaryKeys(Signing | Crypting | Deriving)
	if err != nil {
		t.Fatal("Couldn't initialize temporary keys:", err)
	}

	if k.SigningKey == nil || k.CryptingKey == nil || k.DerivingKey == nil {
		t.Fatal("Couldn't generate the right keys")
	}

	_, err = proto.Marshal(k.SigningKey.header)
	if err != nil {
		t.Fatal("Couldn't marshal signing key")
	}
	_, err = proto.Marshal(k.CryptingKey.header)
	if err != nil {
		t.Fatal("Couldn't marshal crypting key")
	}
	_, err = proto.Marshal(k.DerivingKey.header)
	if err != nil {
		t.Fatal("Couldn't marshal deriving key")
	}
}

func TestSelfSignedX509(t *testing.T) {
	keyName := "Temporary_Keys_signer"
	keyType := SignerTypeFromSuiteName(TaoCryptoSuite)
	keyPurpose := "signing"
	keyStatus := "active"
	keyEpoch := int32(1)
	s, err := InitializeSigner(nil, *keyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if err != nil {
		t.Fatal(err.Error())
	}

	details := &X509Details{
		CommonName:   proto.String("test"),
		Country:      proto.String("US"),
		State:        proto.String("WA"),
		Organization: proto.String("Google"),
	}

	pkInt := PublicKeyAlgFromSignerAlg(*keyType)
	sigInt := SignatureAlgFromSignerAlg(*keyType)
	if pkInt < 0 || sigInt < 0 {
		t.Fatal("Unknown Algorithm identifiers")
	}
	_, nil := s.CreateSelfSignedX509(pkInt, sigInt, int64(1), NewX509Name(details))
	if err != nil {
		t.Fatal(err.Error())
	}
}

func TestNewOnDiskPBEKeys(t *testing.T) {
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
}

func TestVerifierFromX509(t *testing.T) {
	keyName := "Temporary_Keys_signer"
	keyType := SignerTypeFromSuiteName(TaoCryptoSuite)
	keyPurpose := "signing"
	keyStatus := "active"
	keyEpoch := int32(1)
	s, err := InitializeSigner(nil, *keyType, &keyName, &keyEpoch, &keyPurpose, &keyStatus)
	if err != nil {
		t.Fatal(err.Error())
	}

	details := &X509Details{
		CommonName:   proto.String("test"),
		Country:      proto.String("US"),
		State:        proto.String("WA"),
		Organization: proto.String("Google"),
	}

	pkInt := PublicKeyAlgFromSignerAlg(*keyType)
	sigInt := SignatureAlgFromSignerAlg(*keyType)
	if pkInt < 0 || sigInt < 0 {
		t.Fatal("Unknown Algorithm identifiers")
	}
	cert, nil := s.CreateSelfSignedX509(pkInt, sigInt, int64(1), NewX509Name(details))
	if err != nil {
		t.Fatal(err.Error())
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	_, err = cert.Verify(opts)
	if err != nil {
		t.Fatal("Failed to verify certificate: ", err, "\n")
	}
}

func TestNewOnDiskPBESigner(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "TestNewOnDiskPBESigner")
	if err != nil {
		t.Fatal("Couldn't create a temporary directory:", err)
	}
	defer os.RemoveAll(tempDir)

	password := []byte(`don't use this password`)
	k, err := NewOnDiskPBEKeys(Signing, password, tempDir, nil)
	if k == nil || err != nil {
		t.Fatal("Couldn't create on-disk PBE keys:", err)
	}

	// FIX?

	if k.SigningKey == nil || k.CryptingKey != nil || k.DerivingKey != nil {
		t.Fatal("Couldn't generate the right keys")
	}

	_, err = NewOnDiskPBEKeys(Signing, password, tempDir, nil)
	if err != nil {
		t.Fatal("Couldn't recover the serialized keys:", err)
	}
}


// TODO

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
