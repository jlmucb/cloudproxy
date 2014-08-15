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
	"io"
	mrand "math/rand"
	"testing"
	"time"

	"code.google.com/p/goprotobuf/proto"

	"cloudproxy/tao/auth"
)

// A FakeTao is an implementation of the Tao that isn't backed by any hardware
// mechanisms. It's used for testing components that rely on the Tao.
type FakeTao struct {
	keys          *Keys
	name          auth.Prin
	nameExtension auth.SubPrin
}

// Init initializes the FakeTao with a crypter and a signer.
func NewFakeTao(name auth.Prin, path string, password []byte) (Tao, error) {
	f := &FakeTao{
		name: name,
	}

	var err error
	if path == "" {
		f.keys, err = NewTemporaryKeys(Signing | Crypting | Deriving)
	} else {
		f.keys, err = NewOnDiskPBEKeys(Signing|Crypting|Deriving, password, path, nil)
	}

	if err != nil {
		return nil, err
	}

	return f, nil
}

// GetTaoName returns the Tao principal name assigned to the caller.
func (f *FakeTao) GetTaoName() (auth.Prin, error) {
	return f.name.MakeSubprincipal(f.nameExtension), nil
}

// ExtendTaoName irreversibly extends the Tao principal name of the caller.
func (f *FakeTao) ExtendTaoName(subprin auth.SubPrin) error {
	f.nameExtension = append(f.nameExtension, subprin...)
	return nil
}

// GetRandomBytes fills the slice with random bytes.
func (f *FakeTao) GetRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}

// Read implements io.Reader to read random bytes from the Tao.
func (f *FakeTao) Read(p []byte) (int, error) {
	bytes, err := f.GetRandomBytes(len(p))
	if err != nil {
		return 0, err
	}

	copy(p, bytes)
	return len(p), nil
}

// Rand returns an io.Reader for the FakeTao's source of randomness.
func (f *FakeTao) Rand() io.Reader {
	return f
}

// GetShareSecret returns a slice of n secret bytes.
func (f *FakeTao) GetSharedSecret(n int, policy string) ([]byte, error) {
	if policy != SharedSecretPolicyDefault {
		return nil, newError("FakeTao policies not yet implemented")
	}

	// TODO(tmroeder): for now, we're using a fixed salt and counting on
	// the strength of HKDF with a strong key.
	salt := make([]byte, 8)
	material := make([]byte, n)
	if err := f.keys.DerivingKey.Derive(salt, []byte("derive shared secret"), material); err != nil {
		return nil, err
	}

	return material, nil
}

// Seal encrypts the data in a way that can only be opened by the Tao for the
// program that sealed it.  In the case of the FakeTao, this policy is
// implicit.
func (f *FakeTao) Seal(data []byte, policy string) ([]byte, error) {
	// The FakeTao insists on the trivial policy, since it just encrypts the bytes directly
	if policy != SealPolicyDefault {
		return nil, newError("The FakeTao requires SealPolicyDefault")
	}

	return f.keys.CryptingKey.Encrypt(data)
}

// Unseal decrypts data that has been sealed by the Seal operation, but only if
// the policy specified during the Seal operation is satisfied.
func (f *FakeTao) Unseal(sealed []byte) (data []byte, policy string, err error) {
	data, err = f.keys.CryptingKey.Decrypt(sealed)
	policy = SealPolicyDefault
	return data, policy, err
}

// Attest requests that the Tao host sign a statement on behalf of the caller.
func (f *FakeTao) Attest(issuer *auth.Prin, time, expiration *int64, message auth.Form) (*Attestation, error) {

	if issuer == nil {
		issuer = &f.name
	} else if !issuer.Identical(f.name) {
		return nil, newError("Invalid issuer in statement")
	}

	stmt := auth.Says{Speaker: *issuer, Time: time, Expiration: expiration, Message: message}

	var delegation []byte
	if f.keys.Delegation != nil {
		var err error
		delegation, err = proto.Marshal(f.keys.Delegation)
		if err != nil {
			return nil, err
		}
	}

	return GenerateAttestation(f.keys.SigningKey, delegation, stmt)
}

func TestInMemoryInit(t *testing.T) {
	_, err := NewFakeTao(auth.Prin{Type: "key", Key: []byte("test")}, "", nil)
	if err != nil {
		t.Fatal("Couldn't initialize a FakeTao in memory:", err)
	}
}

func TestFakeTaoRandom(t *testing.T) {
	ft, err := NewFakeTao(auth.Prin{Type: "key", Key: []byte("test")}, "", nil)
	if err != nil {
		t.Fatal("Couldn't initialize a FakeTao in memory:", err)
	}

	if _, err := ft.GetRandomBytes(10); err != nil {
		t.Fatal("Couldn't get 10 random bytes:", err)
	}
}

func TestFakeTaoSeal(t *testing.T) {
	ft, err := NewFakeTao(auth.Prin{Type: "key", Key: []byte("test")}, "", nil)
	if err != nil {
		t.Fatal("Couldn't initialize a FakeTao in memory:", err)
	}

	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 33)
	for i := range b {
		b[i] = byte(r.Intn(256))
	}

	_, err = ft.Seal(b, SealPolicyDefault)
	if err != nil {
		t.Fatal("Couldn't seal data in the FakeTao under the default policy:", err)
	}
}

func TestFakeTaoUnseal(t *testing.T) {
	ft, err := NewFakeTao(auth.Prin{Type: "key", Key: []byte("test")}, "", nil)
	if err != nil {
		t.Fatal("Couldn't initialize a FakeTao in memory:", err)
	}

	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 33)
	for i := range b {
		b[i] = byte(r.Intn(256))
	}

	s, err := ft.Seal(b, SealPolicyDefault)
	if err != nil {
		t.Fatal("Couldn't seal data in the FakeTao under the default policyL", err)
	}

	u, p, err := ft.Unseal(s)
	if string(p) != SealPolicyDefault {
		t.Fatal("Invalid policy returned by Unseal")
	}

	if len(u) != len(b) {
		t.Fatal("Invalid unsealed length")
	}

	for i, v := range u {
		if v != b[i] {
			t.Fatalf("Incorrect byte at position %d", i)
		}
	}
}

func TestFakeTaoAttest(t *testing.T) {
	ft, err := NewFakeTao(auth.Prin{Type: "key", Key: []byte("test")}, "", nil)
	if err != nil {
		t.Fatal("Couldn't initialize a FakeTao in memory:", err)
	}

	stmt := auth.Speaksfor{
		Delegate: auth.Prin{Type: "key", Key: []byte("BogusKeyBytes1")},
	}

	_, err = ft.Attest(nil, nil, nil, stmt)
	if err != nil {
		t.Fatal("Couldn't attest to a statement in the FakeTao:", err)
	}
}
