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
	"errors"
	"io"
	mrand "math/rand"
	"testing"
	"time"

	"code.google.com/p/goprotobuf/proto"
)

// A FakeTao is an implementation of the Tao that isn't backed by any hardware
// mechanisms. It's used for testing components that rely on the Tao.
type FakeTao struct {
	keys          *Keys
	name          string
	nameExtension string
}

// Init initializes the FakeTao with a crypter and a signer.
func (f *FakeTao) Init(name, path string, password []byte) error {
	f.name = name

	if path == "" {
		f.keys = NewTemporaryKeys(Signing | Crypting | Deriving)
		if err := f.keys.InitTemporary(); err != nil {
			return err
		}
	} else {
		f.keys = NewOnDiskKeys(Signing|Crypting|Deriving, path)
		if err := f.keys.InitWithPassword(password); err != nil {
			return err
		}
	}

	return nil
}

// GetTaoName returns the Tao principal name assigned to the caller.
func (f *FakeTao) GetTaoName() (string, error) {
	return f.name + f.nameExtension, nil
}

// ExtendTaoName irreversibly extends the Tao principal name of the caller.
func (f *FakeTao) ExtendTaoName(subprin string) error {
	if subprin == "" {
		return errors.New("invalid subprincipal name")
	}

	f.nameExtension += "::" + subprin
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
		return nil, errors.New("FakeTao policies not yet implemented")
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
		return nil, errors.New("The FakeTao requires SealPolicyDefault")
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

// Attest requests that the Tao host sign a Statement on behalf of the caller.
func (f *FakeTao) Attest(stmt *Statement) (*Attestation, error) {
	st := new(Statement)
	proto.Merge(st, stmt)

	if st.Issuer == nil {
		st.Issuer = proto.String(f.name)
	} else if st.GetIssuer() != f.name {
		return nil, errors.New("Invalid issuer in statement")
	}

	if st.Time == nil {
		st.Time = proto.Int64(time.Now().UnixNano())
	}

	if st.Expiration == nil {
		st.Expiration = proto.Int64(time.Now().Add(365 * 24 * time.Hour).UnixNano())
	}

	ser, err := proto.Marshal(st)
	if err != nil {
		return nil, err
	}

	sig, err := f.keys.SigningKey.Sign(ser, AttestationSigningContext)
	if err != nil {
		return nil, err
	}

	a := &Attestation{
		SerializedStatement: ser,
		Signature:           sig,
		Signer:              proto.String(f.name),
	}

	if f.keys.Delegation != nil {
		sd, err := proto.Marshal(f.keys.Delegation)
		if err != nil {
			return nil, err
		}

		a.SerializedDelegation = sd
	}

	return a, nil
}

func TestInMemoryInit(t *testing.T) {
	ft := new(FakeTao)
	if err := ft.Init("test", "", nil); err != nil {
		t.Error(err.Error())
	}
}

func TestFakeTaoRandom(t *testing.T) {
	ft := new(FakeTao)
	if err := ft.Init("test", "", nil); err != nil {
		t.Error(err.Error())
	}

	if _, err := ft.GetRandomBytes(10); err != nil {
		t.Error(err.Error())
	}
}

func TestFakeTaoSeal(t *testing.T) {
	ft := new(FakeTao)
	if err := ft.Init("test", "", nil); err != nil {
		t.Error(err.Error())
	}

	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 33)
	for i := range b {
		b[i] = byte(r.Intn(256))
	}

	_, err := ft.Seal(b, SealPolicyDefault)
	if err != nil {
		t.Error(err.Error())
	}
}

func TestFakeTaoUnseal(t *testing.T) {
	ft := new(FakeTao)
	if err := ft.Init("test", "", nil); err != nil {
		t.Error(err.Error())
	}

	r := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	b := make([]byte, 33)
	for i := range b {
		b[i] = byte(r.Intn(256))
	}

	s, err := ft.Seal(b, SealPolicyDefault)
	if err != nil {
		t.Error(err.Error())
	}

	u, p, err := ft.Unseal(s)
	if string(p) != SealPolicyDefault {
		t.Error("Invalid policy returned by Unseal")
	}

	if len(u) != len(b) {
		t.Error("Invalid unsealed length")
	}

	for i, v := range u {
		if v != b[i] {
			t.Errorf("Incorrect byte at position %d", i)
		}
	}
}

func TestFakeTaoAttest(t *testing.T) {
	ft := new(FakeTao)
	if err := ft.Init("test", "", nil); err != nil {
		t.Error(err.Error())
	}

	stmt := &Statement{
		Delegate: proto.String("Test Principal"),
	}

	_, err := ft.Attest(stmt)
	if err != nil {
		t.Error(err.Error())
	}
}
