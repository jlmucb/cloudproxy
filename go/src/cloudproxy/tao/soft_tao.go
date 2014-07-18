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
	"time"

	"code.google.com/p/goprotobuf/proto"
)

// A SoftTao is an implementation of the Tao that isn't backed by any hardware
// mechanisms.
type SoftTao struct {
	keys          *Keys
	name          string
	nameExtension string
}

// Init initializes the SoftTao with a crypter and a signer.
func (s *SoftTao) Init(name, path string, password []byte) error {
	s.name = name

	if path == "" {
		s.keys = NewTemporaryKeys(Signing | Crypting | Deriving)
		if err := s.keys.InitTemporary(); err != nil {
			return err
		}
	} else {
		s.keys = NewOnDiskKeys(Signing|Crypting|Deriving, path)
		if err := s.keys.InitWithPassword(password); err != nil {
			return err
		}
	}

	return nil
}

// GetTaoName returns the Tao principal name assigned to the caller.
func (s *SoftTao) GetTaoName() (string, error) {
	return s.name + s.nameExtension, nil
}

// ExtendTaoName irreversibly extends the Tao principal name of the caller.
func (s *SoftTao) ExtendTaoName(subprin string) error {
	if subprin == "" {
		return errors.New("invalid subprincipal name")
	}

	s.nameExtension += "::" + subprin
	return nil
}

// GetRandomBytes fills the slice with random bytes.
func (s *SoftTao) GetRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}

// Read implements io.Reader to read random bytes from the Tao.
func (s *SoftTao) Read(p []byte) (int, error) {
	bytes, err := s.GetRandomBytes(len(p))
	if err != nil {
		return 0, err
	}

	copy(p, bytes)
	return len(p), nil
}

// Rand returns an io.Reader for the SoftTao's source of randomness.
func (s *SoftTao) Rand() io.Reader {
	return s
}

// GetShareSecret returns a slice of n secret bytes.
func (s *SoftTao) GetSharedSecret(n int, policy string) ([]byte, error) {
	if policy != SharedSecretPolicyDefault {
		return nil, errors.New("SoftTao policies not yet implemented")
	}

	// TODO(tmroeder): for now, we're using a fixed salt and counting on
	// the strength of HKDF with a strong key.
	salt := make([]byte, 8)
	material := make([]byte, n)
	if err := s.keys.DerivingKey.Derive(salt, []byte("derive shared secret"), material); err != nil {
		return nil, err
	}

	return material, nil
}

// Seal encrypts the data in a way that can only be opened by the Tao for the
// program that sealed it.  In the case of the SoftTao, this policy is
// implicit.
func (s *SoftTao) Seal(data []byte, policy string) ([]byte, error) {
	// The SoftTao insists on the trivial policy, since it just encrypts the bytes directly
	if policy != SealPolicyDefault {
		return nil, errors.New("The SoftTao requires SealPolicyDefault")
	}

	return s.keys.CryptingKey.Encrypt(data)
}

// Unseal decrypts data that has been sealed by the Seal operation, but only if
// the policy specified during the Seal operation is satisfied.
func (s *SoftTao) Unseal(sealed []byte) (data []byte, policy string, err error) {
	data, err = s.keys.CryptingKey.Decrypt(sealed)
	policy = SealPolicyDefault
	return data, policy, err
}

// Attest requests that the Tao host sign a Statement on behalf of the caller.
func (s *SoftTao) Attest(stmt *Statement) (*Attestation, error) {
	st := new(Statement)
	proto.Merge(st, stmt)

	if st.Issuer == nil {
		st.Issuer = proto.String(s.name)
	} else if st.GetIssuer() != s.name {
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

	sig, err := s.keys.SigningKey.Sign(ser, AttestationSigningContext)
	if err != nil {
		return nil, err
	}

	a := &Attestation{
		SerializedStatement: ser,
		Signature:           sig,
		Signer:              proto.String(s.name),
	}

	if s.keys.Delegation != nil {
		sd, err := proto.Marshal(s.keys.Delegation)
		if err != nil {
			return nil, err
		}

		a.SerializedDelegation = sd
	}

	return a, nil
}
