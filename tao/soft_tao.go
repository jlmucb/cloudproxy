//  Copyright (c 2015, Google Inc.  All rights reserved.
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

	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/tao/auth"
)

// A SoftTao is an implementation of the Tao that isn't backed by any hardware
// mechanisms. It's used for testing components that rely on the Tao.
type SoftTao struct {
	keys          *Keys
	name          auth.Prin
	nameExtension auth.SubPrin
}

// Init initializes the SoftTao with a crypter and a signer.
func NewSoftTao(path string, password []byte) (Tao, error) {
	s := &SoftTao{}

	var err error
	if path == "" {
		s.keys, err = NewTemporaryKeys(Signing | Crypting | Deriving)
	} else {
		s.keys, err = NewOnDiskPBEKeys(Signing|Crypting|Deriving, password, path, nil)
	}

	s.name = s.keys.VerifyingKey.ToPrincipal()

	if err != nil {
		return nil, err
	}

	return s, nil
}

// GetTaoName returns the Tao principal name assigned to the caller.
func (s *SoftTao) GetTaoName() (auth.Prin, error) {
	return s.name.MakeSubprincipal(s.nameExtension), nil
}

// ExtendTaoName irreversibly extends the Tao principal name of the caller.
func (s *SoftTao) ExtendTaoName(subprin auth.SubPrin) error {
	s.nameExtension = append(s.nameExtension, subprin...)
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
		return nil, newError("SoftTao policies not yet implemented")
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
		return nil, newError("The SoftTao requires SealPolicyDefault")
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

// Attest requests that the Tao host sign a statement on behalf of the caller.
func (s *SoftTao) Attest(issuer *auth.Prin, time, expiration *int64, message auth.Form) (*Attestation, error) {
	child := s.name.MakeSubprincipal(s.nameExtension)
	if issuer == nil {
		issuer = &child
	} else if !auth.SubprinOrIdentical(issuer, child) {
		return nil, newError("Invalid issuer in statement: %s may not speak for %s", child, issuer)
	}

	stmt := auth.Says{Speaker: *issuer, Time: time, Expiration: expiration, Message: message}

	var delegation []byte
	if s.keys.Delegation != nil {
		var err error
		delegation, err = proto.Marshal(s.keys.Delegation)
		if err != nil {
			return nil, err
		}
	}

	return GenerateAttestation(s.keys.SigningKey, delegation, stmt)
}

// GetVerifier returns the verifying key for this Tao.
func (s *SoftTao) GetVerifier() *Verifier {
	return s.keys.VerifyingKey
}
