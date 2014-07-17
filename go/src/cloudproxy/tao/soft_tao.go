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
	"time"

	"code.google.com/p/goprotobuf/proto"
)

// A SoftTao is an implementation of the Tao that isn't backed by any hardware
// mechanisms.
type SoftTao struct {
	keys *Keys
	name string
}

// Init initializes the SoftTao with a crypter and a signer.
func (s *SoftTao) Init(name, path string, password []byte) error {
	s.name = name

	if path == "" {
		s.keys = NewTemporaryKeys(Signing | Crypting)
		if err := s.keys.InitTemporary(); err != nil {
			return err
		}
	} else {
		s.keys = NewOnDiskKeys(Signing|Crypting, path)
		if err := s.keys.InitWithPassword(password); err != nil {
			return err
		}
	}

	return nil
}

// GetRandomBytes fills the slice with random bytes.
func (s *SoftTao) GetRandomBytes(bytes []byte) error {
	if _, err := rand.Read(bytes); err != nil {
		return err
	}

	return nil
}

// Seal encrypts the data in a way that can only be opened by the Tao for the
// program that sealed it.  In the case of the SoftTao, this policy is
// implicit.
func (s *SoftTao) Seal(data, policy []byte) ([]byte, error) {
	// The SoftTao insists on the trivial policy, since it just encrypts the bytes directly
	if string(policy) != SealPolicyDefault {
		return nil, errors.New("The SoftTao requires SealPolicyDefault")
	}

	return s.keys.CryptingKey.Encrypt(data)
}

func (s *SoftTao) Unseal(sealed []byte) (data, policy []byte, err error) {
	data, err = s.keys.CryptingKey.Decrypt(sealed)
	policy = []byte(SealPolicyDefault)
	return data, policy, err
}

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
		st.Expiration = proto.Int64(st.GetTime() + DefaultAttestTimeout)
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
