// Copyright (c) 2014, Google Inc.  All rights reserved.
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
	"strings"
	"time"

	"code.google.com/p/goprotobuf/proto"
)

// A TaoRootHost is a standalone implementation of TaoHost.
type TaoRootHost struct {
	keys        *Keys
	taoHostName string
}

// NewTaoRootHostFromKeys takes ownership of an existing set of keys and
// returns a TaoRootHost that uses these keys.
func NewTaoRootHostFromKeys(k *Keys) (TaoHost, error) {
	if k.SigningKey == nil || k.CryptingKey == nil || k.VerifyingKey == nil {
		return nil, errors.New("missing required key for TaoRootHost")
	}

	n, err := k.SigningKey.ToPrincipalName()
	if err != nil {
		return nil, err
	}

	t := &TaoRootHost{
		keys:        k,
		taoHostName: n,
	}

	return t, nil
}

// NewTaoRootHost generates a new TaoRootHost with a fresh set of temporary
// keys.
func NewTaoRootHost() (TaoHost, error) {
	k, err := NewTemporaryKeys(Signing | Crypting)
	if err != nil {
		return nil, err
	}

	return NewTaoRootHostFromKeys(k)
}

// GetRandomBytes returns a slice of n random bytes.
func (t *TaoRootHost) GetRandomBytes(childSubprin string, n int) (bytes []byte, err error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}

// GetSharedSecret returns a slice of n secret bytes.
func (t *TaoRootHost) GetSharedSecret(tag string, n int) (bytes []byte, err error) {
	if t.keys.DerivingKey == nil {
		return nil, errors.New("this TaoRootHost does not implement shared secrets")
	}

	// For now, all our key deriving with keys.DerivingKey uses a fixed 0-length salt.
	salt := make([]byte, 0)
	material := make([]byte, n)
	if err := t.keys.DerivingKey.Derive(salt, []byte(tag), material); err != nil {
		return nil, err
	}

	return material, nil
}

// GenerateAttestation uses the signing key to generate an attestation for this
// statement.
func GenerateAttestation(s *Signer, delegation []byte, stmt *Statement) (*Attestation, error) {
	signerName, err := s.ToPrincipalName()
	if err != nil {
		return nil, err
	}

	st := new(Statement)
	proto.Merge(st, stmt)

	t := time.Now()
	if st.Time == nil {
		st.Time = proto.Int64(t.UnixNano())
	}

	if st.Expiration == nil {
		st.Expiration = proto.Int64(t.Add(365 * 24 * time.Hour).UnixNano())
	}

	ser, err := proto.Marshal(st)
	if err != nil {
		return nil, err
	}

	sig, err := s.Sign(ser, AttestationSigningContext)
	if err != nil {
		return nil, err
	}

	a := &Attestation{
		SerializedStatement: ser,
		Signature:           sig,
		Signer:              proto.String(signerName),
	}

	if len(delegation) > 0 {
		a.SerializedDelegation = delegation
	}

	return a, nil
}

// IsSubprincipalOrIdentical checks that the child name either is identical to
// to the parent name or starts with "parentName::".
func IsSubprincipalOrIdentical(childName, parentName string) bool {
	return (childName == parentName) || strings.HasPrefix(childName, parentName+"::")
}

// Attest requests the Tao host sign a Statement on behalf of the caller.
func (t *TaoRootHost) Attest(childSubprin string, stmt *Statement) (*Attestation, error) {
	if stmt.Issuer != nil {
		if !IsSubprincipalOrIdentical(*stmt.Issuer, t.taoHostName+"::"+childSubprin) {
			return nil, errors.New("invalid issuer in statement")
		}
	} else {
		stmt.Issuer = proto.String(t.taoHostName + "::" + childSubprin)
	}

	return GenerateAttestation(t.keys.SigningKey, nil /* delegation */, stmt)
}

// Encrypt data so that only this host can access it.
func (t *TaoRootHost) Encrypt(data []byte) (encrypted []byte, err error) {
	return t.keys.CryptingKey.Encrypt(data)
}

// Decrypt data that only this host can access.
func (t *TaoRootHost) Decrypt(encrypted []byte) (data []byte, err error) {
	return t.keys.CryptingKey.Decrypt(encrypted)
}

// Notify this TaoHost that a new hosted program has been created.
func (t *TaoRootHost) AddedHostedProgram(childSubprin string) error {
	return nil
}

// Notify this TaoHost that a hosted program has been killed.
func (t *TaoRootHost) RemovedHostedProgram(childSubprin string) error {
	return nil
}

// Get the Tao principal name assigned to this hosted Tao host. The
// name encodes the full path from the root Tao, through all
// intermediary Tao hosts, to this hosted Tao host.
func (t *TaoRootHost) TaoHostName() string {
	return t.taoHostName
}
