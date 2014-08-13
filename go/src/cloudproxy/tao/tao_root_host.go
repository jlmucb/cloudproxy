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

	"cloudproxy/tao/auth"
)

// A TaoRootHost is a standalone implementation of TaoHost.
type TaoRootHost struct {
	keys        *Keys
	taoHostName string
}

// NewTaoRootHostFromKeys returns a TaoRootHost that uses these keys.
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
func (t *TaoRootHost) GetRandomBytes(childSubprin auth.SubPrin, n int) (bytes []byte, err error) {
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
	var salt []byte
	material := make([]byte, n)
	if err := t.keys.DerivingKey.Derive(salt, []byte(tag), material); err != nil {
		return nil, err
	}

	return material, nil
}

// Attest requests the Tao host sign a statement on behalf of the caller.
func (t *TaoRootHost) Attest(childSubprin auth.SubPrin, issuer *auth.Prin,
	time, expiration *int64, message auth.Form) (*Attestation, error) {

	child := t.taoHostName.MakeSubprincipal(childSubprin)
	if issuer != nil {
		if !auth.SubprinOrIdentical(*issuer, child) {
			return nil, errors.New("invalid issuer in statement")
		}
	} else {
		issuer = &child
	}

	stmt := Says{Speaker: *issuer, Time: time, Expiration: expiration, Message: message}

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

// AddedHostedProgram notifies this TaoHost that a new hosted program has been
// created.
func (t *TaoRootHost) AddedHostedProgram(childSubprin auth.SubPrin) error {
	return nil
}

// RemovedHostedProgram notifies this TaoHost that a hosted program has been
// killed.
func (t *TaoRootHost) RemovedHostedProgram(childSubprin auth.SubPrin) error {
	return nil
}

// TaoHostName gets the Tao principal name assigned to this hosted Tao host.
// The name encodes the full path from the root Tao, through all intermediary
// Tao hosts, to this hosted Tao host.
func (t *TaoRootHost) TaoHostName() string {
	return t.taoHostName
}
