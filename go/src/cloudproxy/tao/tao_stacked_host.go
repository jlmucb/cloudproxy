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
	"errors"

	"code.google.com/p/goprotobuf/proto"
)

// A TaoStackedHost implements TaoHost over an existing host Tao.
type TaoStackedHost struct {
	taoHostName string
	hostTao     Tao
	keys        *Keys
}

// NewTaoStackedHostFromKeys takes ownership of an existing set of keys and
// returns a TaoStackedHost that uses these keys over an existing host Tao.
func NewTaoStackedHostFromKeys(k *Keys, t Tao) (TaoHost, error) {
	n, err := t.GetTaoName()
	if err != nil {
		return nil, err
	}

	tsh := &TaoStackedHost{
		keys:        k,
		taoHostName: n,
		hostTao:     t,
	}

	return tsh, nil
}

// NewTaoStackedHost generates a new TaoStackedHost with a fresh set of temporary
// keys.
func NewTaoStackedHost(t Tao) (TaoHost, error) {
	k, err := NewTemporaryKeys(Signing | Crypting)
	if err != nil {
		return nil, err
	}

	return NewTaoStackedHostFromKeys(k, t)
}

// GetRandomBytes returns a slice of n random bytes.
func (t *TaoStackedHost) GetRandomBytes(childSubprin string, n int) (bytes []byte, err error) {
	return t.hostTao.GetRandomBytes(n)
}

// GetSharedSecret returns a slice of n secret bytes.
func (t *TaoStackedHost) GetSharedSecret(tag string, n int) (bytes []byte, err error) {
	// TODO(tmroeder): this should be implemented using the underlying host
	if t.keys.DerivingKey == nil {
		return nil, errors.New("this TaoStackedHost does not implement shared secrets")
	}

	// For now, all our key deriving with keys.DerivingKey uses a fixed 0-length salt.
	var salt []byte
	material := make([]byte, n)
	if err := t.keys.DerivingKey.Derive(salt, []byte(tag), material); err != nil {
		return nil, err
	}

	return material, nil
}

// Attest requests the Tao host sign a Statement on behalf of the caller.
func (t *TaoStackedHost) Attest(childSubprin string, stmt *Statement) (*Attestation, error) {
	if stmt.Issuer != nil {
		if !IsSubprincipalOrIdentical(*stmt.Issuer, t.taoHostName+"::"+childSubprin) {
			return nil, errors.New("invalid issuer in statement")
		}
	} else {
		stmt.Issuer = proto.String(t.taoHostName + "::" + childSubprin)
	}

	if t.keys == nil || t.keys.SigningKey == nil {
		return t.hostTao.Attest(stmt)
	}

	var d []byte
	if t.keys.Delegation != nil {
		var err error
		d, err = proto.Marshal(t.keys.Delegation)
		if err != nil {
			return nil, err
		}
	}

	return GenerateAttestation(t.keys.SigningKey, d, stmt)
}

// Encrypt data so that only this host can access it.
func (t *TaoStackedHost) Encrypt(data []byte) (encrypted []byte, err error) {
	if t.keys == nil || t.keys.CryptingKey == nil {
		// TODO(tmroeder) (from TODO(kwalsh) in tao_stacked_host.cc):
		// where should the policy come from here?
		return t.hostTao.Seal(data, SealPolicyDefault)
	}
	
	return t.keys.CryptingKey.Encrypt(data)
}

// Decrypt data that only this host can access.
func (t *TaoStackedHost) Decrypt(encrypted []byte) (data []byte, err error) {
	if t.keys != nil && t.keys.CryptingKey != nil {
		return t.keys.CryptingKey.Decrypt(encrypted)
	}

	// TODO(tmroeder) (from TODO(kwalsh) in tao_stacked_host.cc):
	// where should the policy come from here?
	var policy string
	data, policy, err = t.hostTao.Unseal(encrypted)
	if err != nil {
		return nil, err
	}

	if policy != SealPolicyDefault {
		return nil, errors.New("unsealed data with uncertain provenance")
	}

	return data, nil
}

// AddedHostedProgram notifies this TaoHost that a new hosted program has been
// created.
func (t *TaoStackedHost) AddedHostedProgram(childSubprin string) error {
	return nil
}

// RemovedHostedProgram notifies this TaoHost that a hosted program has been
// killed.
func (t *TaoStackedHost) RemovedHostedProgram(childSubprin string) error {
	return nil
}

// TaoHostName gets the Tao principal name assigned to this hosted Tao host.
// The name encodes the full path from the root Tao, through all intermediary
// Tao hosts, to this hosted Tao host.
func (t *TaoStackedHost) TaoHostName() string {
	return t.taoHostName
}
