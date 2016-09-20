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
	"github.com/golang/protobuf/proto"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

// A StackedHost implements Host over an existing host Tao.
type StackedHost struct {
	taoHostName auth.Prin
	hostTao     Tao
	keys        *Keys
}

// NewTaoStackedHostFromKeys takes ownership of an existing set of keys and
// returns a StackedHost that uses these keys over an existing host Tao.
func NewTaoStackedHostFromKeys(k *Keys, t Tao) (Host, error) {
	n, err := t.GetTaoName()
	if err != nil {
		return nil, err
	}

	tsh := &StackedHost{
		keys:        k,
		taoHostName: n,
		hostTao:     t,
	}

	return tsh, nil
}

// NewTaoStackedHost generates a new StackedHost with a fresh set of temporary
// keys.
func NewTaoStackedHost(t Tao) (Host, error) {
	k, err := NewTemporaryKeys(Signing | Crypting)
	if err != nil {
		return nil, err
	}

	return NewTaoStackedHostFromKeys(k, t)
}

// GetRandomBytes returns a slice of n random bytes.
func (t *StackedHost) GetRandomBytes(childSubprin auth.SubPrin, n int) (bytes []byte, err error) {
	return t.hostTao.GetRandomBytes(n)
}

// GetSharedSecret returns a slice of n secret bytes.
func (t *StackedHost) GetSharedSecret(tag string, n int) (bytes []byte, err error) {
	// TODO(tmroeder): this should be implemented using the underlying host
	if t.keys.DerivingKey == nil {
		return nil, newError("this StackedHost does not implement shared secrets")
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
func (t *StackedHost) Attest(childSubprin auth.SubPrin, issuer *auth.Prin,
	time, expiration *int64, message auth.Form) (*Attestation, error) {

	child := t.taoHostName.MakeSubprincipal(childSubprin)
	if issuer != nil {
		if !auth.SubprinOrIdentical(*issuer, child) {
			return nil, newError("invalid issuer in statement")
		}
	} else {
		issuer = &child
	}

	if t.keys == nil || t.keys.SigningKey == nil {
		return t.hostTao.Attest(issuer, time, expiration, message)
	}

	stmt := auth.Says{Speaker: *issuer, Time: time, Expiration: expiration, Message: message}

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
func (t *StackedHost) Encrypt(data []byte) (encrypted []byte, err error) {
	if t.keys == nil || t.keys.CryptingKey == nil {
		// TODO(tmroeder) (from TODO(kwalsh) in tao_stacked_host.cc):
		// where should the policy come from here?
		return t.hostTao.Seal(data, SealPolicyDefault)
	}

	return t.keys.CryptingKey.Encrypt(data)
}

// Decrypt data that only this host can access.
func (t *StackedHost) Decrypt(encrypted []byte) (data []byte, err error) {
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
		return nil, newError("unsealed data with uncertain provenance")
	}

	return data, nil
}

// AddedHostedProgram notifies this Host that a new hosted program has been
// created.
func (t *StackedHost) AddedHostedProgram(childSubprin auth.SubPrin) error {
	return nil
}

// RemovedHostedProgram notifies this Host that a hosted program has been
// killed.
func (t *StackedHost) RemovedHostedProgram(childSubprin auth.SubPrin) error {
	return nil
}

// HostName gets the Tao principal name assigned to this hosted Tao host.
// The name encodes the full path from the root Tao, through all intermediary
// Tao hosts, to this hosted Tao host.
func (t *StackedHost) HostName() auth.Prin {
	return t.taoHostName
}

func (s *StackedHost) InitCounter(label string, c int64) error {
	return s.hostTao.InitCounter(label, c)
}

func (s *StackedHost) GetCounter(label string) (int64, error) {
	return s.hostTao.GetCounter(label)
}

func (s *StackedHost) RollbackProtectedSeal(label string, data []byte, policy string) ([]byte, error) {
	return s.hostTao.RollbackProtectedSeal(label, data, policy)
}

func (s *StackedHost) RollbackProtectedUnseal(sealed []byte) ([]byte, string, error) {
	return s.hostTao.RollbackProtectedUnseal(sealed)
}
