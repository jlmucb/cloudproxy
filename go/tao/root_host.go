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
	"crypto/x509"

	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

// A RootHost is a standalone implementation of Host.
type RootHost struct {
	keys        *Keys
	taoHostName auth.Prin
}

// NewTaoRootHostFromKeys returns a RootHost that uses these keys.
func NewTaoRootHostFromKeys(k *Keys) (*RootHost, error) {
	if k.SigningKey == nil || k.CryptingKey == nil || k.VerifyingKey == nil {
		return nil, newError("missing required key for RootHost")
	}

	t := &RootHost{
		keys:        k,
		taoHostName: k.SigningKey.ToPrincipal(),
	}

	return t, nil
}

// NewTaoRootHost generates a new RootHost with a fresh set of temporary
// keys.
func NewTaoRootHost() (*RootHost, error) {
	k, err := NewTemporaryKeys(Signing | Crypting)
	if err != nil {
		return nil, err
	}

	return NewTaoRootHostFromKeys(k)
}

// LoadCert loads a given cert into the root host key.
func (t *RootHost) LoadCert(cert *x509.Certificate) {
	t.keys.Cert = cert
}

func (t *RootHost) GetVerifier() *Verifier {
	return t.keys.VerifyingKey
}

// GetRandomBytes returns a slice of n random bytes.
func (t *RootHost) GetRandomBytes(childSubprin auth.SubPrin, n int) (bytes []byte, err error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}

// GetSharedSecret returns a slice of n secret bytes.
func (t *RootHost) GetSharedSecret(tag string, n int) (bytes []byte, err error) {
	if t.keys.DerivingKey == nil {
		return nil, newError("this RootHost does not implement shared secrets")
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
func (t *RootHost) Attest(childSubprin auth.SubPrin, issuer *auth.Prin,
	time, expiration *int64, message auth.Form) (*Attestation, error) {

	child := t.taoHostName.MakeSubprincipal(childSubprin)
	if issuer != nil {
		if !auth.SubprinOrIdentical(*issuer, child) {
			return nil, newError("invalid issuer in statement")
		}
	} else {
		issuer = &child
	}

	stmt := auth.Says{Speaker: *issuer, Time: time, Expiration: expiration, Message: message}

	att, err := GenerateAttestation(t.keys.SigningKey, nil /* delegation */, stmt)
	if err != nil {
		return nil, err
	}
	if t.keys.Cert != nil {
		att.RootEndorsement = t.keys.Cert.Raw
	}
	return att, nil
}

// Encrypt data so that only this host can access it.
func (t *RootHost) Encrypt(data []byte) (encrypted []byte, err error) {
	return t.keys.CryptingKey.Encrypt(data)
}

// Decrypt data that only this host can access.
func (t *RootHost) Decrypt(encrypted []byte) (data []byte, err error) {
	return t.keys.CryptingKey.Decrypt(encrypted)
}

// AddedHostedProgram notifies this Host that a new hosted program has been
// created.
func (t *RootHost) AddedHostedProgram(childSubprin auth.SubPrin) error {
	return nil
}

// RemovedHostedProgram notifies this Host that a hosted program has been
// killed.
func (t *RootHost) RemovedHostedProgram(childSubprin auth.SubPrin) error {
	return nil
}

// HostName gets the Tao principal name assigned to this hosted Tao host.
// The name encodes the full path from the root Tao, through all intermediary
// Tao hosts, to this hosted Tao host.
func (t *RootHost) HostName() auth.Prin {
	return t.taoHostName
}
