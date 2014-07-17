// File: tao.go
// Author: Kevin Walsh <kwalsh@holycross.edu>
// Description: Interface to a host Tao.
//
// Copyright (c) 2013, Google Inc.  All rights reserved.
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
	"io"
	"os"

	"github.com/golang/glog"
)

const (
	HostTaoEnvVar = "GOOGLE_HOST_TAO"

	SharedSecretPolicyDefault      = "self"
	SharedSecretPolicyConservative = "few"
	SharedSecretPolicyLiberal      = "any"

	SealPolicyDefault      = "self"
	SealPolicyConservative = "few"
	SealPolicyLiberal      = "any"
)

// Tao is the fundamental Trustworthy Computing interface provided by a host to
// its hosted programs. Each level of a system can act as a host by exporting
// the Tao interface and providing Tao services to higher-level hosted programs.
//
// In most cases, a hosted program will use a stub Tao that performs RPC over a
// channel to its host. The details of such RPC depend on the specific
// implementation of the host: some hosted programs may use pipes to communicate
// with their host, others may use sockets, etc.
type Tao interface {
	// GetTaoName returns the Tao principal name assigned to the caller.
	GetTaoName() (name string, err error)

	// ExtendTaoName irreversibly extends the Tao principal name of the caller.
	ExtendTaoName(subprin string) error

	// GetRandomBytes returns a slice of n random bytes.
	GetRandomBytes(n int) (bytes []byte, err error)

	// Rand produces an io.Reader for random bytes from this Tao.
	Rand() io.Reader

	// GetSharedSecret returns a slice of n secret bytes.
	GetSharedSecret(n int, policy string) (bytes []byte, err error)

	// Attest requests the Tao host sign a Statement on behalf of the caller.
	Attest(stmt *Statement) (*Attestation, error)

	// Seal encrypts data so only certain hosted programs can unseal it.
	Seal(data []byte, policy string) (sealed []byte, err error)

	// Unseal decrypts data that has been sealed by the Seal() operation, but only
	// if the policy specified during the Seal() operation is satisfied.
	Unseal(sealed []byte) (data []byte, policy string, err error)
}

// Host is a pointer to the host Tao underlying this hosted program.
var Host Tao

func init() {
	host, err := DeserializeTaoRPC(os.Getenv(HostTaoEnvVar))
	if err != nil {
		glog.Error(err)
		return
	}
	Host = host
}
