//  File: tao.go
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: Interface used by hosted programs to access Tao services.
//
//  Copyright (c) 2013, Google Inc.  All rights reserved.
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
	"fmt"
	"os"
)

const (
	HostTaoEnvVar = "GOOGLE_HOST_TAO"
	SealPolicyDefault = "self"
	SealPolicyConservative = "few"
	SealPolicyLiberal = "any"
)

// Tao is the fundamental Trustworthy Computing interface provided by a host to
// its hosted programs. Each level of a system can act as a host by exporting
// the Tao interface and providing Tao services to higher-level hosted
// programs.
//
// In most cases, a hosted program will use a stub Tao that performs RPC over a
// channel to its host. The details of such RPC depend on the specific
// implementation of the host: some hosted programs may use pipes to
// communicate with their host, others may use sockets, etc.
type Tao interface {
	// GetTaoName returns the Tao principal name assigned to this hosted
	// program.
	GetTaoName() (name string, err error)

	/// ExtendTaoName irreversibly extend the Tao principal name of this hosted
	/// program.
	ExtendTaoName(subprin string) error

	// GetRandomBytes returns a slice of n random bytes.
	GetRandomBytes(n int) (bytes []byte, err error)

	// Attest requests the Tao host sign a Statement on behalf of this hosted program.
	// Attest(stmt *Statement) (*Attestation, error)

	// Seal encrypts data so only certain hosted programs can unseal it.
	Seal(data []byte, policy string) (sealed []byte, err error)

	// Decrypt data that has been sealed by the Seal() operation, but only
	// if the policy specified during the Seal() operation is satisfied.
	Unseal(sealed []byte) (data []byte, policy string, err error)

	// Get most recent error message, if any.
	GetRecentErrorMessage() string

	// Clear the most recent error message and return the previous value, if any.
	ResetRecentErrorMessage() string
}

var hostTao Tao

func Host() Tao {
	if hostTao != nil {
		return hostTao
	}
	s := os.Getenv(HostTaoEnvVar)
	if s == "" {
		fmt.Printf("Missing tao env\n")
		return nil
	}
	hostTao := DeserializeTaoRPC(s)
	if hostTao != nil {
		fmt.Printf("Got serialized TaoRPC\n")
	} else {
		fmt.Printf("Did not get message channel\n")
	}
	return hostTao
}
