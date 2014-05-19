//  File: tao.go
//  Author: Tom Roeder <tmroeder@google.com>
//
//  Description: The Tao interface for Trusted Computing
//
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
)

// Tao is the fundamental interface for Trustworthy Computing in CloudProxy.
// Each level of a system can implement a Tao interface and provide Tao
// services to higher-level hosted programs.
//
// For example, a Linux system installed on hardware with a TPM might work as
// follows: TPMTaoChildChannel <-> LinuxTao <-> PipeTaoChannel. The
// TPMTaoChildChannel implements a shim for the TPM hardware to convert Tao
// operations into TPM commands. LinuxTao implements the Tao for Linux, and it
// holds a PipeTaoChannel that it uses to communicate with hosted programs
// running as processes. A hosted program called CloudServer would have the
// following interactions: PipeTaoChildChannel <-> CloudServer. The
// PipeTaoChildChannel and the PipeTaoChannel communicate over Unix pipes to
// send Tao messages between LinuxTao and CloudServer. See the apps/ folder for
// applications that implement exactly this setup: apps/linux_tao_service.cc
// implements the LinuxTao, and apps/server.cc implements CloudServer.
//
// Similarly, the LinuxTao could start KVM Guests as hosted programs
// (using the KvmVmFactory instead of the ProcessFactory). In this case, the
// interaction would be: TPMTaoChildChannel <-> LinuxTao <-> KvmUnixTaoChannel.
//
// And the guest OS would have another instance of the LinuxTao that would have
// the following interactions:
// KvmUnixTaoChildChannel <-> LinuxTao <-> PipeTaoChannel. This version of
// the LinuxTao in the Guest OS would use the ProcessFactory to start hosted
// programs as processes in the guest.
//
// In summary: each level of the Tao can have a TaoChildChannel to communicate
// with its host Tao and has a TaoChannel to communicated with hosted programs.
// Hosts use implementations of HostedProgramFactory to instantiate hosted
// programs.
type Tao interface {
	// Init initializes and acquires resources.
	Init() error

	// Destroy cleans up resources that were allocated in Init.
	Destroy() error

	// GetRandomBytes fills the given slice with random bytes, up to the
	// length of the slice.
	GetRandomBytes(bytes []byte) error

	// Seal protects the given data for the given hosted program and
	// returns an opaque protected blob that can be unsealed later.
	Seal(data []byte) (sealed []byte, err error)

	// Unseal opens a blob created by Seal if the hosted program matches
	// the program that sealed the data.
	Unseal(sealed []byte) (data []byte, err error)

	// Attest generates a cryptographic attestation to a given data blob
	// for a given hosted program.
	Attest(data []byte) (attestation []byte, err error)
}
