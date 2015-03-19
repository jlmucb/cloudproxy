// Copyright (c) 2015, Google, Inc.  All rights reserved.
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
	"os"
)

// The HostTaoType is the type of Tao (either a Root of trust, or Stacked on
// another Tao)
type HostTaoType int

// These constants represent the different types of configurations for the Tao.
const (
	NoHost HostTaoType = iota
	Root
	Stacked
)

// HostTaoTypeMap maps strings to the type of a host Tao.
var HostTaoTypeMap = map[string]HostTaoType{
	"none":    NoHost,
	"root":    Root,
	"stacked": Stacked,
}

// The HostTaoChannelType represents the type of the host Tao for a Stacked Tao.
type HostTaoChannelType int

// These constants given the different types of host Tao.
const (
	NoChannel HostTaoChannelType = iota
	TPM
	Pipe
	File
	Unix
)

// HostTaoChannelMap maps strings to the type of a host Tao channel.
var HostTaoChannelMap = map[string]HostTaoChannelType{
	"none": NoChannel,
	"tpm":  TPM,
	"pipe": Pipe,
	"file": File,
	"unix": Unix,
}

// The HostedProgramType represents the type of hosted programs and the channel
// type used for communication between the Host and the Hosted Program.
type HostedProgramType int

// These constants represent the different configurations of hosted programs and
// communication channels.
const (
	NoHostedPrograms HostedProgramType = iota
	ProcessPipe
	DockerUnix
	KVMCoreOSFile
)

// HostedProgramTypeMap maps strings to the type of a hosted program.
var HostedProgramTypeMap = map[string]HostedProgramType{
	"none":       NoHostedPrograms,
	"process":    ProcessPipe,
	"docker":     DockerUnix,
	"kvm_coreos": KVMCoreOSFile,
}

// A TaoConfig stores the information about the Tao, its Host Tao, and the way
// it creates Hosted Programs.
type TaoConfig struct {
	HostType        HostTaoType
	HostChannelType HostTaoChannelType
	HostSpec        string
	HostedType      HostedProgramType

	// Variables for the TPM configuration
	TPMAIKPath string
	TPMPCRs    string
	TPMDevice  string
}

// IsValid checks a TaoConfig for validity.
func (tc TaoConfig) IsValid() bool {
	// All valid Tao configs support creating hosted programs.
	if tc.HostedType == NoHostedPrograms {
		return false
	}

	switch tc.HostType {
	case NoHost:
		return false
	case Root:
		if tc.HostChannelType != NoChannel || tc.HostType != NoHost {
			return false
		}

		// There are no constraints on the hosted-program types for a
		// root Tao.
	case Stacked:
		if tc.HostChannelType == NoChannel || tc.HostSpec == "" {
			return false
		}
	default:
		return false
	}

	return true
}

// NewTaoConfigFromString creates a new TaoConfig using strings representing the
// options.
func NewTaoConfigFromString(htt, htct, f, hpt, tpmaik, tpmpcrs, tpmdev string) TaoConfig {
	tc := TaoConfig{}
	switch htt {
	case "none", "":
		tc.HostType = NoHost
	case "root":
		tc.HostType = Root
	case "stacked":
		tc.HostType = Stacked
	default:
		tc.HostType = NoHost
	}

	switch htct {
	case "none":
		tc.HostChannelType = NoChannel
	case "tpm":
		tc.HostChannelType = TPM
		// TODO(tmroeder): check the TPM variables here and add them to
		// the config in some way.
		tc.TPMAIKPath = tpmaik
		tc.TPMPCRs = tpmpcrs
		tc.TPMDevice = tpmdev
	case "pipe":
		tc.HostChannelType = Pipe
	case "file":
		tc.HostChannelType = File
	case "unix":
		tc.HostChannelType = Unix
	default:
		tc.HostChannelType = NoChannel
	}

	if f != "" {
		tc.HostSpec = f
	}

	switch hpt {
	case "process":
		tc.HostedType = ProcessPipe
	case "docker":
		tc.HostedType = DockerUnix
	case "kvm_coreos":
		tc.HostedType = KVMCoreOSFile
	default:
		tc.HostedType = NoHostedPrograms
	}

	return tc
}

// NewTaoConfigFromEnv creates a TaoConfig using values drawn from environment
// variables.
func NewTaoConfigFromEnv() TaoConfig {
	htt := os.Getenv(HostTypeEnvVar)
	htct := os.Getenv(HostChannelTypeEnvVar)
	f := os.Getenv(HostSpecEnvVar)
	hpt := os.Getenv(HostedTypeEnvVar)
	tpmaik := os.Getenv(TaoTPMAIKEnvVar)
	tpmpcrs := os.Getenv(TaoTPMPCRsEnvVar)
	tpmdev := os.Getenv(TaoTPMDeviceEnvVar)

	return NewTaoConfigFromString(htt, htct, f, hpt, tpmaik, tpmpcrs, tpmdev)
}

// Merge combines two TaoConfig values into one. The parameter value take
// precendence over the existing values unless an incoming value is NoHost,
// NoChannel, or NoHostedPrograms. This is used to merge a config taken from the
// environment with a config specified explicitly on the command line. The
// latter takes precedence where it is explicitly given.
func (tc *TaoConfig) Merge(c TaoConfig) {
	if tc.HostType == NoHost || c.HostType != NoHost {
		tc.HostType = c.HostType
	}

	if tc.HostChannelType == NoChannel || c.HostChannelType != NoChannel {
		tc.HostChannelType = c.HostChannelType
	}

	if tc.HostSpec == "" || c.HostSpec != "" {
		tc.HostSpec = c.HostSpec
	}

	if tc.HostedType == NoHostedPrograms || c.HostedType != NoHostedPrograms {
		tc.HostedType = c.HostedType
	}

	if tc.TPMAIKPath == "" || c.TPMAIKPath != "" {
		tc.TPMAIKPath = c.TPMAIKPath
	}

	if tc.TPMPCRs == "" || c.TPMPCRs != "" {
		tc.TPMPCRs = c.TPMPCRs
	}

	if tc.TPMDevice == "" || c.TPMDevice != "" {
		tc.TPMDevice = c.TPMDevice
	}
}
