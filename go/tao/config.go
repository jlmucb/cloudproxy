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

// A Config stores the information about the Tao, its Host Tao, and the way
// it creates Hosted Programs.
type Config struct {
	HostType        HostTaoType
	HostChannelType string
	HostSpec        string
	HostedType      HostedProgramType

	// Variables for the TPM configuration
	TPMAIKPath string
	TPMPCRs    string
	TPMDevice  string

	TPM2InfoDir string
	TPM2PCRs string
	TPM2Device string
	TPM2EkCert string
	TPM2QuoteCert string
}

// IsValid checks a Config for validity.
func (tc Config) IsValid() bool {
	// All valid Tao configs support creating hosted programs.
	if tc.HostedType == NoHostedPrograms {
		return false
	}

	switch tc.HostType {
	case NoHost:
		return false
	case Root:
		if tc.HostChannelType != "" || tc.HostType != NoHost {
			return false
		}

		// There are no constraints on the hosted-program types for a
		// root Tao.
	case Stacked:
		if tc.HostChannelType == "" || tc.HostSpec == "" {
			return false
		}
	default:
		return false
	}

	return true
}

// NewConfigFromString creates a new Config using strings representing the
// options.
func NewConfigFromString(htt, htct, f, hpt, tpmaik, tpmpcrs, tpmdev string) Config {
	tc := Config{}
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

	tc.HostChannelType = htct
	if htct == "tpm" {
		// TODO(tmroeder): check the TPM variables here and add them to
		// the config in some way.
		tc.TPMAIKPath = tpmaik
		tc.TPMPCRs = tpmpcrs
		tc.TPMDevice = tpmdev
	}
	if htct == "tpm2" {
		// TODO -- tpm2
		// tc.TPM2InfoDir string
		// tc.TPM2PCRs string
		// tc.TPM2Device string
		// tc.TPM2EkCert string
		// tc.TPM2QuoteCert string
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

// NewConfigFromEnv creates a Config using values drawn from environment
// variables.
func NewConfigFromEnv() Config {
	htt := os.Getenv(HostTypeEnvVar)
	htct := os.Getenv(HostChannelTypeEnvVar)
	f := os.Getenv(HostSpecEnvVar)
	hpt := os.Getenv(HostedTypeEnvVar)
	tpmaik := os.Getenv(TaoTPMAIKEnvVar)
	tpmpcrs := os.Getenv(TaoTPMPCRsEnvVar)
	tpmdev := os.Getenv(TaoTPMDeviceEnvVar)

	return NewConfigFromString(htt, htct, f, hpt, tpmaik, tpmpcrs, tpmdev)
}

// Merge combines two Config values into one. The parameter value take
// precendence over the existing values unless an incoming value is NoHost,
// NoChannel, or NoHostedPrograms. This is used to merge a config taken from the
// environment with a config specified explicitly on the command line. The
// latter takes precedence where it is explicitly given.
func (tc *Config) Merge(c Config) {
	if tc.HostType == NoHost || c.HostType != NoHost {
		tc.HostType = c.HostType
	}

	if tc.HostChannelType == "" || c.HostChannelType != "" {
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
