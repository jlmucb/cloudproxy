// Copyright (c) 2014, Kevin Walsh.  All rights reserved.
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
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/golang/glog"
	"github.com/jlmucb/cloudproxy/go/tao/auth"
)

// Constants used by the Tao implementations for policy, signing contexts, and
// environment variables.
const (
	HostTypeEnvVar        = "CLOUDPROXY_TAO_HOST_TYPE"
	HostSpecEnvVar        = "CLOUDPROXY_TAO_HOST_SPEC"
	HostChannelTypeEnvVar = "CLOUDPROXY_TAO_HOST_CHANNEL_TYPE"
	HostedTypeEnvVar      = "CLOUDPROXY_TAO_HOSTED_TYPE"

	TaoTPMPCRsEnvVar   = "CLOUDPROXY_TAO_TPM_PCRS"
	TaoTPMAIKEnvVar    = "CLOUDPROXY_TAO_TPM_AIK"
	TaoTPMDeviceEnvVar = "CLOUDPROXY_TAO_TPM_DEVICE"

	SharedSecretPolicyDefault      = "self"
	SharedSecretPolicyConservative = "few"
	SharedSecretPolicyLiberal      = "any"

	SealPolicyDefault      = "self"
	SealPolicyConservative = "few"
	SealPolicyLiberal      = "any"

	AttestationSigningContext = "Tao Attestation Signing Context V1"
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
	GetTaoName() (name auth.Prin, err error)

	// ExtendTaoName irreversibly extends the Tao principal name of the caller.
	ExtendTaoName(subprin auth.SubPrin) error

	// GetRandomBytes returns a slice of n random bytes.
	GetRandomBytes(n int) (bytes []byte, err error)

	// Rand produces an io.Reader for random bytes from this Tao.
	Rand() io.Reader

	// GetSharedSecret returns a slice of n secret bytes.
	GetSharedSecret(n int, policy string) (bytes []byte, err error)

	// Attest requests the Tao host sign a statement on behalf of the caller. The
	// optional issuer, time and expiration will be given default values if nil.
	// TODO(kwalsh) Maybe create a struct for these optional params? Or use
	// auth.Says instead (in which time and expiration are optional) with a
	// bogus Speaker field like key("") or nil("") or self, etc.
	Attest(issuer *auth.Prin, time, expiration *int64, message auth.Form) (*Attestation, error)

	// Seal encrypts data so only certain hosted programs can unseal it.
	Seal(data []byte, policy string) (sealed []byte, err error)

	// Unseal decrypts data that has been sealed by the Seal() operation, but only
	// if the policy specified during the Seal() operation is satisfied.
	Unseal(sealed []byte) (data []byte, policy string, err error)
}

// Cached interface to the host Tao underlying this hosted program.
var cachedHost Tao
var cacheOnce sync.Once

// ParentFromConfig gets a parent Tao given a Config that specifies the Tao
// type.
func ParentFromConfig(tc Config) Tao {
	cacheOnce.Do(func() {
		// Get a default config from the environment.
		tcEnv := NewConfigFromEnv()

		// The incoming config overrides the environment variables for
		// any values that are set in it.
		tcEnv.Merge(tc)
		switch tcEnv.HostChannelType {
		case TPM:
			aikblob, err := ioutil.ReadFile(tcEnv.TPMAIKPath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Couldn't read the aikblob: %s\n", err)
				glog.Error(err)
				return
			}

			taoPCRs := tcEnv.TPMPCRs
			pcrStr := strings.TrimPrefix(taoPCRs, "PCRs(\"")

			// This index operation will never panic, since strings.Split always
			// returns at least one entry in the resulting slice.
			pcrIntList := strings.Split(pcrStr, "\", \"")[0]
			pcrInts := strings.Split(pcrIntList, ",")
			pcrs := make([]int, len(pcrInts))
			for i, s := range pcrInts {
				var err error
				pcrs[i], err = strconv.Atoi(s)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Couldn't split the PCRs: %s\n", err)
					glog.Error(err)
					return
				}
			}

			host, err := NewTPMTao(tcEnv.TPMDevice, aikblob, pcrs)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Couldn't create a new TPMTao: %s\n", err)
				glog.Error(err)
				return
			}

			cachedHost = host
		case Pipe:
			host, err := DeserializeRPC(tcEnv.HostSpec)
			if err != nil {
				glog.Error(err)
				return
			}
			cachedHost = host
		case File:
			host, err := DeserializeFileRPC(tcEnv.HostSpec)
			if err != nil {
				glog.Error(err)
				return
			}
			cachedHost = host
		case Unix:
			host, err := DeserializeUnixSocketRPC(tcEnv.HostSpec)
			if err != nil {
				glog.Error(err)
				return
			}
			cachedHost = host
		default:
			glog.Errorf("unknown host tao channel type '%d'\n", tcEnv.HostChannelType)
		}

	})

	return cachedHost
}

// Parent returns the interface to the underlying host Tao. It depends on a
// specific environment variable being set. On success it memoizes the result
// before returning it because there should only ever be a single channel to the
// host. On failure, it logs a message using glog and returns nil.
// Note: errors are not returned so that, once it is confirmed that Parent
// returns a non-nil value, callers can use the function result in an
// expression, e.g.:
//   name, err := tao.Parent().GetTaoName()
func Parent() Tao {
	ParentFromConfig(Config{})
	return cachedHost
}
