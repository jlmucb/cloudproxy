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
	"fmt"
	"sync"
	"syscall"

	"code.google.com/p/goprotobuf/proto"
	"github.com/golang/glog"

	"cloudproxy/tao/auth"
)

// A LinuxHost is a Tao host environment in which hosted programs are Linux
// processes. A Unix domain socket accepts administrative commands for
// controlling the host, e.g., for starting hosted processes, stopping hosted
// processes, or shutting down the host. A LinuxTao can be run in stacked mode
// (on top of a host Tao) or in root mode (without an underlying host Tao).
type LinuxHost struct {
	path           string
	guard          TaoGuard
	taoHost        TaoHost
	childFactory   LinuxProcessFactory
	hostedPrograms []*LinuxHostServer
	hpm            sync.RWMutex
	nextChildID    uint
	idm            sync.Mutex
}

// NewStackedLinuxHost creates a new LinuxHost as a hosted program of an existing
// host Tao.
func NewStackedLinuxHost(path string, guard TaoGuard, hostTao Tao) (*LinuxHost, error) {
	lh := &LinuxHost{
		path:  path,
		guard: guard,
	}

	subprin := guard.Subprincipal()
	if err := hostTao.ExtendTaoName(subprin); err != nil {
		return nil, err
	}

	if err := hostTao.ExtendTaoName(subprin); err != nil {
		return nil, err
	}

	k, err := NewOnDiskTaoSealedKeys(Signing|Crypting|Deriving, hostTao, path, SealPolicyDefault)
	if err != nil {
		return nil, err
	}

	lh.taoHost, err = NewTaoStackedHostFromKeys(k, hostTao)
	if err != nil {
		return nil, err
	}

	return lh, nil
}

// NewRootLinuxHost creates a new LinuxHost as a standalone Host that can
// provide the Tao to hosted Linux processes.
func NewRootLinuxHost(path string, guard TaoGuard, password []byte) (*LinuxHost, error) {
	lh := &LinuxHost{guard: guard}
	k, err := NewOnDiskPBEKeys(Signing|Crypting|Deriving, password, path, nil)
	if err != nil {
		return nil, err
	}

	lh.taoHost, err = NewTaoRootHostFromKeys(k)
	if err != nil {
		return nil, err
	}

	return lh, nil
}

// handleGetTaoName returns a Tao name for this child subprincipal.
func (lh *LinuxHost) handleGetTaoName(childSubprin auth.SubPrin) auth.Prin {
	return lh.taoHost.TaoHostName().MakeSubprincipal(childSubprin)
}

// handleGetRandomBytes gets random bytes from the TaoHost.
func (lh *LinuxHost) handleGetRandomBytes(childSubprin auth.SubPrin, n int) ([]byte, error) {
	return lh.taoHost.GetRandomBytes(childSubprin, n)
}

// handleGetSharedSecret derives a tag for the secret and generates one from
// the TaoHost.
func (lh *LinuxHost) handleGetSharedSecret(childSubprin auth.SubPrin, n int, policy string) ([]byte, error) {
	// Compute the tag based on the policy identifier and childSubprin.
	var tag string
	switch policy {
	case SharedSecretPolicyDefault:
	case SharedSecretPolicyConservative:
		// We are using a master key-deriving key shared among all
		// similar LinuxHost instances. For LinuxHost, the default
		// and conservative policies means any process running the same
		// program binary as the caller hosted on a similar
		// LinuxHost.
		// TODO(kwalsh) conservative policy could include PID or other
		// child info.
		tag = policy + "|" + childSubprin.String()
	case SharedSecretPolicyLiberal:
		// The most liberal we can do is allow any hosted process
		// running on a similar LinuxHost instance.
		tag = policy
	default:
		return nil, newError("policy not supported for GetSharedSecret: " + policy)
	}

	return lh.taoHost.GetSharedSecret(tag, n)
}

// handleSeal seals data for the given policy and child subprincipal. This call
// also zeroes the data parameter.
func (lh *LinuxHost) handleSeal(childSubprin auth.SubPrin, data []byte, policy string) ([]byte, error) {
	defer zeroBytes(data)
	lhsb := &LinuxHostSealedBundle{
		Policy: proto.String(policy),
		Data:   data,
	}

	switch policy {
	case SharedSecretPolicyDefault:
	case SharedSecretPolicyConservative:
		// We are using a master key-deriving key shared among all
		// similar LinuxHost instances. For LinuxHost, the default
		// and conservative policies means any process running the same
		// program binary as the caller hosted on a similar
		// LinuxHost.
		lhsb.PolicyInfo = proto.String(childSubprin.String())
	case SharedSecretPolicyLiberal:
		// The most liberal we can do is allow any hosted process
		// running on a similar LinuxHost instance. So, we don't set
		// any policy info.
	default:
		return nil, newError("policy not supported for Seal: " + policy)
	}

	m, err := proto.Marshal(lhsb)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(m)

	return lh.taoHost.Encrypt(m)
}

// handleUnseal unseals data and checks its policy information to see if this
// Unseal operation is authorized.
func (lh *LinuxHost) handleUnseal(childSubprin auth.SubPrin, sealed []byte) ([]byte, string, error) {
	decrypted, err := lh.taoHost.Decrypt(sealed)
	if err != nil {
		return nil, "", err
	}
	defer zeroBytes(decrypted)

	var lhsb LinuxHostSealedBundle
	if err := proto.Unmarshal(decrypted, &lhsb); err != nil {
		return nil, "", err
	}

	if lhsb.Policy == nil {
		return nil, "", newError("invalid policy in sealed data")
	}

	policy := *lhsb.Policy
	switch policy {
	case SharedSecretPolicyDefault:
	case SharedSecretPolicyConservative:
		if lhsb.PolicyInfo == nil || childSubprin.String() != *lhsb.PolicyInfo {
			return nil, "", newError("principal not authorized for unseal")
		}
	case SharedSecretPolicyLiberal:
		// Allow all
		break
	default:
		return nil, "", newError("policy not supported for Unseal: " + policy)
	}

	return lhsb.Data, policy, nil
}

// handleAttest performs policy checking and performs attestation for a child
// subprincipal.
func (lh *LinuxHost) handleAttest(childSubprin auth.SubPrin, issuer *auth.Prin, time, expiration *int64, stmt auth.Form) (*Attestation, error) {
	return lh.taoHost.Attest(childSubprin, issuer, time, expiration, stmt)
}

// StartHostedProgram starts a new program based on an admin RPC request.
// This function is accessible using net/rpc.
func (lh *LinuxHost) StartHostedProgram(r *LinuxAdminRPCRequest, s *LinuxAdminRPCResponse) error {
	if r.Path == nil {
		return newError("hosted program creation request is missing path")
	}

	lh.idm.Lock()
	id := lh.nextChildID
	if lh.nextChildID != 0 {
		lh.nextChildID++
	} else {
		glog.Warning("Running without unique child IDs")
	}
	lh.idm.Unlock()

	subprin, temppath, err := lh.childFactory.MakeHostedProgramSubprin(id, *r.Path)
	if err != nil {
		return err
	}

	// We allow multiple hosted programs with the same subprincipal name,
	// so we don't check here to make sure that there isn't another program
	// with the same subprincipal.

	// TODO(tmroeder): do we want to support concurrent updates to policy?
	// Then we need a lock here, too.
	hostName := lh.taoHost.TaoHostName()
	childName := hostName.MakeSubprincipal(subprin)
	if !lh.guard.IsAuthorized(childName, "Execute", []string{}) {
		return newError("Hosted program %s denied authorization to execute on host %s", subprin, hostName)
	}

	lhs, err := lh.childFactory.StartHostedProgram(lh, temppath, r.Args, subprin)
	if err != nil {
		return err
	}

	lh.hpm.Lock()
	lh.hostedPrograms = append(lh.hostedPrograms, lhs)
	lh.hpm.Unlock()

	s.Data = auth.Marshal(subprin)
	return nil
}

// StopHostedProgram stops a running hosted program based on an admin RPC
// request.
// This function is accessible using net/rpc.
func (lh *LinuxHost) StopHostedProgram(r *LinuxAdminRPCRequest, s *LinuxAdminRPCResponse) error {
	subprin, err := auth.UnmarshalSubPrin(r.Data)
	if err != nil {
		return err
	}
	lh.hpm.Lock()
	defer lh.hpm.Unlock()

	// For Stop, we send SIGTERM
	sigterm := 15
	var i int
	for i < len(lh.hostedPrograms) {
		lph := lh.hostedPrograms[i]
		n := len(lh.hostedPrograms)
		if lph.ChildSubprin.Identical(subprin) {
			// Close the channel before sending SIGTERM
			lph.channel.Close()

			if err := syscall.Kill(lph.Cmd.Process.Pid, syscall.Signal(sigterm)); err != nil {
				glog.Errorf("Couldn't send SIGTERM to process %d, subprincipal %s: %s\n", lph.Cmd.Process.Pid, subprin, err)
			}

			// The order of this array doesn't matter, and we want
			// to make sure we remove all references to pointers to
			// LinuxHostServer instances so that they get garbage
			// collected. So, we implement delete from the slice by
			// moving elements around.
			lh.hostedPrograms[i] = lh.hostedPrograms[n-1]
			lh.hostedPrograms[n-1] = nil
			lh.hostedPrograms = lh.hostedPrograms[:n-1]
			i--
		}

		i++
	}

	return nil
}

// ListHostedPrograms returns a list of hosted programs to the caller.
// This function is accessible using net/rpc.
func (lh *LinuxHost) ListHostedPrograms(r *LinuxAdminRPCRequest, s *LinuxAdminRPCResponse) error {
	lh.hpm.RLock()
	subprins := make([]string, len(lh.hostedPrograms))
	pids := make([]int32, len(lh.hostedPrograms))
	for _, v := range lh.hostedPrograms {
		subprins = append(subprins, v.ChildSubprin.String())
		pids = append(pids, int32(v.Cmd.Process.Pid))
	}
	lh.hpm.RUnlock()

	info := &LinuxAdminRPCHostedProgramList{
		Name: subprins,
		Pid:  pids,
	}

	var err error
	s.Data, err = proto.Marshal(info)
	if err != nil {
		return err
	}

	return nil
}

// KillHostedProgram kills a running hosted program based on an admin RPC
// request.
// This function is accessible using net/rpc.
func (lh *LinuxHost) KillHostedProgram(r *LinuxAdminRPCRequest, s *LinuxAdminRPCResponse) error {
	subprin, err := auth.UnmarshalSubPrin(r.Data)
	if err != nil {
		return err
	}
	lh.hpm.Lock()
	defer lh.hpm.Unlock()
	var i int
	for i < len(lh.hostedPrograms) {
		lph := lh.hostedPrograms[i]
		n := len(lh.hostedPrograms)
		if lph.ChildSubprin.Identical(subprin) {
			// Close the channel before sending SIGTERM
			lph.channel.Close()

			if err := lph.Cmd.Process.Kill(); err != nil {
				glog.Errorf("Couldn't kill process %d, subprincipal %s: %s\n", lph.Cmd.Process.Pid, subprin, err)
			}

			// The order of this array doesn't matter, and we want
			// to make sure we remove all references to pointers to
			// LinuxHostServer instances so that they get garbage
			// collected. So, we implement delete from the slice by
			// moving elements around.
			lh.hostedPrograms[i] = lh.hostedPrograms[n-1]
			lh.hostedPrograms[n-1] = nil
			lh.hostedPrograms = lh.hostedPrograms[:n-1]
			i--
		}

		i++
	}

	return nil
}

// GetTaoHostName returns the name of the TaoHost used by the LinuxHost.
// This function is accessible using net/rpc.
func (lh *LinuxHost) GetTaoHostName(r *LinuxAdminRPCRequest, s *LinuxAdminRPCResponse) error {
	fmt.Println("got host name request")
	s.Data = auth.Marshal(lh.taoHost.TaoHostName())
	return nil
}

// TaoHostName returns the name of the TaoHost used by the LinuxHost.
func (lh *LinuxHost) TaoHostName() auth.Prin {
	return lh.taoHost.TaoHostName()
}
