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
	"sync"
	"syscall"

	"code.google.com/p/goprotobuf/proto"
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
	hostedPrograms map[string]*LinuxHostServer
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

	subprin := guard.SubprincipalName()
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
	k, err := NewOnDiskPBEKeys(Signing|Crypting|Deriving, password, path)
	if err != nil {
		return nil, err
	}

	lh.taoHost, err = NewTaoRootHostFromKeys(k)
	if err != nil {
		return nil, err
	}

	return lh, nil
}

// HandleGetTaoName returns a Tao name for this child subprincipal.
func (lh *LinuxHost) HandleGetTaoName(childSubprin string) string {
	return lh.taoHost.TaoHostName() + "::" + childSubprin
}

// HandleGetRandomBytes gets random bytes from the TaoHost.
func (lh *LinuxHost) HandleGetRandomBytes(childSubprin string, n int) ([]byte, error) {
	return lh.taoHost.GetRandomBytes(childSubprin, n)
}

// HandleGetSharedSecret derives a tag for the secret and generates one from
// the TaoHost.
func (lh *LinuxHost) HandleGetSharedSecret(childSubprin string, n int, policy string) ([]byte, error) {
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
		tag = policy + "|" + childSubprin
	case SharedSecretPolicyLiberal:
		// The most liberal we can do is allow any hosted process
		// running on a similar LinuxHost instance.
		tag = policy
	default:
		return nil, errors.New("policy not supported for GetSharedSecret: " + policy)
	}

	return lh.taoHost.GetSharedSecret(tag, n)
}

// HandleSeal seals data for the given policy and child subprincipal.
func (lh *LinuxHost) HandleSeal(childSubprin string, data []byte, policy string) ([]byte, error) {
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
		lhsb.PolicyInfo = proto.String(childSubprin)
	case SharedSecretPolicyLiberal:
		// The most liberal we can do is allow any hosted process
		// running on a similar LinuxHost instance. So, we don't set
		// any policy info.
	default:
		return nil, errors.New("policy not supported for Seal: " + policy)
	}

	m, err := proto.Marshal(lhsb)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(m)

	return lh.taoHost.Encrypt(m)
}

// HandleUnseal unseals data and checks its policy information to see if this
// Unseal operation is authorized.
func (lh *LinuxHost) HandleUnseal(childSubprin string, sealed []byte) ([]byte, string, error) {
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
		return nil, "", errors.New("invalid policy in sealed data")
	}

	policy := *lhsb.Policy
	switch policy {
	case SharedSecretPolicyDefault:
	case SharedSecretPolicyConservative:
		if lhsb.PolicyInfo == nil || childSubprin != *lhsb.PolicyInfo {
			return nil, "", errors.New("principal not authorized for unseal")
		}
	case SharedSecretPolicyLiberal:
		// Allow all
		break
	default:
		return nil, "", errors.New("policy not supported for Unseal: " + policy)
	}

	return lhsb.Data, policy, nil
}

// HandleAttest performs policy checking and performs attestation for a child
// subprincipal.
func (lh *LinuxHost) HandleAttest(childSubprin string, stmt *Statement) (*Attestation, error) {
	if stmt.Delegate == nil && stmt.PredicateName == nil {
		return nil, errors.New("must supply either delegate or predicate_name in statement for attestation")
	}

	return lh.taoHost.Attest(childSubprin, stmt)
}

// StartHostedProgram starts a new program based on an admin RPC request.
func (lh *LinuxHost) StartHostedProgram(r *LinuxAdminRPCRequest, s *LinuxAdminRPCResponse) error {
	if r.Path == nil {
		return errors.New("hosted program creation request is missing path")
	}

	lh.idm.Lock()
	id := lh.nextChildID
	lh.nextChildID++
	lh.idm.Unlock()

	subprin, temppath, err := lh.childFactory.MakeHostedProgramSubprin(id, *r.Path)
	if err != nil {
		return err
	}

	lh.hpm.RLock()
	_, ok := lh.hostedPrograms[subprin]
	lh.hpm.RUnlock()
	if ok {
		return errors.New("hosted program " + subprin + " already exists")
	}

	// TODO(tmroeder): do we want to support concurrent updates to policy? Then we need a lock here, too.
	name := lh.taoHost.TaoHostName()
	if !lh.guard.IsAuthorized(name+"::"+subprin, "Execute", []string{}) {
		return errors.New("Hosted program " + subprin + " denied authorization to execute on host " + name)
	}

	lhs, err := lh.childFactory.StartHostedProgram(lh, temppath, r.Args, subprin)
	if err != nil {
		return err
	}

	lh.hpm.Lock()
	lh.hostedPrograms[subprin] = lhs
	lh.hpm.Unlock()

	s.Data = []byte(subprin)
	return nil
}

// StopHostedProgram stops a running hosted program based on an admin RPC
// request.
func (lh *LinuxHost) StopHostedProgram(r *LinuxAdminRPCRequest, s *LinuxAdminRPCResponse) error {
	if r.Data == nil {
		return errors.New("missing child subprincipal")
	}

	// TODO(tmroeder): this implementation should be extended to support
	// multiple clients with the same subprincipal name.
	subprin := string(r.Data)
	lh.hpm.Lock()
	defer lh.hpm.Unlock()
	lph, ok := lh.hostedPrograms[subprin]
	if !ok {
		return errors.New("no subprincipal " + subprin)
	}

	// Close the channel before sending SIGTERM
	lph.channel.Close()

	// For Stop, we send SIGTERM
	var sigterm int = 15
	if err := syscall.Kill(lph.Cmd.Process.Pid, syscall.Signal(sigterm)); err != nil {
		return err
	}

	delete(lh.hostedPrograms, subprin)
	return nil
}

// ListHostedPrograms returns a list of hosted programs to the caller.
func (lh *LinuxHost) ListHostedPrograms(r *LinuxAdminRPCRequest, s *LinuxAdminRPCResponse) error {
	lh.hpm.RLock()
	subprins := make([]string, len(lh.hostedPrograms))
	pids := make([]int32, len(lh.hostedPrograms))
	for k, v := range lh.hostedPrograms {
		subprins = append(subprins, k)
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
func (lh *LinuxHost) KillHostedProgram(r *LinuxAdminRPCRequest, s *LinuxAdminRPCResponse) error {
	if r.Data == nil {
		return errors.New("missing child subprincipal")
	}

	// TODO(tmroeder): this implementation should be extended to support
	// multiple clients with the same subprincipal name.
	subprin := string(r.Data)
	lh.hpm.Lock()
	defer lh.hpm.Unlock()
	lph, ok := lh.hostedPrograms[subprin]
	if !ok {
		return errors.New("no subprincipal " + subprin)
	}

	// Close the channel before sending SIGTERM
	lph.channel.Close()

	// For kill, we use the Go call on Process.
	if err := lph.Cmd.Process.Kill(); err != nil {
		return err
	}

	delete(lh.hostedPrograms, subprin)
	return nil
}

// GetTaoHostName returns the name of the TaoHost used by the LinuxHost.
func (lh *LinuxHost) GetTaoHostName(r *LinuxAdminRPCRequest, s *LinuxAdminRPCResponse) error {
	s.Data = []byte(lh.taoHost.TaoHostName())
	return nil
}
