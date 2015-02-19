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
	"io"
	"sync"

	"code.google.com/p/goprotobuf/proto"

	"github.com/golang/glog"
	"github.com/jlmucb/cloudproxy/tao/auth"
)

// A LinuxHost is a Tao host environment in which hosted programs are Linux
// processes. A Unix domain socket accepts administrative commands for
// controlling the host, e.g., for starting hosted processes, stopping hosted
// processes, or shutting down the host. A LinuxTao can be run in stacked mode
// (on top of a host Tao) or in root mode (without an underlying host Tao).
type LinuxHost struct {
	path           string
	guard          Guard
	taoHost        Host
	childFactory   HostedProgramFactory
	hostedPrograms []*LinuxHostChild
	hpm            sync.RWMutex
	nextChildID    uint
	idm            sync.Mutex
}

// NewStackedLinuxHost creates a new LinuxHost as a hosted program of an existing
// host Tao.
func NewStackedLinuxHost(path string, guard Guard, hostTao Tao, childFactory HostedProgramFactory) (*LinuxHost, error) {
	lh := &LinuxHost{
		path:         path,
		guard:        guard,
		childFactory: childFactory,
	}

	// TODO(tmroeder): the TPM Tao currently doesn't support name extensions.
	if _, ok := hostTao.(*TPMTao); !ok {
		subprin := guard.Subprincipal()
		if err := hostTao.ExtendTaoName(subprin); err != nil {
			return nil, err
		}
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
func NewRootLinuxHost(path string, guard Guard, password []byte, childFactory HostedProgramFactory) (*LinuxHost, error) {
	lh := &LinuxHost{
		guard:        guard,
		childFactory: childFactory,
	}
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

// LinuxHostChild holds state associated with a running child program.
type LinuxHostChild struct {
	channel      io.ReadWriteCloser
	ChildSubprin auth.SubPrin
	Cmd          HostedProgram
}

// GetTaoName returns the Tao name for the child.
func (lh *LinuxHost) GetTaoName(child *LinuxHostChild) auth.Prin {
	return lh.taoHost.TaoHostName().MakeSubprincipal(child.ChildSubprin)
}

// ExtendTaoName irreversibly extends the Tao principal name of the child.
func (lh *LinuxHost) ExtendTaoName(child *LinuxHostChild, ext auth.SubPrin) error {
	child.ChildSubprin = append(child.ChildSubprin, ext...)
	return nil
}

// GetRandomBytes returns a slice of n random bytes for the child.
func (lh *LinuxHost) GetRandomBytes(child *LinuxHostChild, n int) ([]byte, error) {
	return lh.taoHost.GetRandomBytes(child.ChildSubprin, n)
}

// GetSharedSecret returns a slice of n secret bytes for the child.
func (lh *LinuxHost) GetSharedSecret(child *LinuxHostChild, n int, policy string) ([]byte, error) {
	// Compute a tag based on the policy identifier and the child's subprin.
	var tag string
	switch policy {
	case SharedSecretPolicyDefault, SharedSecretPolicyConservative:
		// We are using a master key-deriving key shared among all
		// similar LinuxHost instances. For LinuxHost, the default
		// and conservative policies means any process running the same
		// program binary as the caller hosted on a similar
		// LinuxHost.
		// TODO(kwalsh) conservative policy could include PID or other
		// child info.
		tag = policy + "|" + child.ChildSubprin.String()
	case SharedSecretPolicyLiberal:
		// The most liberal we can do is allow any hosted process
		// running on a similar LinuxHost instance.
		tag = policy
	default:
		return nil, newError("policy not supported for GetSharedSecret: " + policy)
	}
	return lh.taoHost.GetSharedSecret(tag, n)
}

// Seal encrypts data for the child. This call also zeroes the data parameter.
func (lh *LinuxHost) Seal(child *LinuxHostChild, data []byte, policy string) ([]byte, error) {
	defer ZeroBytes(data)
	lhsb := &LinuxHostSealedBundle{
		Policy: proto.String(policy),
		Data:   data,
	}

	switch policy {
	case SharedSecretPolicyDefault, SharedSecretPolicyConservative:
		// We are using a master key-deriving key shared among all
		// similar LinuxHost instances. For LinuxHost, the default
		// and conservative policies means any process running the same
		// program binary as the caller hosted on a similar
		// LinuxHost.
		lhsb.PolicyInfo = proto.String(child.ChildSubprin.String())
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
	defer ZeroBytes(m)

	return lh.taoHost.Encrypt(m)
}

// Unseal decrypts data for the child, but only if the policy is satisfied.
func (lh *LinuxHost) Unseal(child *LinuxHostChild, sealed []byte) ([]byte, string, error) {
	decrypted, err := lh.taoHost.Decrypt(sealed)
	if err != nil {
		return nil, "", err
	}
	defer ZeroBytes(decrypted)

	var lhsb LinuxHostSealedBundle
	if err := proto.Unmarshal(decrypted, &lhsb); err != nil {
		return nil, "", err
	}

	if lhsb.Policy == nil {
		return nil, "", newError("invalid policy in sealed data")
	}

	policy := *lhsb.Policy
	switch policy {
	case SharedSecretPolicyConservative, SharedSecretPolicyDefault:
		if lhsb.PolicyInfo == nil || child.ChildSubprin.String() != *lhsb.PolicyInfo {
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

// Attest signs a statement on behalf of the child.
func (lh *LinuxHost) Attest(child *LinuxHostChild, issuer *auth.Prin, time, expiration *int64, stmt auth.Form) (*Attestation, error) {
	return lh.taoHost.Attest(child.ChildSubprin, issuer, time, expiration, stmt)
}

// StartHostedProgram starts a new hosted program.
func (lh *LinuxHost) StartHostedProgram(path string, args []string, uid, gid int) (auth.SubPrin, int, error) {
	lh.idm.Lock()
	id := lh.nextChildID
	if lh.nextChildID != 0 {
		lh.nextChildID++
	} else {
		glog.Warning("Running without unique child IDs")
	}
	lh.idm.Unlock()

	subprin, temppath, err := lh.childFactory.MakeSubprin(id, path, uid, gid)
	if err != nil {
		return auth.SubPrin{}, 0, err
	}

	// We allow multiple hosted programs with the same subprincipal name,
	// so we don't check here to make sure that there isn't another program
	// with the same subprincipal.

	// TODO(tmroeder): do we want to support concurrent updates to policy?
	// Then we need a lock here, too.
	hostName := lh.taoHost.TaoHostName()
	childName := hostName.MakeSubprincipal(subprin)
	if !lh.guard.IsAuthorized(childName, "Execute", []string{}) {
		return auth.SubPrin{}, 0, newError("Hosted program %s denied authorization to execute on host %s", subprin, hostName)
	}

	channel, cmd, err := lh.childFactory.Launch(temppath, args, uid, gid)
	if err != nil {
		return auth.SubPrin{}, 0, err
	}
	child := &LinuxHostChild{channel, subprin, cmd}
	go NewLinuxHostTaoServer(lh, child).Serve(channel)
	pid := child.Cmd.ID()

	lh.hpm.Lock()
	lh.hostedPrograms = append(lh.hostedPrograms, child)
	lh.hpm.Unlock()

	return subprin, pid, nil
}

// StopHostedProgram stops a running hosted program.
func (lh *LinuxHost) StopHostedProgram(subprin auth.SubPrin) error {
	lh.hpm.Lock()
	defer lh.hpm.Unlock()

	var i int
	for i < len(lh.hostedPrograms) {
		lph := lh.hostedPrograms[i]
		n := len(lh.hostedPrograms)
		if lph.ChildSubprin.Identical(subprin) {
			// Close the channel before sending SIGTERM
			lph.channel.Close()

			if err := lph.Cmd.Stop(); err != nil {
				glog.Errorf("Couldn't stop hosted program %d, subprincipal %s: %s\n", lph.Cmd.ID(), subprin, err)
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

// ListHostedPrograms returns a list of running hosted programs.
func (lh *LinuxHost) ListHostedPrograms() ([]auth.SubPrin, []int, error) {
	lh.hpm.RLock()
	subprins := make([]auth.SubPrin, len(lh.hostedPrograms))
	pids := make([]int, len(lh.hostedPrograms))
	for i, v := range lh.hostedPrograms {
		subprins[i] = v.ChildSubprin
		pids[i] = v.Cmd.ID()
	}
	lh.hpm.RUnlock()
	return subprins, pids, nil
}

// KillHostedProgram kills a running hosted program.
func (lh *LinuxHost) KillHostedProgram(subprin auth.SubPrin) error {
	lh.hpm.Lock()
	defer lh.hpm.Unlock()
	var i int
	for i < len(lh.hostedPrograms) {
		lph := lh.hostedPrograms[i]
		n := len(lh.hostedPrograms)
		if lph.ChildSubprin.Identical(subprin) {
			// Close the channel before killing the hosted program.
			lph.channel.Close()

			if err := lph.Cmd.Kill(); err != nil {
				glog.Errorf("Couldn't kill hosted program %d, subprincipal %s: %s\n", lph.Cmd.ID(), subprin, err)
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

// TaoHostName returns the name of the Host used by the LinuxHost.
func (lh *LinuxHost) TaoHostName() auth.Prin {
	return lh.taoHost.TaoHostName()
}
